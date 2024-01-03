pub mod protocols;

use crate::errors::{Error, P2PError};

use crate::peer::PeerType;
use crate::services::{
    dump_peer_store::DumpPeerStoreService, outbound_peer::OutboundPeerService,
    protocol_type_checker::ProtocolTypeCheckerService,
};
use crate::NetworkState;
use crate::SupportProtocols;
use protocols::{
    disconnect_message::DisconnectMessageProtocol,
    discovery::{DiscoveryAddressManager, DiscoveryProtocol},
    feeler::Feeler,
    identify::{Flags, IdentifyCallback, IdentifyProtocol},
    ping::PingHandler,
};

use crate::{CKBProtocol, PeerIndex, ServiceControl};
use ckb_app_config::{default_support_all_protocols, SupportProtocol};
use ckb_logger::{debug, error, info, warn};
use ckb_spawn::Spawn;
use ckb_stop_handler::{broadcast_exit_signals, new_tokio_exit_rx, CancellationToken};

use futures::{channel::mpsc::Sender, Future};

use p2p::{
    async_trait,
    builder::ServiceBuilder,
    bytes::Bytes,
    context::ServiceContext,
    error::SendErrorKind,
    error::{DialerErrorKind, HandshakeErrorKind, ProtocolHandleErrorKind},
    multiaddr::Multiaddr,
    secio::error::SecioError,
    service::{ProtocolHandle, Service, ServiceAsyncControl, ServiceError, ServiceEvent},
    traits::ServiceHandle,
    utils::{is_reachable, multiaddr_to_socketaddr},
    yamux::config::Config as YamuxConfig,
    SessionId,
};
use rand::prelude::IteratorRandom;
#[cfg(feature = "with_sentry")]
use sentry::{capture_message, with_scope, Level};
use std::sync::mpsc;
use std::{cmp::max, collections::HashSet, pin::Pin, sync::Arc, time::Duration, usize};
use tokio::{self, sync::oneshot};

/// Used to handle global events of tentacle, such as session open/close
pub struct EventHandler {
    pub(crate) network_state: Arc<NetworkState>,
}

impl EventHandler {
    /// init an event handler
    pub fn new(network_state: Arc<NetworkState>) -> Self {
        Self { network_state }
    }
}

impl EventHandler {
    fn inbound_eviction(&self) -> Vec<SessionId> {
        if self.network_state.config.bootnode_mode {
            let status = self.network_state.connection_status();

            if status.max_inbound <= status.non_whitelist_inbound.saturating_add(10) {
                self.network_state
                    .with_peer_registry(|registry| {
                        registry
                            .peers()
                            .values()
                            .filter(|peer| peer.is_inbound() && !peer.is_whitelist)
                            .flat_map(|peer| match peer.index {
                                PeerIndex::Tentacle(s) => Some(s),
                                PeerIndex::Libp2p(_) => None,
                            })
                            .collect::<Vec<SessionId>>()
                    })
                    .into_iter()
                    .enumerate()
                    .filter_map(|(index, peer)| if index & 0x1 != 0 { Some(peer) } else { None })
                    .collect()
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    }
}

#[async_trait]
impl ServiceHandle for EventHandler {
    async fn handle_error(&mut self, context: &mut ServiceContext, error: ServiceError) {
        match error {
            ServiceError::DialerError { address, error } => {
                let mut public_addrs = self.network_state.public_addrs.write();

                match error {
                    DialerErrorKind::HandshakeError(HandshakeErrorKind::SecioError(
                        SecioError::ConnectSelf,
                    )) => {
                        debug!("dial observed address success: {:?}", &address);
                        if let Some(ip) = multiaddr_to_socketaddr(&address) {
                            if is_reachable(ip.ip()) {
                                public_addrs.insert((&address).into());
                            }
                        }
                        return;
                    }
                    DialerErrorKind::IoError(e)
                        if e.kind() == std::io::ErrorKind::AddrNotAvailable =>
                    {
                        warn!("DialerError({}) {}", &address, e);
                    }
                    _ => {
                        debug!("DialerError({}) {}", &address, error);
                    }
                }
                public_addrs.remove(&address.clone().into());
                self.network_state.dial_failed(&address.into());
            }
            ServiceError::ProtocolError {
                id,
                proto_id,
                error,
            } => {
                debug!("ProtocolError({}, {}) {}", id, proto_id, error);
                let message = format!("ProtocolError id={proto_id}");
                // Ban because misbehave of remote peer
                self.network_state.ban_session(
                    &context.control().clone().into(),
                    id,
                    Duration::from_secs(300),
                    &message,
                );
            }
            ServiceError::SessionTimeout { session_context } => {
                debug!(
                    "SessionTimeout({}, {})",
                    session_context.id, session_context.address,
                );
            }
            ServiceError::MuxerError {
                session_context,
                error,
            } => {
                debug!(
                    "MuxerError({}, {}), substream error {}, disconnect it",
                    session_context.id, session_context.address, error,
                );
            }
            ServiceError::ListenError { address, error } => {
                debug!("ListenError: address={:?}, error={:?}", address, error);
            }
            ServiceError::ProtocolSelectError {
                proto_name,
                session_context,
            } => {
                debug!(
                    "ProtocolSelectError: proto_name={:?}, session_id={}",
                    proto_name, session_context.id,
                );
            }
            ServiceError::SessionBlocked { session_context } => {
                debug!("SessionBlocked: {}", session_context.id);
            }
            ServiceError::ProtocolHandleError { proto_id, error } => {
                debug!("ProtocolHandleError: {:?}, proto_id: {}", error, proto_id);

                let ProtocolHandleErrorKind::AbnormallyClosed(opt_session_id) = error;
                {
                    if let Some(id) = opt_session_id {
                        self.network_state.ban_session(
                            &context.control().clone().into(),
                            id,
                            Duration::from_secs(300),
                            &format!("protocol {proto_id} panic when process peer message"),
                        );
                    }
                    #[cfg(feature = "with_sentry")]
                    with_scope(
                        |scope| scope.set_fingerprint(Some(&["ckb-network", "p2p-service-error"])),
                        || {
                            capture_message(
                                &format!("ProtocolHandleError: AbnormallyClosed, proto_id: {opt_session_id:?}, session id: {opt_session_id:?}"),
                                Level::Warning,
                            )
                        },
                    );
                    error!("ProtocolHandleError: AbnormallyClosed, proto_id: {opt_session_id:?}, session id: {opt_session_id:?}");

                    broadcast_exit_signals();
                }
            }
        }
    }

    async fn handle_event(&mut self, context: &mut ServiceContext, event: ServiceEvent) {
        // When session disconnect update status anyway
        match event {
            ServiceEvent::SessionOpen { session_context } => {
                debug!(
                    "SessionOpen({}, {})",
                    session_context.id, session_context.address,
                );
                self.network_state
                    .dial_success(&session_context.address.clone().into());

                let iter = self.inbound_eviction();

                let control = context.control().clone().into();

                for peer in iter {
                    if let Err(err) =
                        disconnect_with_message(&control, peer, "bootnode random eviction")
                    {
                        debug!("Inbound eviction failed {:?}, error: {:?}", peer, err);
                    }
                }

                if self
                    .network_state
                    .with_peer_registry(|reg| reg.is_feeler(&(&session_context.address).into()))
                {
                    debug!(
                        "feeler connected {} => {}",
                        session_context.id, session_context.address,
                    );
                } else {
                    match self.network_state.accept_peer(&session_context) {
                        Ok(Some(evicted_peer)) => {
                            debug!(
                                "evict peer (disconnect it), {:?} => {:?}",
                                evicted_peer.index, evicted_peer.connected_addr,
                            );
                            match evicted_peer.index {
                                PeerIndex::Tentacle(s) => {
                                    if let Err(err) = disconnect_with_message(
                                        &control,
                                        s,
                                        "evict because accepted better peer",
                                    ) {
                                        debug!("Disconnect failed {:?}, error: {:?}", s, err);
                                    }
                                }
                                PeerIndex::Libp2p(_) => panic!("Must not evict non-tentacle peers"),
                            }
                        }
                        Ok(None) => debug!(
                            "{} open, registry {} success",
                            session_context.id, session_context.address,
                        ),
                        Err(err) => {
                            debug!(
                                "registry peer failed {:?} disconnect it, {} => {}",
                                err, session_context.id, session_context.address,
                            );
                            if let Err(err) = disconnect_with_message(
                                &control,
                                session_context.id,
                                "reject peer connection",
                            ) {
                                debug!(
                                    "Disconnect failed {:?}, error: {:?}",
                                    session_context.id, err
                                );
                            }
                        }
                    }
                }
            }
            ServiceEvent::SessionClose { session_context } => {
                debug!(
                    "SessionClose({}, {})",
                    session_context.id, session_context.address,
                );
                let peer_exists = self.network_state.with_peer_registry_mut(|reg| {
                    // should make sure feelers is clean
                    reg.remove_feeler(&(&session_context.address).into());
                    reg.remove_peer(session_context.id).is_some()
                });
                if peer_exists {
                    debug!(
                        "{} closed, remove {} from peer_registry",
                        session_context.id, session_context.address,
                    );
                    self.network_state.with_peer_store_mut(|peer_store| {
                        peer_store.remove_disconnected_peer(&(&session_context.address).into());
                    });
                }
            }
            _ => {
                info!("p2p service event: {:?}", event);
            }
        }
    }
}

/// Network controller
#[derive(Clone)]
pub struct NetworkController {
    pub(crate) version: String,
    pub(crate) network_state: Arc<NetworkState>,
    pub(crate) p2p_control: ServiceControl,
    pub(crate) ping_controller: Option<Sender<()>>,
}

/// Ckb network service, use to start p2p network
pub struct NetworkService {
    p2p_service: Service<EventHandler>,
    network_state: Arc<NetworkState>,
    ping_controller: Option<Sender<()>>,
    // Background services
    bg_services: Vec<Pin<Box<dyn Future<Output = ()> + 'static + Send>>>,
    version: String,
}

impl NetworkService {
    /// init with all config
    pub fn new(
        network_state: Arc<NetworkState>,
        protocols: Vec<CKBProtocol>,
        required_protocols: Vec<SupportProtocols>,
        // name, version, flags
        identify_announce: (String, String, Flags),
    ) -> Self {
        let config = &network_state.config;

        if config.support_protocols.iter().collect::<HashSet<_>>()
            != default_support_all_protocols()
                .iter()
                .collect::<HashSet<_>>()
        {
            warn!(
                "Customized supported protocols: {:?}",
                config.support_protocols
            );
        }

        // == Build p2p service struct
        let mut protocol_metas = protocols
            .into_iter()
            .map(CKBProtocol::build)
            .collect::<Vec<_>>();

        // == Build special protocols

        // Identify is a core protocol, user cannot disable it via config
        let identify_callback = IdentifyCallback::new(
            Arc::clone(&network_state),
            identify_announce.0,
            identify_announce.1.clone(),
            identify_announce.2,
        );
        let identify_meta = SupportProtocols::Identify.build_meta_with_service_handle(move || {
            ProtocolHandle::Callback(Box::new(IdentifyProtocol::new(identify_callback)))
        });
        protocol_metas.push(identify_meta);

        // Ping protocol
        let ping_controller = if config.support_protocols.contains(&SupportProtocol::Ping) {
            let ping_interval = Duration::from_secs(config.ping_interval_secs);
            let ping_timeout = Duration::from_secs(config.ping_timeout_secs);

            let ping_network_state = Arc::clone(&network_state);
            let (ping_handler, ping_controller) =
                PingHandler::new(ping_interval, ping_timeout, ping_network_state);
            let ping_meta = SupportProtocols::Ping.build_meta_with_service_handle(move || {
                ProtocolHandle::Callback(Box::new(ping_handler))
            });
            protocol_metas.push(ping_meta);
            Some(ping_controller)
        } else {
            None
        };

        // Discovery protocol
        if config
            .support_protocols
            .contains(&SupportProtocol::Discovery)
        {
            let addr_mgr = DiscoveryAddressManager {
                network_state: Arc::clone(&network_state),
                discovery_local_address: config.discovery_local_address,
            };
            let disc_meta = SupportProtocols::Discovery.build_meta_with_service_handle(move || {
                ProtocolHandle::Callback(Box::new(DiscoveryProtocol::new(
                    addr_mgr,
                    config
                        .discovery_announce_check_interval_secs
                        .map(Duration::from_secs),
                )))
            });
            protocol_metas.push(disc_meta);
        }

        // Feeler protocol
        if config.support_protocols.contains(&SupportProtocol::Feeler) {
            let feeler_meta = SupportProtocols::Feeler.build_meta_with_service_handle({
                let network_state = Arc::clone(&network_state);
                move || ProtocolHandle::Callback(Box::new(Feeler::new(Arc::clone(&network_state))))
            });
            protocol_metas.push(feeler_meta);
        }

        // DisconnectMessage protocol
        if config
            .support_protocols
            .contains(&SupportProtocol::DisconnectMessage)
        {
            let disconnect_message_state = Arc::clone(&network_state);
            let disconnect_message_meta = SupportProtocols::DisconnectMessage
                .build_meta_with_service_handle(move || {
                    ProtocolHandle::Callback(Box::new(DisconnectMessageProtocol::new(
                        disconnect_message_state,
                    )))
                });
            protocol_metas.push(disconnect_message_meta);
        }

        let mut service_builder = ServiceBuilder::default();
        let yamux_config = YamuxConfig {
            max_stream_count: protocol_metas.len(),
            max_stream_window_size: 1024 * 1024,
            ..Default::default()
        };
        for meta in protocol_metas.into_iter() {
            network_state
                .protocols
                .write()
                .push((meta.id(), meta.name(), meta.support_versions()));
            service_builder = service_builder.insert_protocol(meta);
        }
        let event_handler = EventHandler {
            network_state: Arc::clone(&network_state),
        };
        service_builder = service_builder
            .key_pair(network_state.local_private_key.clone())
            .upnp(config.upnp)
            .yamux_config(yamux_config)
            .forever(true)
            .max_connection_number(1024)
            .set_send_buffer_size(config.max_send_buffer())
            .set_channel_size(config.channel_size())
            .timeout(Duration::from_secs(5));

        #[cfg(target_os = "linux")]
        let p2p_service = {
            if config.reuse_port_on_linux {
                let iter = config.listen_addresses.iter();

                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                enum TransportType {
                    Ws,
                    Tcp,
                }

                fn find_type(addr: &Multiaddr) -> TransportType {
                    let mut iter = addr.iter();

                    iter.find_map(|proto| {
                        if let p2p::multiaddr::Protocol::Ws = proto {
                            Some(TransportType::Ws)
                        } else {
                            None
                        }
                    })
                    .unwrap_or(TransportType::Tcp)
                }

                #[derive(Clone, Copy, Debug, Eq, PartialEq)]
                enum BindType {
                    None,
                    Ws,
                    Tcp,
                    Both,
                }
                impl BindType {
                    fn transform(&mut self, other: TransportType) {
                        match (&self, other) {
                            (BindType::None, TransportType::Ws) => *self = BindType::Ws,
                            (BindType::None, TransportType::Tcp) => *self = BindType::Tcp,
                            (BindType::Ws, TransportType::Tcp) => *self = BindType::Both,
                            (BindType::Tcp, TransportType::Ws) => *self = BindType::Both,
                            _ => (),
                        }
                    }

                    fn is_ready(&self) -> bool {
                        // should change to Both if ckb enable ws
                        matches!(self, BindType::Tcp)
                    }
                }

                let mut init = BindType::None;
                for addr in iter {
                    if init.is_ready() {
                        break;
                    }
                    match find_type(addr) {
                        // wait ckb enable ws support
                        TransportType::Ws => (),
                        TransportType::Tcp => {
                            // only bind once
                            if matches!(init, BindType::Tcp) {
                                continue;
                            }
                            if let Some(addr) = multiaddr_to_socketaddr(addr) {
                                use p2p::service::TcpSocket;
                                let domain = socket2::Domain::for_address(addr);
                                service_builder =
                                    service_builder.tcp_config(move |socket: TcpSocket| {
                                        let socket_ref = socket2::SockRef::from(&socket);
                                        #[cfg(all(
                                            unix,
                                            not(target_os = "solaris"),
                                            not(target_os = "illumos")
                                        ))]
                                        socket_ref.set_reuse_port(true)?;

                                        socket_ref.set_reuse_address(true)?;
                                        if socket_ref.domain()? == domain {
                                            socket_ref.bind(&addr.into())?;
                                        }
                                        Ok(socket)
                                    });
                                init.transform(TransportType::Tcp)
                            }
                        }
                    }
                }
            }

            service_builder.build(event_handler)
        };

        #[cfg(not(target_os = "linux"))]
        // The default permissions of Windows are not enough to enable this function,
        // and the administrator permissions of group permissions must be turned on.
        // This operation is very burdensome for windows users, so it is turned off by default
        //
        // The integration test fails after MacOS is turned on, the behavior is different from linux.
        // Decision to turn off it
        let p2p_service = service_builder.build(event_handler);

        // == Build background service tasks
        // TODO: need port this to libp2p, one thing that we need to be careful
        // is that we use the same MultiAddr format for libp2p and tentacle.
        let dump_peer_store_service = DumpPeerStoreService::new(Arc::clone(&network_state));
        // TODO: need port this to libp2p
        let protocol_type_checker_service = ProtocolTypeCheckerService::new(
            Arc::clone(&network_state),
            p2p_service.control().to_owned().into(),
            required_protocols
                .iter()
                .map(|p| (*p).protocol_id())
                .collect(),
        );
        let mut bg_services = vec![
            Box::pin(dump_peer_store_service) as Pin<Box<_>>,
            Box::pin(protocol_type_checker_service) as Pin<Box<_>>,
        ];
        // TODO: need port this to libp2p
        if config.outbound_peer_service_enabled() {
            let outbound_peer_service = OutboundPeerService::new(
                Arc::clone(&network_state),
                p2p_service.control().to_owned().into(),
                Duration::from_secs(config.connect_outbound_interval_secs),
            );
            bg_services.push(Box::pin(outbound_peer_service) as Pin<Box<_>>);
        };

        #[cfg(feature = "with_dns_seeding")]
        if config.dns_seeding_service_enabled() {
            let dns_seeding_service = crate::services::dns_seeding::DnsSeedingService::new(
                Arc::clone(&network_state),
                config.dns_seeds.clone(),
            );
            bg_services.push(Box::pin(dns_seeding_service.start()) as Pin<Box<_>>);
        };

        NetworkService {
            p2p_service,
            network_state,
            ping_controller,
            bg_services,
            version: identify_announce.1,
        }
    }

    /// Start the network in the background and return a controller
    pub fn start<S: Spawn>(self, handle: &S) -> Result<NetworkController, Error> {
        let config = self.network_state.config.clone();

        let p2p_control: ServiceControl = self.p2p_service.control().to_owned().into();

        let target = &self.network_state.required_flags;

        // get bootnodes
        // try get addrs from peer_store, if peer_store have no enough addrs then use bootnodes
        let nodes_to_dial = self.network_state.with_peer_store_mut(|peer_store| {
            let count = max((config.max_outbound_peers >> 1) as usize, 1);
            let mut addrs = self
                .network_state
                .config
                .whitelist_peers()
                .into_iter()
                .map(Into::into)
                .collect::<Vec<_>>();
            addrs.extend(
                peer_store
                    .fetch_addrs_to_attempt(count, Some(*target), PeerType::Tentacle)
                    .into_iter()
                    .map(|paddr| paddr.addr)
                    .collect::<Vec<_>>(),
            );
            // Get bootnodes randomly
            let bootnodes = self
                .network_state
                .bootnodes
                .iter()
                .choose_multiple(&mut rand::thread_rng(), count.saturating_sub(addrs.len()))
                .into_iter()
                .map(Into::into)
                .cloned();
            addrs.extend(bootnodes);
            addrs
        });

        let Self {
            mut p2p_service,
            network_state,
            ping_controller,
            bg_services,
            version,
        } = self;

        // Start background tasks, and returns a token which cancel background tasks when it is dropped.
        let bg_signals = {
            let (bg_signals, bg_receivers): (Vec<_>, Vec<_>) = bg_services
                .into_iter()
                .map(|bg_service| {
                    let (signal_sender, signal_receiver) = oneshot::channel::<()>();
                    (signal_sender, (bg_service, signal_receiver))
                })
                .unzip();
            for (mut service, mut receiver) in bg_receivers {
                handle.spawn_task(async move {
                    loop {
                        tokio::select! {
                            _ = &mut service => {},
                            _ = &mut receiver => break
                        }
                    }
                });
            }
            bg_signals
        };

        let receiver: CancellationToken = new_tokio_exit_rx();
        let (start_sender, start_receiver) = mpsc::channel();
        {
            let network_state = Arc::clone(&network_state);
            let p2p_control: ServiceAsyncControl = p2p_control.clone().into();
            handle.spawn_task(async move {
                for addr in &config.listen_addresses {
                    match p2p_service.listen(addr.to_owned()).await {
                        Ok(listen_address) => {
                            info!("Listen on address: {}", listen_address);
                            network_state
                                .listened_addrs
                                .write()
                                .push(listen_address.into());
                        }
                        Err(err) => {
                            warn!(
                                "listen on address {} failed, due to error: {}",
                                addr.clone(),
                                err
                            );
                            start_sender
                                .send(Err(Error::P2P(P2PError::Transport(err))))
                                .expect("channel abnormal shutdown");
                            return;
                        }
                    };
                }
                start_sender.send(Ok(())).unwrap();
                tokio::spawn(async move { p2p_service.run().await });
                let _ = receiver.cancelled().await;
                info!("NetworkService receive exit signal, start shutdown...");
                let _ = p2p_control.shutdown().await;
                // Drop senders to stop all corresponding background task
                drop(bg_signals);
                info!("NetworkService shutdown now");
            });
        }

        if let Ok(Err(e)) = start_receiver.recv() {
            return Err(e);
        }

        let nc = NetworkController {
            version,
            network_state,
            p2p_control,
            ping_controller,
        };

        for addr in nodes_to_dial {
            debug!("dial node {:?}", addr);
            nc.network_state.dial_identify(&nc.p2p_control, addr);
        }
        Ok(nc)
    }
}

// Send an optional message before disconnect a peer
pub(crate) fn disconnect_with_message(
    control: &ServiceControl,
    peer_index: SessionId,
    message: &str,
) -> Result<(), SendErrorKind> {
    if !message.is_empty() {
        let data = Bytes::from(message.as_bytes().to_vec());
        // Must quick send, otherwise this message will be dropped.
        control.quick_send_message_to(
            peer_index,
            SupportProtocols::DisconnectMessage.protocol_id(),
            data,
        )?;
    }
    control.disconnect(peer_index)
}

pub(crate) async fn async_disconnect_with_message(
    control: &ServiceAsyncControl,
    peer_index: SessionId,
    message: &str,
) -> Result<(), SendErrorKind> {
    if !message.is_empty() {
        let data = Bytes::from(message.as_bytes().to_vec());
        // Must quick send, otherwise this message will be dropped.
        control
            .quick_send_message_to(
                peer_index,
                SupportProtocols::DisconnectMessage.protocol_id(),
                data,
            )
            .await?;
    }
    control.disconnect(peer_index).await
}
