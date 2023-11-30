//! Global state struct and start function
pub(crate) use super::tentacle::async_disconnect_with_message as tentacle_async_disconnect_with_message;
pub(crate) use super::tentacle::disconnect_with_message as tentacle_disconnect_with_message;
pub use super::tentacle::EventHandler as TentacleEventHandler;
pub use super::tentacle::NetworkService as TentacleNetworkService;

use crate::errors::Error;
use crate::libp2p;

use crate::peer_registry::{ConnectionStatus, PeerRegistry};
use crate::peer_store::{
    types::{AddrInfo, BannedAddr},
    PeerStore,
};
use crate::tentacle;
use crate::tentacle::protocols::identify::Flags;
use crate::SupportProtocols;

use crate::{
    Behaviour, Multiaddr, Peer, PeerId, PeerIndex, ProtocolId, ServiceControl, TentacleMultiaddr,
    TentaclePeerId,
};
use ckb_app_config::NetworkConfig;
use ckb_logger::{debug, error, info, trace, warn};

use ckb_spawn::Spawn;
use ckb_util::{Condvar, Mutex, RwLock};
use ipnetwork::IpNetwork;
use p2p::{
    bytes::Bytes,
    context::SessionContext,
    error::SendErrorKind,
    multiaddr::Protocol,
    secio::{self},
    service::{TargetProtocol, TargetSession},
    utils::{extract_peer_id, is_reachable, multiaddr_to_socketaddr},
    SessionId,
};
use rand::prelude::IteratorRandom;
#[cfg(feature = "with_sentry")]
use sentry::{capture_message, with_scope, Level};

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
    usize,
};

const P2P_SEND_TIMEOUT: Duration = Duration::from_secs(6);
const P2P_TRY_SEND_INTERVAL: Duration = Duration::from_millis(100);
// After 5 minutes we consider this dial hang
const DIAL_HANG_TIMEOUT: Duration = Duration::from_secs(300);

/// The global shared state of the network module
pub struct NetworkState {
    pub(crate) peer_registry: RwLock<PeerRegistry>,
    pub(crate) peer_store: Mutex<PeerStore>,
    /// Node listened addresses
    pub(crate) listened_addrs: RwLock<Vec<Multiaddr>>,
    dialing_addrs: RwLock<HashMap<PeerId, Instant>>,
    /// Node public addresses,
    /// includes manually public addrs and remote peer observed addrs
    pub(crate) public_addrs: RwLock<HashSet<Multiaddr>>,
    pending_observed_addrs: RwLock<HashSet<Multiaddr>>,
    pub(crate) local_private_key: secio::SecioKeyPair,
    local_peer_id: PeerId,
    pub(crate) bootnodes: Vec<Multiaddr>,
    pub config: NetworkConfig,
    pub(crate) active: AtomicBool,
    /// Node supported protocols
    /// fields: ProtocolId, Protocol Name, Supported Versions
    pub(crate) protocols: RwLock<Vec<(ProtocolId, String, Vec<String>)>>,
    pub(crate) required_flags: Flags,

    pub(crate) ckb2023: AtomicBool,
}

impl NetworkState {
    /// Init from config
    pub fn from_config(config: NetworkConfig) -> Result<NetworkState, Error> {
        config.create_dir_if_not_exists()?;
        let local_private_key = config.fetch_private_key()?;
        let local_peer_id = local_private_key.peer_id();
        // set max score to public addresses
        let public_addrs: HashSet<Multiaddr> = config
            .listen_addresses
            .iter()
            .chain(config.public_addresses.iter())
            .cloned()
            .filter_map(|mut addr| {
                multiaddr_to_socketaddr(&addr)
                    .filter(|addr| is_reachable(addr.ip()))
                    .and({
                        if extract_peer_id(&addr).is_none() {
                            addr.push(Protocol::P2P(Cow::Borrowed(local_peer_id.as_bytes())));
                        }
                        Some(addr)
                    })
            })
            .map(Into::into)
            .collect();
        info!("loading the peer store, which may take a few seconds to complete");
        let peer_store = Mutex::new(PeerStore::load_from_dir_or_default(
            config.peer_store_path(),
        ));
        let bootnodes = config.bootnodes().into_iter().map(Into::into).collect();

        let peer_registry = PeerRegistry::new(
            config.max_inbound_peers(),
            config.max_outbound_peers(),
            config.whitelist_only,
            config.whitelist_peers().iter().map(Into::into).collect(),
        );

        Ok(NetworkState {
            peer_store,
            config,
            bootnodes,
            peer_registry: RwLock::new(peer_registry),
            dialing_addrs: RwLock::new(HashMap::default()),
            public_addrs: RwLock::new(public_addrs),
            listened_addrs: RwLock::new(Vec::new()),
            pending_observed_addrs: RwLock::new(HashSet::default()),
            local_private_key,
            local_peer_id: local_peer_id.into(),
            active: AtomicBool::new(true),
            protocols: RwLock::new(Vec::new()),
            required_flags: Flags::SYNC | Flags::DISCOVERY | Flags::RELAY,
            ckb2023: AtomicBool::new(false),
        })
    }

    /// fork flag
    pub fn ckb2023(self, init: bool) -> Self {
        self.ckb2023.store(init, Ordering::SeqCst);
        self
    }

    /// use to discovery get nodes message to announce what kind of node information need from the other peer
    /// default with `Flags::SYNC | Flags::DISCOVERY | Flags::RELAY`
    pub fn required_flags(mut self, flags: Flags) -> Self {
        self.required_flags = flags;
        self
    }

    pub(crate) fn report_session(
        &self,
        p2p_control: &ServiceControl,
        session_id: SessionId,
        behaviour: Behaviour,
    ) {
        if let Some(addr) = self.with_peer_registry(|reg| {
            reg.get_peer(session_id)
                .filter(|peer| !peer.is_whitelist)
                .map(|peer| peer.connected_addr.clone())
        }) {
            trace!("report {:?} because {:?}", addr, behaviour);
            let report_result = self.peer_store.lock().report(&addr, behaviour);
            if report_result.is_banned() {
                if let Err(err) =
                    tentacle_disconnect_with_message(p2p_control, session_id, "banned")
                {
                    debug!("Disconnect failed {:?}, error: {:?}", session_id, err);
                }
            }
        } else {
            debug!(
                "Report {} failed: not in peer registry or it is in the whitelist",
                session_id
            );
        }
    }

    pub(crate) fn remove_peer_from_registry(
        &self,
        session_id: impl Into<PeerIndex>,
        duration: Duration,
        reason: &str,
    ) {
        let session_id = session_id.into();
        if let Some(addr) = self.with_peer_registry(|reg| {
            reg.get_peer(session_id)
                .filter(|peer| !peer.is_whitelist)
                .map(|peer| peer.connected_addr.clone())
        }) {
            info!(
                "Ban peer {:?} for {} seconds, reason: {}",
                addr,
                duration.as_secs(),
                reason
            );
            if let Some(metrics) = ckb_metrics::handle() {
                metrics.ckb_network_ban_peer.inc();
            }
            if let Some(peer) = self.with_peer_registry_mut(|reg| reg.remove_peer(session_id)) {
                self.peer_store.lock().ban_addr(
                    &peer.connected_addr,
                    duration.as_millis() as u64,
                    reason,
                );
            }
        } else {
            debug!(
                "Ban session({:?}) failed: not in peer registry or it is in the whitelist",
                session_id
            );
        }
    }

    pub(crate) fn ban_session(
        &self,
        p2p_control: &ServiceControl,
        session_id: SessionId,
        duration: Duration,
        reason: &str,
    ) {
        self.remove_peer_from_registry(session_id, duration, reason);
        let message: String = format!("Ban for {} seconds, reason: {}", duration.as_secs(), reason);
        if let Err(err) =
            tentacle_disconnect_with_message(p2p_control, session_id, message.as_str())
        {
            debug!("Disconnect failed {:?}, error: {:?}", session_id, err);
        };
    }

    pub(crate) fn accept_peer(
        &self,
        session_context: &SessionContext,
    ) -> Result<Option<Peer>, Error> {
        // NOTE: be careful, here easy cause a deadlock,
        //    because peer_store's lock scope across peer_registry's lock scope
        let mut peer_store = self.peer_store.lock();
        let accept_peer_result = {
            self.peer_registry.write().accept_peer(
                session_context.address.clone().into(),
                session_context.id,
                session_context.ty,
                &mut peer_store,
            )
        };
        accept_peer_result.map_err(Into::into)
    }

    /// For restrict lock in inner scope
    pub fn with_peer_registry<F, T>(&self, callback: F) -> T
    where
        F: FnOnce(&PeerRegistry) -> T,
    {
        callback(&self.peer_registry.read())
    }

    // For restrict lock in inner scope
    pub(crate) fn with_peer_registry_mut<F, T>(&self, callback: F) -> T
    where
        F: FnOnce(&mut PeerRegistry) -> T,
    {
        callback(&mut self.peer_registry.write())
    }

    // For restrict lock in inner scope
    pub(crate) fn with_peer_store_mut<F, T>(&self, callback: F) -> T
    where
        F: FnOnce(&mut PeerStore) -> T,
    {
        callback(&mut self.peer_store.lock())
    }

    /// Get peer id of local node
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Use on test
    pub fn local_private_key(&self) -> &secio::SecioKeyPair {
        &self.local_private_key
    }

    /// Get local node's peer id in base58 format string
    pub fn node_id(&self) -> String {
        TentaclePeerId::from(self.local_peer_id()).to_base58()
    }

    pub(crate) fn public_addrs(&self, count: usize) -> Vec<Multiaddr> {
        self.public_addrs
            .read()
            .iter()
            .take(count)
            .cloned()
            .collect()
    }

    pub(crate) fn connection_status(&self) -> ConnectionStatus {
        self.peer_registry.read().connection_status()
    }

    /// Get local node's listen address list
    pub fn public_urls(&self, max_urls: usize) -> Vec<(String, u8)> {
        let listened_addrs = self.listened_addrs.read();
        self.public_addrs(max_urls.saturating_sub(listened_addrs.len()))
            .into_iter()
            .filter_map(|addr| {
                if !listened_addrs.contains(&addr) {
                    Some((addr, 1))
                } else {
                    None
                }
            })
            .chain(listened_addrs.iter().map(|addr| (addr.to_owned(), 1)))
            .map(|(addr, score)| {
                // TODO: We need also to consider libp2p address here
                (TentacleMultiaddr::from(addr).to_string(), score)
            })
            .collect()
    }

    pub(crate) fn add_node(&self, p2p_control: &ServiceControl, address: Multiaddr) {
        self.dial_identify(p2p_control, address);
    }

    /// use a filter to get protocol id list
    pub fn get_protocol_ids<F: Fn(ProtocolId) -> bool>(&self, filter: F) -> Vec<ProtocolId> {
        self.protocols
            .read()
            .iter()
            .filter_map(|&(id, _, _)| if filter(id) { Some(id) } else { None })
            .collect::<Vec<_>>()
    }

    pub(crate) fn can_dial(&self, addr: &Multiaddr) -> bool {
        let peer_id = PeerId::try_from(addr);
        if let Err(error) = peer_id {
            error!(
                "Do not dial addr without peer id, addr: {:?}, error: {}",
                addr, error
            );
            return false;
        }
        let peer_id = peer_id.as_ref().unwrap();

        if self.local_peer_id() == peer_id {
            trace!("Do not dial self: {:?}, {:?}", peer_id, addr);
            return false;
        }
        if self.public_addrs.read().contains(addr) {
            trace!(
                "Do not dial listened address(self): {:?}, {:?}",
                peer_id,
                addr
            );
            return false;
        }

        // Tentacle specific logic to check if we have already connnected to peer.
        match peer_id {
            PeerId::Tentacle(peer_id) => {
                let peer_in_registry = self.with_peer_registry(|reg| {
                    reg.get_key_by_peer_id(peer_id).is_some() || reg.is_feeler(addr)
                });
                if peer_in_registry {
                    trace!("Do not dial peer in registry: {:?}, {:?}", peer_id, addr);
                    return false;
                }
            }
            _ => {}
        }

        if let Some(dial_started) = self.dialing_addrs.read().get(peer_id) {
            trace!(
                "Do not repeat send dial command to network service: {:?}, {:?}",
                peer_id,
                addr
            );
            if Instant::now().saturating_duration_since(*dial_started) > DIAL_HANG_TIMEOUT {
                #[cfg(feature = "with_sentry")]
                with_scope(
                    |scope| scope.set_fingerprint(Some(&["ckb-network", "dialing-timeout"])),
                    || {
                        capture_message(
                            &format!(
                                "Dialing {:?}, {:?} for more than {} seconds, \
                                 something is wrong in network service",
                                peer_id,
                                addr,
                                DIAL_HANG_TIMEOUT.as_secs(),
                            ),
                            Level::Warning,
                        )
                    },
                );
            }
            return false;
        }

        true
    }

    pub(crate) fn dial_success(&self, addr: &Multiaddr) {
        if let Ok(peer_id) = PeerId::try_from(addr) {
            self.dialing_addrs.write().remove(&peer_id);
        }
    }

    pub(crate) fn dial_failed(&self, addr: &Multiaddr) {
        self.with_peer_registry_mut(|reg| {
            reg.remove_feeler(addr);
        });

        if let Ok(peer_id) = PeerId::try_from(addr) {
            self.dialing_addrs.write().remove(&peer_id);
        }
    }

    /// Dial
    /// return value indicates the dialing is actually sent or denied.
    fn dial_inner(
        &self,
        p2p_control: &ServiceControl,
        addr: Multiaddr,
        target: TargetProtocol,
    ) -> Result<(), Error> {
        if !self.can_dial(&addr) {
            return Err(Error::Dial(format!("ignore dialing addr {:?}", addr)));
        }

        debug!("dialing {:?}", addr);
        p2p_control.dial(TentacleMultiaddr::from(&addr), target)?;
        self.dialing_addrs.write().insert(
            PeerId::try_from(addr).expect("verified addr"),
            Instant::now(),
        );
        Ok(())
    }

    /// Dial just identify protocol
    pub fn dial_identify(&self, p2p_control: &ServiceControl, addr: Multiaddr) {
        if let Err(err) = self.dial_inner(
            p2p_control,
            addr,
            TargetProtocol::Single(SupportProtocols::Identify.protocol_id()),
        ) {
            debug!("dial_identify error: {err}");
        }
    }

    /// Dial just feeler protocol
    pub fn dial_feeler(&self, p2p_control: &ServiceControl, addr: Multiaddr) {
        if let Err(err) = self.dial_inner(
            p2p_control,
            addr.clone(),
            TargetProtocol::Single(SupportProtocols::Identify.protocol_id()),
        ) {
            debug!("dial_feeler error {err}");
        } else {
            self.with_peer_registry_mut(|reg| {
                reg.add_feeler(&addr);
            });
        }
    }

    /// this method is intent to check observed addr by dial to self
    pub(crate) fn try_dial_observed_addrs(&self, p2p_control: &ServiceControl) {
        let mut pending_observed_addrs = self.pending_observed_addrs.write();
        if pending_observed_addrs.is_empty() {
            let addrs = self.public_addrs.read();
            if addrs.is_empty() {
                return;
            }
            // random get addr
            if let Some(addr) = addrs.iter().choose(&mut rand::thread_rng()) {
                if let Err(err) = p2p_control.dial(
                    TentacleMultiaddr::from(addr),
                    TargetProtocol::Single(SupportProtocols::Identify.protocol_id()),
                ) {
                    trace!("try_dial_observed_addrs fail {err} on public address")
                }
            }
        } else {
            for addr in pending_observed_addrs.drain() {
                trace!("try dial observed addr: {:?}", addr);
                if let Err(err) = p2p_control.dial(
                    TentacleMultiaddr::from(addr),
                    TargetProtocol::Single(SupportProtocols::Identify.protocol_id()),
                ) {
                    trace!("try_dial_observed_addrs fail {err} on pending observed")
                }
            }
        }
    }

    /// add observed address for identify protocol
    pub(crate) fn add_observed_addrs(&self, iter: impl Iterator<Item = Multiaddr>) {
        let mut pending_observed_addrs = self.pending_observed_addrs.write();
        pending_observed_addrs.extend(iter)
    }

    /// Network message processing controller, default is true, if false, discard any received messages
    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::Relaxed)
    }
}

/// Exit trait used to notify all other module to exit
pub trait ExitHandler: Send + Unpin + 'static {
    /// notify other module to exit
    fn notify_exit(&self);
}

/// Default exit handle
#[derive(Clone, Default)]
pub struct DefaultExitHandler {
    lock: Arc<Mutex<()>>,
    exit: Arc<Condvar>,
}

impl DefaultExitHandler {
    /// Block on current thread util exit notify
    pub fn wait_for_exit(&self) {
        self.exit.wait(&mut self.lock.lock());
    }
}

impl ExitHandler for DefaultExitHandler {
    fn notify_exit(&self) {
        self.exit.notify_all();
    }
}

/// Network controller
#[derive(Clone)]
pub struct NetworkController {
    pub(crate) tentacle: Option<tentacle::NetworkController>,
    pub(crate) libp2p: Option<libp2p::NetworkController>,
}

impl NetworkController {
    pub fn new(
        tentacle: Option<tentacle::NetworkController>,
        libp2p: Option<libp2p::NetworkController>,
    ) -> Self {
        if tentacle.is_none() && libp2p.is_none() {
            panic!("Expect tentacle or libp2p network controller to be present.")
        }
        Self { tentacle, libp2p }
    }

    pub fn libp2p_controller(&self) -> Option<&libp2p::NetworkController> {
        self.libp2p.as_ref()
    }

    pub fn tentacle_controller(&self) -> Option<&tentacle::NetworkController> {
        self.tentacle.as_ref()
    }

    pub fn must_get_libp2p_controller(&self) -> &libp2p::NetworkController {
        self.libp2p.as_ref().expect("Tentacle controller exists")
    }

    pub fn must_get_tentacle_controller(&self) -> &tentacle::NetworkController {
        self.tentacle.as_ref().expect("Tentacle controller exists")
    }

    /// Set ckb2023 start
    pub fn init_ckb2023(&self) {
        self.must_get_tentacle_controller()
            .network_state
            .ckb2023
            .store(true, Ordering::SeqCst);
    }

    pub fn dial_libp2p_peer(&self, multiaddr: libp2p::Multiaddr) {
        let libp2p = self.must_get_libp2p_controller();

        let handle = &libp2p.handle;
        let command_sender = libp2p.command_sender.clone();
        info!("Dialing {}", &multiaddr);
        handle.spawn_task(async move {
            let _ = command_sender
                .send(libp2p::Command::Dial { multiaddr: multiaddr.into() })
                .await;
        });
    }

    pub fn disconnect_libp2p_peer(&self, peer: libp2p::PeerId, message: String) {
        let libp2p = self.must_get_libp2p_controller();

        let handle = &libp2p.handle;
        let command_sender = libp2p.command_sender.clone();
        info!("Disconnecting {}", &peer);
        handle.spawn_task(async move {
            let _ = command_sender
                .send(libp2p::Command::Disconnect { peer: peer.into(), message })
                .await;
        });
    }

    /// Get ckb2023 flag
    pub fn load_ckb2023(&self) -> bool {
        self.must_get_tentacle_controller()
            .network_state
            .ckb2023
            .load(Ordering::SeqCst)
    }

    /// Node listen address list
    pub fn public_urls(&self, max_urls: usize) -> Vec<(String, u8)> {
        self.must_get_tentacle_controller()
            .network_state
            .public_urls(max_urls)
    }

    /// ckb version
    pub fn version(&self) -> &String {
        &self.must_get_tentacle_controller().version
    }

    /// Node peer id's base58 format string
    pub fn node_id(&self) -> String {
        self.must_get_tentacle_controller().network_state.node_id()
    }

    /// p2p service control
    pub fn p2p_control(&self) -> &ServiceControl {
        &self.must_get_tentacle_controller().p2p_control
    }

    pub fn dial_node(&self, addr: Multiaddr) {
        self.must_get_tentacle_controller()
            .network_state
            .dial_identify(self.p2p_control(), addr);
    }

    /// Dial remote node
    pub fn add_node(&self, address: Multiaddr) {
        self.must_get_tentacle_controller()
            .network_state
            .add_node(self.p2p_control(), address)
    }

    /// Disconnect session with peer id
    pub fn remove_node(&self, peer_id: &PeerId) {
        match peer_id {
            PeerId::Tentacle(peer_id) => {
                if let Some(session_id) = self
                    .must_get_tentacle_controller()
                    .network_state
                    .peer_registry
                    .read()
                    .get_key_by_peer_id(peer_id)
                {
                    if let Err(err) = tentacle_disconnect_with_message(
                        self.p2p_control(),
                        session_id,
                        "disconnect manually",
                    ) {
                        debug!("Disconnect failed {:?}, error: {:?}", session_id, err);
                    }
                } else {
                    error!("Cannot find peer {:?}", peer_id);
                }
            }
            PeerId::Libp2p(_) => todo!("remove_node for libp2p not implemented"),
        }
    }

    /// Get banned peer list
    pub fn get_banned_addrs(&self) -> Vec<BannedAddr> {
        self.must_get_tentacle_controller()
            .network_state
            .peer_store
            .lock()
            .ban_list()
            .get_banned_addrs()
    }

    /// Clear banned list
    pub fn clear_banned_addrs(&self) {
        self.must_get_tentacle_controller()
            .network_state
            .peer_store
            .lock()
            .clear_ban_list();
    }

    /// Get address info from peer store
    pub fn addr_info(&self, addr: &Multiaddr) -> Option<AddrInfo> {
        self.must_get_tentacle_controller()
            .network_state
            .peer_store
            .lock()
            .addr_manager()
            .get(addr)
            .cloned()
    }

    /// Ban an ip
    pub fn ban(&self, address: IpNetwork, ban_until: u64, ban_reason: &str) {
        self.disconnect_peers_in_ip_range(address, ban_reason);
        self.must_get_tentacle_controller()
            .network_state
            .peer_store
            .lock()
            .ban_network(address, ban_until, ban_reason)
    }

    /// Unban an ip
    pub fn unban(&self, address: &IpNetwork) {
        self.must_get_tentacle_controller()
            .network_state
            .peer_store
            .lock()
            .mut_ban_list()
            .unban_network(address);
    }

    /// Return all connected peers' information
    pub fn connected_peers(&self) -> Vec<(PeerIndex, Peer)> {
        self.must_get_tentacle_controller()
            .network_state
            .with_peer_registry(|reg| {
                reg.peers()
                    .iter()
                    .map(|(peer_index, peer)| (*peer_index, peer.clone()))
                    .collect::<Vec<_>>()
            })
    }

    /// Ban an peer through peer index
    pub fn ban_peer(&self, peer_index: impl Into<PeerIndex>, duration: Duration, reason: &str) {
        match peer_index.into() {
            PeerIndex::Tentacle(s) => {
                self.must_get_tentacle_controller()
                    .network_state
                    .ban_session(self.p2p_control(), s, duration, reason);
            }
            PeerIndex::Libp2p(peer_id) => {
                self.must_get_libp2p_controller()
                    .command_sender
                    .try_send(libp2p::Command::Disconnect {
                        peer: peer_id.into(),
                        message: "".to_string(),
                    })
                    .expect("command receiver not closed");
            }
        }
    }

    /// disconnect peers with matched peer_ip or peer_ip_network, eg: 192.168.0.2 or 192.168.0.0/24
    fn disconnect_peers_in_ip_range(&self, address: IpNetwork, reason: &str) {
        self.must_get_tentacle_controller()
            .network_state
            .with_peer_registry(|reg| {
                reg.peers()
                    .iter()
                    .for_each(|(peer_index, peer)| match peer_index {
                        PeerIndex::Tentacle(peer_index) => {
                            if let Some(addr) =
                                multiaddr_to_socketaddr(&peer.connected_addr.clone().into())
                            {
                                if address.contains(addr.ip()) {
                                    let _ = tentacle_disconnect_with_message(
                                        self.p2p_control(),
                                        *peer_index,
                                        &format!("Ban peer {}, reason: {}", addr.ip(), reason),
                                    );
                                }
                            }
                        }
                        PeerIndex::Libp2p(_) => todo!(),
                    })
            });
    }

    fn try_broadcast(
        &self,
        quick: bool,
        target: Option<SessionId>,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result<(), SendErrorKind> {
        let now = Instant::now();
        loop {
            let target = target
                .map(TargetSession::Single)
                .unwrap_or(TargetSession::All);
            let result = if quick {
                self.p2p_control()
                    .quick_filter_broadcast(target, proto_id, data.clone())
            } else {
                self.p2p_control()
                    .filter_broadcast(target, proto_id, data.clone())
            };
            match result {
                Ok(()) => {
                    return Ok(());
                }
                Err(SendErrorKind::WouldBlock) => {
                    if Instant::now().saturating_duration_since(now) > P2P_SEND_TIMEOUT {
                        warn!("broadcast message to {} timeout", proto_id);
                        return Err(SendErrorKind::WouldBlock);
                    }
                    thread::sleep(P2P_TRY_SEND_INTERVAL);
                }
                Err(err) => {
                    warn!("broadcast message to {} failed: {:?}", proto_id, err);
                    return Err(err);
                }
            }
        }
    }

    /// Broadcast a message to all connected peers
    pub fn broadcast(&self, proto_id: ProtocolId, data: Bytes) -> Result<(), SendErrorKind> {
        self.try_broadcast(false, None, proto_id, data)
    }

    /// Broadcast a message to all connected peers through quick queue
    pub fn quick_broadcast(&self, proto_id: ProtocolId, data: Bytes) -> Result<(), SendErrorKind> {
        self.try_broadcast(true, None, proto_id, data)
    }

    /// Send message to one connected peer
    pub fn send_message_to(
        &self,
        session_id: SessionId,
        proto_id: ProtocolId,
        data: Bytes,
    ) -> Result<(), SendErrorKind> {
        self.try_broadcast(false, Some(session_id), proto_id, data)
    }

    /// network message processing controller, always true, if false, discard any received messages
    pub fn is_active(&self) -> bool {
        self.must_get_tentacle_controller()
            .network_state
            .is_active()
    }

    /// Change active status, if set false discard any received messages
    pub fn set_active(&self, active: bool) {
        self.must_get_tentacle_controller()
            .network_state
            .active
            .store(active, Ordering::Relaxed);
    }

    /// Return all connected peers' protocols info
    pub fn protocols(&self) -> Vec<(ProtocolId, String, Vec<String>)> {
        self.must_get_tentacle_controller()
            .network_state
            .protocols
            .read()
            .clone()
    }

    /// Try ping all connected peers
    pub fn ping_peers(&self) {
        if let Some(mut ping_controller) =
            self.must_get_tentacle_controller().ping_controller.clone()
        {
            let _ignore = ping_controller.try_send(());
        }
    }
}
