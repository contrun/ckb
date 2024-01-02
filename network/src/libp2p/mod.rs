use crate::{peer::PeerType, NetworkState};

use crate::errors::Error;
use crate::SupportProtocols;

use ckb_async_runtime::Handle;
use ckb_logger::{debug, error, info, trace, warn};

use core::time::Duration;
use libp2p::{
    identify, noise, ping,
    request_response::{self, ProtocolSupport},
    swarm::behaviour::toggle::Toggle,
    swarm::NetworkBehaviour,
    swarm::SwarmEvent,
    tcp, yamux, StreamProtocol, Swarm,
};

use serde::{Deserialize, Serialize};

use ckb_spawn::Spawn;
use tokio::{select, sync::mpsc, time};

use futures::StreamExt;
use std::{sync::Arc, time::Instant};

pub use libp2p::Multiaddr;
pub use libp2p::PeerId;

use self::sync::{SyncRequest, SyncResponse};

mod sync;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DisconnectMessageRequest(String);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DisconnectMessageResponse(String);

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    identify: identify::Behaviour,
    ping: Toggle<ping::Behaviour>,
    disconnect_message: Toggle<
        request_response::cbor::Behaviour<DisconnectMessageRequest, DisconnectMessageResponse>,
    >,
    sync: Toggle<request_response::cbor::Behaviour<SyncRequest, SyncResponse>>,
}

#[derive(Debug, Clone)]
pub enum Command {
    Dial { multiaddr: Multiaddr },
    Disconnect { peer: PeerId, message: String },
    GetHeader,
}

pub enum Event {}

pub struct NetworkService {
    swarm: Swarm<MyBehaviour>,
    network_state: Arc<NetworkState>,
    command_receiver: mpsc::Receiver<Command>,
}

impl NetworkService {
    async fn run(mut self) {
        loop {
            tokio::select! {
                event = self.swarm.next() => {
                    info!("{:?}", &event);
                    self.handle_event(event.expect("Swarm stream to be infinite.")).await;
                },
                command = self.command_receiver.recv() => {
                    trace!("{:?}", &command);
                    match command {
                        Some(command) => self.handle_command(command).await,
                        None => {
                            info!("Command sender dropped, exiting libp2p network service");
                            return
                        },
                    }
                },
            }
        }
    }

    async fn handle_event(&mut self, event: SwarmEvent<MyBehaviourEvent>) {
        match event {
            SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                info!("Connected to {}", peer_id);
            }
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                info!("Disconnected from {}", peer_id);
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::Ping(ping::Event {
                peer,
                result,
                connection,
            })) => {
                info!(
                    "Ping Peer {} result {:?} connection {}",
                    peer, result, connection
                );
                match result {
                    Err(e) => {
                        info!(
                            "Closing connection {} to peer {} because ping failure ({})",
                            connection, peer, e
                        );
                        let _ = self.swarm.close_connection(connection);
                    }
                    Ok(duration) => {
                        let now = Instant::now();
                        self.network_state.with_peer_registry_mut(|reg| {
                            if let Some(peer) = reg.get_peer_mut(peer) {
                                peer.last_ping_protocol_message_received_at = Some(now);
                                peer.ping_rtt = Some(duration);
                            }
                        });
                    }
                }
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::Identify(event)) => {
                info!("Identify event {:?}", event);
                match event {
                    identify::Event::Received { peer_id, info } => {
                        // NOTE: be careful, here easy cause a deadlock,
                        //    because peer_store's lock scope across peer_registry's lock scope
                        let mut peer_store = self.network_state.peer_store.lock();
                        let accept_peer_result = {
                            self.network_state.peer_registry.write().accept_libp2p_peer(
                                peer_id,
                                info,
                                &mut peer_store,
                            )
                        };
                        if let Err(error) = accept_peer_result {
                            error!("Accept peer {peer_id} error: {error}");
                        }
                    }
                    _ => {}
                }
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::DisconnectMessage(
                request_response::Event::Message { message, peer },
            )) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    info!(
                        "Sending disconnect message request ({:?}) from channel {:?}",
                        request, channel
                    );

                    let disconnect_message = &mut self.swarm.behaviour_mut().disconnect_message;
                    if !disconnect_message.is_enabled() {
                        return;
                    }
                    let disconnect_message = disconnect_message.as_mut().unwrap();

                    let _ = disconnect_message
                        .send_response(channel, DisconnectMessageResponse("Ok, bye".to_string()));
                    let _ = self.swarm.disconnect_peer_id(peer);
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    info!(
                        "Received disconnect message response ({:?}) for request_id {:?}",
                        response, request_id,
                    );
                }
            },
            SwarmEvent::Behaviour(MyBehaviourEvent::Sync(request_response::Event::Message {
                message,
                peer,
            })) => match message {
                request_response::Message::Request {
                    request, channel, ..
                } => {
                    info!(
                        "Sending sync request ({:?}) from channel {:?} of peer {:?}",
                        request, channel, peer
                    );

                    let sync = &mut self.swarm.behaviour_mut().sync;
                    if !sync.is_enabled() {
                        return;
                    }
                    let sync = sync.as_mut().unwrap();

                    let _ = sync.send_response(channel, SyncResponse("Got you".to_string()));
                }
                request_response::Message::Response {
                    request_id,
                    response,
                } => {
                    info!(
                        "Received disconnect message response ({:?}) for request_id {:?}",
                        response, request_id,
                    );
                }
            },
            SwarmEvent::Behaviour(MyBehaviourEvent::DisconnectMessage(
                request_response::Event::OutboundFailure {
                    request_id, error, ..
                },
            )) => {
                info!(
                    "Outbound connection for request_id {} failed: {}",
                    request_id, error
                );
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::DisconnectMessage(
                request_response::Event::ResponseSent { .. },
            )) => {}
            other => {
                debug!("Unhandled {:?}", other);
            }
        };
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::Dial { multiaddr } => {
                if let Err(error) = self.swarm.dial(multiaddr.clone()) {
                    error!("Dialing libp2p peer {} failed: {}", multiaddr, error);
                } else {
                    info!("Dialing libp2p peer {} succeeded", multiaddr);
                }
            }
            Command::Disconnect { peer, message } => {
                let disconnect_message = &mut self.swarm.behaviour_mut().disconnect_message;
                if !disconnect_message.is_enabled() {
                    return;
                }
                let disconnect_message = disconnect_message.as_mut().unwrap();

                let request_id =
                    &disconnect_message.send_request(&peer, DisconnectMessageRequest(message));
                info!(
                    "Disconnect message send to {}, request_id {:?}",
                    peer, request_id
                );
            }
            Command::GetHeader => {
                let sync = &mut self.swarm.behaviour_mut().sync;
                if !sync.is_enabled() {
                    return;
                }
                let sync = sync.as_mut().unwrap();

                let addrs: Vec<PeerId> = self
                    .network_state
                    .peer_store
                    .lock()
                    .fetch_addrs_to_attempt(10, None, PeerType::Libp2p)
                    .into_iter()
                    .filter_map(|paddr| {
                        let peer: Result<PeerId, _> = (&paddr.addr).try_into();
                        match peer {
                            Ok(peer) => Some(peer),
                            Err(_) => {
                                warn!("Peer multi address without peerId: {:?}", &paddr.addr);
                                None
                            }
                        }
                    })
                    .collect::<Vec<_>>();
                for addr in addrs {
                    let peer: PeerId = addr.try_into().expect("Multiaddr to PeerId");
                    let request_id =
                        &sync.send_request(&peer, SyncRequest("hello world".to_string()));
                    info!("Sync message send to {}, request_id {:?}", peer, request_id);
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct NetworkController {
    pub(crate) handle: Handle,
    pub(crate) command_sender: mpsc::Sender<Command>,
}

impl NetworkController {
    pub fn new(
        handle: &Handle,
        network_identification: String,
        client_version: String,
        network_state: Arc<NetworkState>,
        supported_protocols: &[SupportProtocols],
        _required_protocol_ids: &[SupportProtocols],
    ) -> Result<Self, Error> {
        info!("supported protocols {:?}", supported_protocols);
        let priv_key_bytes: [u8; 32] = network_state
            .config
            .fetch_private_key_bytes()?
            .try_into()
            .expect("Private key must be of length 32");

        // TODO: CKB actually use secp256k1 secret key.
        // libp2p::identity only exports function secp256k1_from_der
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(priv_key_bytes)
            .expect("Valid ed25519 key");

        let ping_behaviour =
            Toggle::from(if supported_protocols.contains(&SupportProtocols::Ping) {
                let interval = Duration::from_secs(network_state.config.ping_interval_secs);
                let timeout = Duration::from_secs(network_state.config.ping_timeout_secs);
                Some(ping::Behaviour::new(
                    ping::Config::new()
                        .with_interval(interval)
                        .with_timeout(timeout),
                ))
            } else {
                None
            });

        let disconnect_message_supported =
            supported_protocols.contains(&SupportProtocols::DisconnectMessage);
        let disconenct_message_behaviour = Toggle::from(if disconnect_message_supported {
            Some(request_response::cbor::Behaviour::new(
                [(
                    StreamProtocol::try_from_owned(SupportProtocols::DisconnectMessage.name())
                        .expect("Protocol of DisconnectMessage name start with /"),
                    ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ))
        } else {
            None
        });

        let sync_supported = supported_protocols.contains(&SupportProtocols::Sync);
        let sync_behaviour = Toggle::from(if sync_supported {
            Some(request_response::cbor::Behaviour::new(
                [(
                    StreamProtocol::try_from_owned(SupportProtocols::Sync.name())
                        .expect("Protocol of Sync name start with /"),
                    ProtocolSupport::Full,
                )],
                request_response::Config::default(),
            ))
        } else {
            None
        });

        let swarm = libp2p::SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                // According to the comment, https://github.com/contrun/ckb/commit/0567f1a203fae9c7389109de93864cfb20cb9f80#r135680667
                // The default config is not optimal.
                // TODO: Do some benchmark and change this parameter.
                yamux::Config::default,
            )
            .expect("Create tcp transport")
            .with_behaviour(|key| MyBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    format!("{}/{}/0.0.1", network_identification, client_version),
                    key.public(),
                )),
                ping: ping_behaviour,
                disconnect_message: disconenct_message_behaviour,
                sync: sync_behaviour,
            })
            .expect("Create behaviour")
            .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(Duration::from_secs(3600)))
            .build();

        let libp2p_port = std::env::var("LIBP2P_PORT")
            .unwrap_or_default()
            .parse::<i16>()
            .unwrap_or_default();
        let (command_sender, command_receiver) = mpsc::channel(100);
        let mut service = NetworkService {
            swarm,
            network_state,
            command_receiver,
        };

        handle.spawn_task(async move {
            let addr = format!("/ip4/0.0.0.0/tcp/{}", libp2p_port);
            // Note that although listen_on is not an async function,
            // it actually requires a runtime, so we must call it within a handle.spawn_task.
            let result = service
                .swarm
                .listen_on(addr.parse().expect("Correct multiaddr"));
            let _ = result.expect("libp2p listen succeed");
            info!(
                "libp2p listen on {}/p2p/{}",
                addr,
                service.swarm.local_peer_id()
            );
            service.run().await;
        });

        if sync_supported {
            let command_sender = command_sender.clone();
            let mut interval = time::interval(Duration::from_secs(1));
            handle.spawn_task(async move {
                select! {
                    _ = interval.tick() => {
                        command_sender.send(Command::GetHeader).await.expect("receiver not dropped");
                    },
                }
            });
        }
        Ok(NetworkController {
            handle: handle.clone(),
            command_sender,
        })
    }
}
