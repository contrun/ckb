use ckb_network::NetworkState;

use ckb_network::SupportProtocols;

use ckb_async_runtime::Handle;
use ckb_logger::{debug, error, info, trace};
use ckb_network::async_trait;
use ckb_stop_handler::new_tokio_exit_rx;

use ckb_network::libp2p::{
    futures::StreamExt,
    identify, identity, noise, ping,
    request_response::{self, ProtocolSupport},
    serde,
    swarm::behaviour::toggle::Toggle,
    swarm::SwarmEvent,
    tcp, yamux, Command, Deserialize, NetworkServiceTrait, PeerId, Serialize,
    StreamProtocol, Swarm, SwarmBuilder,
    swarm::NetworkBehaviour
};
use core::time::Duration;


use ckb_network::tokio::{select, sync::mpsc, time};
use ckb_spawn::Spawn;

use std::sync::Arc;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "self::serde")] // must be below the derive attribute
pub struct SyncRequest(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "self::serde")] // must be below the derive attribute
pub struct SyncResponse(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "self::serde")] // must be below the derive attribute
pub struct DisconnectMessageRequest(String);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "self::serde")] // must be below the derive attribute
pub struct DisconnectMessageResponse(String);

#[derive(NetworkBehaviour)]
pub struct MyBehaviour {
    identify: identify::Behaviour,
    ping: Toggle<ping::Behaviour>,
    disconnect_message: Toggle<
        request_response::cbor::Behaviour<DisconnectMessageRequest, DisconnectMessageResponse>,
    >,
    sync: Toggle<request_response::cbor::Behaviour<SyncRequest, SyncResponse>>,
}

pub fn new_swarm(
    handle: Handle,
    network_identification: String,
    client_version: String,
    network_state: Arc<NetworkState>,
    supported_protocols: &[SupportProtocols],
    _required_protocol_ids: &[SupportProtocols],
    command_sender: mpsc::Sender<Command>,
) -> Swarm<MyBehaviour> {
    info!("supported protocols {:?}", supported_protocols);
    let priv_key_bytes: [u8; 32] = network_state
        .config
        .fetch_private_key_bytes()
        .expect("Private key must be set")
        .try_into()
        .expect("Private key must be of length 32");

    // TODO: CKB actually use secp256k1 secret key.
    // identity only exports function secp256k1_from_der
    let keypair = identity::Keypair::ed25519_from_bytes(priv_key_bytes).expect("Valid ed25519 key");

    let ping_behaviour = Toggle::from(if supported_protocols.contains(&SupportProtocols::Ping) {
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
    if sync_supported {
        let command_sender = command_sender.clone();
        handle.spawn_task(async move {
            let mut interval = time::interval(Duration::from_secs(1));
            let rx = new_tokio_exit_rx();
            loop {
                select! {
                    _ = interval.tick() => {
                        command_sender.send(Command::GetHeader).await.expect("receiver not dropped");
                    },
                    _ = rx.cancelled() => {
                        info!("Exit signal received, exit now");
                        break
                    },
                }
            }
        });
    }

    let swarm = SwarmBuilder::with_existing_identity(keypair)
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

    swarm
}

pub struct NetworkService {
    swarm: Swarm<MyBehaviour>,
    network_state: Arc<NetworkState>,
    command_receiver: mpsc::Receiver<Command>,
}

#[async_trait]
impl NetworkServiceTrait for NetworkService {
    type Behaviour = MyBehaviour;
    type State = Arc<NetworkState>;

    fn new(
        swarm: Swarm<Self::Behaviour>,
        network_state: Self::State,
        command_receiver: mpsc::Receiver<Command>,
    ) -> Self {
        Self {
            swarm,
            network_state,
            command_receiver,
        }
    }
    async fn run(mut self) {
        loop {
            select! {
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
                        // TODO: save ping result to peer_store
                        info!(
                            "Ping peer {} with duration {:?} success",
                            peer, duration
                        );
                    }
                }
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::Identify(event)) => {
                info!("Identify event {:?}", event);
                match event {
                    identify::Event::Received { peer_id, info } => {
                        // NOTE: be careful, here easy cause a deadlock,
                        //    because peer_store's lock scope across peer_registry's lock scope
                        
                        // TODO: we should use peer_store to store peer info
                        info!("Received identify event from peer {:?} {:?}", peer_id, info);
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
                info!("GetHeader command received, trying to send sync request");
                let sync = &mut self.swarm.behaviour_mut().sync;
                if !sync.is_enabled() {
                    return;
                }
                let sync = sync.as_mut().unwrap();

                // TODO: get peers from peer_store
                let peers: Vec<PeerId> = vec![];
                info!("Fetched peers from network state {:?}", peers);
                for peer in peers {
                    let request_id =
                        &sync.send_request(&peer, SyncRequest("hello world".to_string()));
                    info!("Sync message send to {}, request_id {:?}", peer, request_id);
                }
            }
        }
    }
}
