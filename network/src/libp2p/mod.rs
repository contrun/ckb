
use crate::{NetworkState};

use crate::errors::Error;
use crate::SupportProtocols;

use ckb_async_runtime::Handle;
use ckb_logger::{debug, error, info, trace};


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
use tokio::sync::mpsc;

use futures::StreamExt;
use std::sync::Arc;

pub use libp2p::Multiaddr;
pub use libp2p::PeerId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DisconnectMessageRequest(String);
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DisconnectMessageResponse(String);

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
    disconnect_message: Toggle<
        request_response::cbor::Behaviour<DisconnectMessageRequest, DisconnectMessageResponse>,
    >,
}

#[derive(Debug, Clone)]
pub enum Command {
    Dial { multiaddr: Multiaddr },
    Disconnect { peer: PeerId, message: String },
}

pub enum Event {}

pub struct NetworkService {
    swarm: Swarm<MyBehaviour>,
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
            SwarmEvent::Behaviour(MyBehaviourEvent::Ping(ping::Event { peer, result, .. })) => {
                info!("Ping Peer {} result {:?}", peer, result);
            }
            SwarmEvent::Behaviour(MyBehaviourEvent::Identify(event)) => {
                info!("Identify event {:?}", event);
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
        }
    }
}

#[derive(Clone)]
pub struct NetworkController {
    pub(crate) handle: Handle,
    pub(crate) network_state: Arc<NetworkState>,
    pub(crate) command_sender: mpsc::Sender<Command>,
    // event_reciever: mpsc::Receiver<Event>,
}

impl NetworkController {
    pub fn new(
        handle: &Handle,
        network_identification: String,
        client_version: String,
        network_state: Arc<NetworkState>,
        _supported_protocols: Vec<SupportProtocols>,
        _required_protocol_ids: Vec<SupportProtocols>,
    ) -> Result<Self, Error> {
        let priv_key_bytes: [u8; 32] = network_state
            .config
            .fetch_private_key_bytes()?
            .try_into()
            .expect("Private key must be of length 32");

        // TODO: CKB actually use secp256k1 secret key.
        // libp2p::identity only exports function secp256k1_from_der
        let keypair = libp2p::identity::Keypair::ed25519_from_bytes(priv_key_bytes)
            .expect("Valid ed25519 key");

        // TODO: Set this by reading from supported_protocols.
        let disconnect_message_supported = true;
        let disconenct_message_behaviour = Toggle::from(if disconnect_message_supported {
            Some(request_response::cbor::Behaviour::new(
                [(
                    StreamProtocol::try_from_owned(SupportProtocols::DisconnectMessage.name())
                        .expect("name start with /"),
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
                yamux::Config::default,
            )
            .expect("Create tcp transport")
            .with_behaviour(|key| MyBehaviour {
                identify: identify::Behaviour::new(identify::Config::new(
                    format!("{}/{}/0.0.1", network_identification, client_version),
                    key.public(),
                )),
                ping: ping::Behaviour::new(
                    ping::Config::new().with_interval(Duration::from_secs(1)),
                ),
                disconnect_message: disconenct_message_behaviour,
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
        Ok(NetworkController {
            handle: handle.clone(),
            network_state,
            command_sender,
        })
    }
}
