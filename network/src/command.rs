use crate::CKBProtocolContext;
use crate::{Behaviour, Peer, PeerIndex, SupportProtocols};
use ckb_logger::debug;
use p2p::bytes::Bytes;
use p2p::service::TargetSession;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

pub enum Command {
    Disconnect {
        peer_index: PeerIndex,
        message: String,
    },
    Ban {
        peer_index: PeerIndex,
        duration: Duration,
        reason: String,
    },
    Report {
        peer_index: PeerIndex,
        behaviour: Behaviour,
    },
    GetPeer {
        peer_index: PeerIndex,
        sender: oneshot::Sender<Option<Peer>>,
    },
    GetConnectedPeers {
        sender: oneshot::Sender<Vec<PeerIndex>>,
    },
    SendMessage {
        protocol: SupportProtocols,
        peer_index: PeerIndex,
        message: Bytes,
    },
    FilterBroadCast {
        protocol: SupportProtocols,
        target: TargetSession,
        message: Bytes,
        quick: bool,
    },
}

#[derive(Clone, Copy)]
pub struct CommandSenderContext {
    protocol: SupportProtocols,
    ckb2023: bool,
}

#[derive(Clone)]
pub struct CommandSender {
    context: CommandSenderContext,
    channel: mpsc::Sender<Command>,
}

impl CommandSender {
    pub fn new_from_nc(nc: Arc<dyn CKBProtocolContext + Sync>) -> (Self, mpsc::Receiver<Command>) {
        let (command_sender, command_receiver) = mpsc::channel(42);
        (
            Self {
                context: CommandSenderContext {
                    protocol: nc.protocol_id().into(),
                    ckb2023: nc.ckb2023(),
                },
                channel: command_sender,
            },
            command_receiver,
        )
    }
    pub fn send(&self, command: Command) -> Result<(), mpsc::error::SendError<Command>> {
        self.channel.blocking_send(command)
    }

    pub fn try_send(&self, command: Command) {
        let _ = self.send(command);
    }

    pub fn must_send(&self, command: Command) {
        self.send(command).expect("Receiver alive");
    }

    pub fn protocol(&self) -> SupportProtocols {
        self.context.protocol
    }

    pub fn ckb2023(&self) -> bool {
        self.context.ckb2023
    }

    pub fn get_peer(&self, peer: PeerIndex) -> Option<Peer> {
        let (sender, receiver) = oneshot::channel();
        match self.send(Command::GetPeer {
            peer_index: peer,
            sender,
        }) {
            Ok(_) => receiver.blocking_recv().ok().flatten(),
            Err(e) => {
                debug!("Failed to get peer {:?}: {:?}", peer, e);
                None
            }
        }
    }

    pub fn get_connected_peers(&self) -> Vec<PeerIndex> {
        let (sender, receiver) = oneshot::channel();
        match self.send(Command::GetConnectedPeers { sender }) {
            Ok(_) => receiver.blocking_recv().ok().unwrap_or_default(),
            Err(e) => {
                debug!("Failed to get connected peers: {:?}", e);
                vec![]
            }
        }
    }
}
