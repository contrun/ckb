use crate::CKBProtocolContext;
use crate::peer::BroadcastTarget;
use crate::{Behaviour, Peer, PeerIndex, SupportProtocols};
use ckb_logger::debug;
use p2p::bytes::Bytes;
use crate::Multiaddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

#[derive(Debug)]
pub enum Command {
    Dial {
        multiaddr: Multiaddr,
    },
    Disconnect {
        peer: PeerIndex,
        message: String,
    },
    Ban {
        peer: PeerIndex,
        duration: Duration,
        reason: String,
    },
    Report {
        peer: PeerIndex,
        behaviour: Behaviour,
    },
    GetPeer {
        peer: PeerIndex,
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
        target: BroadcastTarget,
        message: Bytes,
        quick: bool,
    },
}

#[derive(Clone, Copy, Default, Debug)]
pub struct CommandSenderContext {
    protocol: Option<SupportProtocols>,
    ckb2023: Option<bool>,
}

#[derive(Clone, Default, Debug)]
pub struct CommandSender {
    context: CommandSenderContext,
    channel: Option<mpsc::Sender<Command>>,
}

impl CommandSender {
    pub fn new_from_nc(nc: Arc<dyn CKBProtocolContext + Sync>) -> (Self, mpsc::Receiver<Command>) {
        let (command_sender, command_receiver) = mpsc::channel(42);
        (
            Self {
                context: CommandSenderContext {
                    protocol: Some(nc.protocol_id().into()),
                    ckb2023: Some(nc.ckb2023()),
                },
                channel: Some(command_sender),
            },
            command_receiver,
        )
    }

    pub fn with_mpsc_sender(mut self, mpsc_sender: mpsc::Sender<Command>) -> Self {
        self.channel = Some(mpsc_sender);
        self
    }
    pub fn with_ckb2023(mut self, ckb2023: bool) -> Self {
        self.context.ckb2023 = Some(ckb2023);
        self
    }
    pub fn with_protocol(mut self, protocol: SupportProtocols) -> Self {
        self.context.protocol = Some(protocol);
        self
    }

    pub fn send(&self, command: Command) -> Result<(), mpsc::error::SendError<Command>> {
        self.channel.as_ref().unwrap().blocking_send(command)
    }

    pub fn try_send(&self, command: Command) {
        let _ = self.send(command);
    }

    pub fn must_send(&self, command: Command) {
        self.send(command).expect("Receiver alive");
    }

    pub fn protocol(&self) -> SupportProtocols {
        self.context.protocol.unwrap()
    }

    pub fn ckb2023(&self) -> bool {
        self.context.ckb2023.unwrap()
    }

    pub fn get_peer(&self, peer: PeerIndex) -> Option<Peer> {
        let (sender, receiver) = oneshot::channel();
        match self.send(Command::GetPeer {
            peer,
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
