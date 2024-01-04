use crate::peer::BroadcastTarget;
use crate::CKBProtocolContext;
use crate::Multiaddr;
use crate::{Behaviour, Peer, PeerIndex, SupportProtocols};
use ckb_async_runtime::Handle;
use ckb_logger::debug;
use p2p::bytes::Bytes;
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
        peer: PeerIndex,
        message: Bytes,
    },
    FilterBroadCast {
        protocol: SupportProtocols,
        target: BroadcastTarget,
        message: Bytes,
        quick: bool,
    },
}

#[derive(Clone, Default, Debug)]
pub struct CommandSenderContext {
    protocol: Option<SupportProtocols>,
    ckb2023: Option<bool>,
    handle: Option<Handle>,
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
                    handle: None,
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
    pub fn with_handle(mut self, handle: Handle) -> Self {
        self.context.handle = Some(handle);
        self
    }

    pub fn send(&self, command: Command) {
        let sender = self.channel.as_ref().unwrap();
        match self.context.handle.as_ref() {
            Some(handle) => {
                let sender = sender.clone();
                handle.spawn(async move {
                    let result = sender.send(command).await;
                    if let Err(err) = result {
                        debug!("Failed to send command: {:?}", err);
                    };
                });
            }
            None => {
                let result = sender.blocking_send(command);
                if let Err(err) = result {
                    debug!("Failed to send command: {:?}", err);
                };
        }
        };
    }

    pub fn blocking_send(&self, command: Command) -> Result<(), mpsc::error::SendError<Command>> {
        self.channel.as_ref().unwrap().blocking_send(command)
    }

    pub fn protocol(&self) -> SupportProtocols {
        self.context.protocol.unwrap()
    }

    pub fn ckb2023(&self) -> bool {
        self.context.ckb2023.unwrap()
    }

    pub fn get_peer(&self, peer: PeerIndex) -> Option<Peer> {
        let (sender, receiver) = oneshot::channel();
        self.send(Command::GetPeer { peer, sender });
        receiver.blocking_recv().ok().flatten()
    }

    pub fn get_connected_peers(&self) -> Vec<PeerIndex> {
        let (sender, receiver) = oneshot::channel();
        self.send(Command::GetConnectedPeers { sender });
        receiver.blocking_recv().ok().unwrap_or_default()
    }
}
