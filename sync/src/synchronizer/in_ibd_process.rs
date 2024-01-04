use crate::synchronizer::Synchronizer;
use crate::Status;
use ckb_logger::info;
use ckb_network::{Command, CommandSender, PeerIndex};

pub struct InIBDProcess<'a> {
    synchronizer: &'a Synchronizer,
    peer: PeerIndex,
    command_sender: CommandSender,
}

impl<'a> InIBDProcess<'a> {
    pub fn new(
        synchronizer: &'a Synchronizer,
        peer: PeerIndex,
        command_sender: CommandSender,
    ) -> Self {
        InIBDProcess {
            command_sender,
            synchronizer,
            peer,
        }
    }

    pub fn execute(self) -> Status {
        info!("getheader with ibd peer {:?}", self.peer);
        if let Some(mut kv_pair) = self.synchronizer.peers().state.get_mut(&self.peer) {
            let state = kv_pair.value_mut();

            // The node itself needs to ensure the validity of the outbound connection.
            //
            // If outbound is an ibd node(non-whitelist), it should be disconnected automatically.
            // If inbound is an ibd node, just mark the node does not pass header sync authentication.
            if state.peer_flags.is_outbound {
                if state.peer_flags.is_whitelist {
                    self.synchronizer.shared().state().suspend_sync(state);
                } else {
                    self.command_sender.send(Command::Disconnect {
                        peer: self.peer,
                        message: "outbound in ibd".to_string(),
                    })
                }
            } else {
                self.synchronizer.shared().state().suspend_sync(state);
            }
        }
        Status::ok()
    }
}
