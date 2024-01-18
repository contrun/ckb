

use crate::errors::Error;


use ckb_async_runtime::Handle;
use ckb_logger::{info};

use libp2p::swarm::{NetworkBehaviour, SwarmEvent};
use p2p::async_trait;

pub use libp2p::*;

pub use libp2p as upstream;

pub use serde::{self, Deserialize, Serialize};

use ckb_spawn::Spawn;
use tokio::{sync::mpsc};
pub use crate::Command;

pub enum Event {}

/// This trait encapsulate the libp2p protocol processing logic.
/// It will be used to handle libp2p swarm events (e.g. connection established)
/// and user commands (e.g. disconnect to one peer).
/// Typically, we react to swarm events with the function `handle_event`,
/// and process user commands with the function `handle_command`.
/// These functions can use the state encapsulated in the type `State`.
/// And they may run in a loop, which can be spawn by the function `run`.
/// Note that libp2p swarm events is an associated type of this trait (Behaviour),
/// while the user commands is an fixed type defined in this module (Command).
/// We may conclude that, given ckb's usage of libp2p, we can just define Behaviour and Command here.
/// But we will encounter a problem that `Synchronizer` (implemented in crate ckb-sync),
/// the implmentation of ckb's protocol to sync blocks, depends on this crate (ckb-network).
/// If we are going to implement sync protocol in this crate, we need to use SyncState to
/// keep the state of sync protocol, which unfortunately, is a type defined in ckb-sync.
/// Thus we have a cyclic dependency. We can move SyncState to this crate
/// (or a crate that would be both the parent of this crate and ckb-sync), but there are
/// just too many things to move. So we create this trait solve this problem.
/// A sync protocol in libp2p should create its own sync `Behaviour` which can use `SyncState`
/// from ckb-sync. This protocol only needs to implement the trait below and use the
/// NetworkController::new to spawn libp2p network service.
#[async_trait]
pub trait NetworkServiceTrait: Send + 'static {
    type Behaviour: NetworkBehaviour + Send;
    type State: Send;
    fn new(
        swarm: Swarm<Self::Behaviour>,
        network_state: Self::State,
        command_receiver: mpsc::Receiver<Command>,
    ) -> Self;
    async fn run(mut self);
    async fn handle_event(
        &mut self,
        event: SwarmEvent<<Self::Behaviour as NetworkBehaviour>::ToSwarm>,
    );
    async fn handle_command(&mut self, command: Command);
}

#[derive(Clone)]
pub struct NetworkController {
    pub(crate) handle: Handle,
    pub(crate) command_sender: mpsc::Sender<Command>,
}

impl NetworkController {
    pub fn new<NST: NetworkServiceTrait>(
        handle: &Handle,
        network_state: <NST as NetworkServiceTrait>::State,
        swarm: Swarm<<NST as NetworkServiceTrait>::Behaviour>,
        command_sender: mpsc::Sender<Command>,
        command_receiver: mpsc::Receiver<Command>,
    ) -> Result<Self, Error> {
        handle.spawn_task(async move {
            let mut swarm = swarm;
            let libp2p_port = std::env::var("LIBP2P_PORT")
                .unwrap_or_default()
                .parse::<i16>()
                .unwrap_or_default();

            let addr = format!("/ip4/0.0.0.0/tcp/{}", libp2p_port);
            // Note that although listen_on is not an async function,
            // it actually requires a runtime, so we must call it within a handle.spawn_task.
            let result = swarm.listen_on(addr.parse().expect("Correct multiaddr"));
            let _ = result.expect("libp2p listen succeed");
            info!("libp2p listen on {}/p2p/{}", addr, swarm.local_peer_id());
            let service = NST::new(swarm, network_state, command_receiver);
            service.run().await;
        });

        Ok(NetworkController {
            handle: handle.clone(),
            command_sender,
        })
    }
}
