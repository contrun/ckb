use crate::NetworkState;

use crate::SupportProtocols;

use libp2p::{identify, ping, swarm::NetworkBehaviour, Swarm};

use std::sync::Arc;

#[derive(NetworkBehaviour)]
struct MyBehaviour {
    identify: identify::Behaviour,
    ping: ping::Behaviour,
}

#[derive(Clone)]
pub struct NetworkController {
    // swarm: Swarm<MyBehaviour>,
    network_state: Arc<NetworkState>,
}

impl NetworkController {
    pub fn new(
        _network_identification: String,
        _client_version: String,
        _network_state: Arc<NetworkState>,
        _supported_protocols: Vec<SupportProtocols>,
        _required_protocol_ids: Vec<SupportProtocols>,
    ) -> Self {
        todo!();
    }
}
