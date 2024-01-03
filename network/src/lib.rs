//! ckb network module
//!
//! This module is based on the Tentacle library, once again abstract the context that protocols can use,
//! and providing a unified implementation of the peer storage and registration mechanism.
//!
//! And implemented several basic protocols: identify, discovery, ping, feeler, disconnect_message
//!

// Just to conviniently use the derive macro NetworkBehaviour.
#[allow(unused_imports)]
#[macro_use]
extern crate libp2p as backend_libp2p;

mod behaviour;
mod command;
/// compress module
pub mod compress;
pub mod errors;
pub mod libp2p;
pub mod network;
mod network_group;
pub mod peer;
pub mod peer_registry;
pub mod peer_store;
mod services;
mod support_protocols;
pub mod tentacle;

#[cfg(test)]
mod tests;

pub use crate::peer::{Multiaddr, PeerId};
pub use crate::{
    behaviour::Behaviour,
    command::{Command, CommandSender},
    errors::Error,
    network::{
        DefaultExitHandler, ExitHandler, NetworkController, NetworkState, TentacleEventHandler,
        TentacleNetworkService,
    },
    peer::{Peer, PeerIdentifyInfo, PeerIndex},
    peer_registry::PeerRegistry,
    peer_store::Score,
    support_protocols::SupportProtocols,
    tentacle::protocols::{identify::Flags, CKBProtocol, CKBProtocolContext, CKBProtocolHandler},
};
pub use p2p::{
    async_trait,
    builder::ServiceBuilder,
    bytes,
    multiaddr::{self, MultiAddr as TentacleMultiaddr},
    secio::{PeerId as TentaclePeerId, PublicKey as TentaclePublicKey},
    service::{ServiceControl, SessionType, TargetProtocol, TargetSession},
    traits::ServiceProtocol,
    utils::{extract_peer_id, multiaddr_to_socketaddr},
    ProtocolId, SessionId, SessionId as TentacleSessionId,
};
pub use tokio;
pub use serde::{self, Deserialize, Serialize};

/// Protocol version used by network protocol open
pub type ProtocolVersion = String;

/// Observe listen port occupancy
pub async fn observe_listen_port_occupancy(
    _addrs: &[multiaddr::MultiAddr],
) -> Result<(), std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        use p2p::utils::dns::DnsResolver;
        use std::net::{SocketAddr, TcpListener};

        for raw_addr in _addrs {
            let ip_addr: Option<SocketAddr> = match DnsResolver::new(raw_addr.clone()) {
                Some(dns) => dns.await.ok().as_ref().and_then(multiaddr_to_socketaddr),
                None => multiaddr_to_socketaddr(raw_addr),
            };

            if let Some(addr) = ip_addr {
                if let Err(e) = TcpListener::bind(addr) {
                    ckb_logger::error!(
                        "addr {} can't use on your machines by error: {}, please check",
                        raw_addr,
                        e
                    );
                    return Err(e);
                }
            }
        }
    }

    Ok(())
}
