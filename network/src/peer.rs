use crate::network_group::Group;
use crate::{
    multiaddr::Multiaddr as TentacleMultiaddr, tentacle::protocols::identify::Flags, ProtocolId,
    ProtocolVersion, SessionType,
};
use ipnetwork::IpNetwork;
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr as Libp2pMultiaddr, PeerId as Libp2pPeerId};
use p2p::service::TargetSession;
use p2p::utils::{extract_peer_id, multiaddr_to_socketaddr};
use p2p::{secio::PeerId as TentaclePeerId, SessionId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// Peer info from identify protocol message
#[derive(Clone, Debug)]
pub struct PeerIdentifyInfo {
    /// Node version
    pub client_version: String,
    /// Node flags
    pub flags: Flags,
}

#[derive(Copy, Clone, PartialOrd, PartialEq, Eq, Hash, Debug)]
pub enum PeerType {
    Tentacle,
    Libp2p,
}

#[derive(Clone, PartialOrd, PartialEq, Eq, Hash, Debug)]
pub enum PeerId {
    Tentacle(TentaclePeerId),
    Libp2p(Libp2pPeerId),
}

impl From<&PeerId> for TentaclePeerId {
    fn from(value: &PeerId) -> Self {
        match value {
            PeerId::Tentacle(t) => t.clone(),
            _ => panic!("Unexpected address format, expecting tentacle address"),
        }
    }
}

impl From<&PeerId> for Libp2pPeerId {
    fn from(value: &PeerId) -> Self {
        match value {
            PeerId::Libp2p(l) => *l,
            _ => panic!("Unexpected address format, expecting tentacle address"),
        }
    }
}

impl From<&TentaclePeerId> for PeerId {
    fn from(value: &TentaclePeerId) -> Self {
        PeerId::Tentacle(value.clone())
    }
}

impl From<&Libp2pPeerId> for PeerId {
    fn from(value: &Libp2pPeerId) -> Self {
        PeerId::Libp2p(*value)
    }
}

impl From<PeerId> for TentaclePeerId {
    fn from(value: PeerId) -> Self {
        match value {
            PeerId::Tentacle(t) => t,
            _ => panic!("Unexpected address format, expecting tentacle address"),
        }
    }
}

impl From<PeerId> for Libp2pPeerId {
    fn from(value: PeerId) -> Self {
        match value {
            PeerId::Libp2p(l) => l,
            _ => panic!("Unexpected address format, expecting tentacle address"),
        }
    }
}

impl From<TentaclePeerId> for PeerId {
    fn from(value: TentaclePeerId) -> Self {
        PeerId::Tentacle(value)
    }
}

impl From<Libp2pPeerId> for PeerId {
    fn from(value: Libp2pPeerId) -> Self {
        PeerId::Libp2p(value)
    }
}

#[derive(PartialEq, Eq, Clone, Hash, Debug, Serialize, Deserialize)]
pub enum Multiaddr {
    Tentacle(TentacleMultiaddr),
    Libp2p(Libp2pMultiaddr),
}

impl TryFrom<&Multiaddr> for SocketAddr {
    type Error = String;
    fn try_from(value: &Multiaddr) -> Result<Self, Self::Error> {
        match value {
            Multiaddr::Tentacle(t) => {
                multiaddr_to_socketaddr(t).ok_or(format!("Unexpected addr: {}", t))
            }
            Multiaddr::Libp2p(l) => {
                let mut iter = l.iter();
                let ip_addr = iter.next().and_then(|p| match p {
                    Protocol::Ip4(a) => Some(a.into()),
                    Protocol::Ip6(a) => Some(a.into()),
                    _ => None,
                });
                let port = iter.next().and_then(|p| match p {
                    Protocol::Udp(port) => Some(port),
                    Protocol::Tcp(port) => Some(port),
                    _ => None,
                });
                ip_addr
                    .zip(port)
                    .map(|(ip, port)| SocketAddr::new(ip, port))
            }
            .ok_or(format!("Unexpected addr {}", l)),
        }
    }
}

impl TryFrom<&Multiaddr> for IpAddr {
    type Error = String;
    fn try_from(value: &Multiaddr) -> Result<Self, Self::Error> {
        SocketAddr::try_from(value).map(|addr| addr.ip())
    }
}

impl TryFrom<&Multiaddr> for IpNetwork {
    type Error = String;
    fn try_from(value: &Multiaddr) -> Result<Self, Self::Error> {
        Ok(match SocketAddr::try_from(value)?.ip() {
            IpAddr::V4(v4) => IpNetwork::V4(v4.into()),
            IpAddr::V6(v6) => IpNetwork::V6(v6.into()),
        })
    }
}

impl From<&Multiaddr> for TentacleMultiaddr {
    fn from(value: &Multiaddr) -> Self {
        match value {
            Multiaddr::Tentacle(t) => t.clone(),
            _ => panic!("Unexpected address format, expecting tentacle address"),
        }
    }
}

impl From<&Multiaddr> for Libp2pMultiaddr {
    fn from(value: &Multiaddr) -> Self {
        match value {
            Multiaddr::Libp2p(l) => l.clone(),
            _ => panic!("Unexpected address format, expecting tentacle address"),
        }
    }
}

impl From<&TentacleMultiaddr> for Multiaddr {
    fn from(value: &TentacleMultiaddr) -> Self {
        Multiaddr::Tentacle(value.clone())
    }
}

impl From<&Libp2pMultiaddr> for Multiaddr {
    fn from(value: &Libp2pMultiaddr) -> Self {
        Multiaddr::Libp2p(value.clone())
    }
}

impl From<Multiaddr> for TentacleMultiaddr {
    fn from(value: Multiaddr) -> Self {
        match value {
            Multiaddr::Tentacle(t) => t,
            _ => panic!("Unexpected address format, expecting tentacle address"),
        }
    }
}

impl From<Multiaddr> for Libp2pMultiaddr {
    fn from(value: Multiaddr) -> Self {
        match value {
            Multiaddr::Libp2p(l) => l,
            _ => panic!("Unexpected address format, expecting tentacle address"),
        }
    }
}

impl From<TentacleMultiaddr> for Multiaddr {
    fn from(value: TentacleMultiaddr) -> Self {
        Multiaddr::Tentacle(value)
    }
}

impl From<Libp2pMultiaddr> for Multiaddr {
    fn from(value: Libp2pMultiaddr) -> Self {
        Multiaddr::Libp2p(value)
    }
}

impl TryFrom<Multiaddr> for PeerId {
    type Error = String;
    fn try_from(value: Multiaddr) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Multiaddr> for PeerId {
    type Error = String;
    fn try_from(value: &Multiaddr) -> Result<Self, Self::Error> {
        match value {
            Multiaddr::Tentacle(t) => match extract_peer_id(t) {
                Some(peer_id) => Ok(PeerId::Tentacle(peer_id)),
                _ => Err("Failed to extract tentacle peer id".to_string()),
            },
            Multiaddr::Libp2p(l) => match l.iter().last() {
                Some(Protocol::P2p(peer_id)) => Ok(PeerId::Libp2p(peer_id)),
                _ => Err("Failed to extract libp2p peer id".to_string()),
            },
        }
    }
}

impl TryFrom<Multiaddr> for Libp2pPeerId {
    type Error = String;
    fn try_from(value: Multiaddr) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Multiaddr> for Libp2pPeerId {
    type Error = String;
    fn try_from(value: &Multiaddr) -> Result<Self, Self::Error> {
        let peer: PeerId = value.try_into()?;
        match peer {
            PeerId::Libp2p(p) => Ok(p),
            PeerId::Tentacle(_) => {
                Err("Unexpected peer id format, expecting libp2p peer id".to_string())
            }
        }
    }
}

impl TryFrom<Multiaddr> for TentaclePeerId {
    type Error = String;
    fn try_from(value: Multiaddr) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Multiaddr> for TentaclePeerId {
    type Error = String;
    fn try_from(value: &Multiaddr) -> Result<Self, Self::Error> {
        let peer: PeerId = value.try_into()?;
        match peer {
            PeerId::Tentacle(p) => Ok(p),
            PeerId::Libp2p(_) => {
                Err("Unexpected peer id format, expecting tentacle peer id".to_string())
            }
        }
    }
}

/// Peer info
#[derive(Clone, Debug)]
pub struct Peer {
    /// Peer address
    pub connected_addr: Multiaddr,
    /// Peer listen addresses
    pub listened_addrs: Vec<Multiaddr>,
    /// Peer info from identify protocol message
    pub identify_info: Option<PeerIdentifyInfo>,
    /// Ping/Pong message last received time
    pub last_ping_protocol_message_received_at: Option<Instant>,
    /// ping pong rtt
    pub ping_rtt: Option<Duration>,
    /// Indicates whether it is a probe connection of the fleer protocol
    pub is_feeler: bool,
    /// Peer connected time
    pub connected_time: Instant,
    /// Session id
    pub index: PeerIndex,
    /// Session type, Inbound or Outbound
    pub session_type: ConnectionType,
    /// Opened protocols on this session
    pub protocols: HashMap<ProtocolId, ProtocolVersion>,
    /// Whether a whitelist
    pub is_whitelist: bool,
    /// Whether the remote peer is a light client, and it subscribes the chain state.
    pub if_lightclient_subscribed: bool,
}

impl Peer {
    /// Init session info
    pub fn new(
        index: impl Into<PeerIndex>,
        session_type: impl Into<ConnectionType>,
        connected_addr: impl Into<Multiaddr>,
        is_whitelist: bool,
    ) -> Self {
        let connected_addr = connected_addr.into();
        Peer {
            connected_addr,
            listened_addrs: Vec::new(),
            identify_info: None,
            ping_rtt: None,
            last_ping_protocol_message_received_at: None,
            connected_time: Instant::now(),
            is_feeler: false,
            index: index.into(),
            session_type: session_type.into(),
            protocols: HashMap::with_capacity_and_hasher(1, Default::default()),
            is_whitelist,
            if_lightclient_subscribed: false,
        }
    }

    /// Whether outbound session
    pub fn is_outbound(&self) -> bool {
        self.session_type.is_outbound()
    }

    /// Whether inbound session
    pub fn is_inbound(&self) -> bool {
        self.session_type.is_inbound()
    }

    /// Get net group
    pub fn network_group(&self) -> Group {
        (&self.connected_addr).into()
    }

    /// Opened protocol version
    pub fn protocol_version(&self, protocol_id: ProtocolId) -> Option<ProtocolVersion> {
        self.protocols.get(&protocol_id).cloned()
    }
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum PeerIndex {
    Tentacle(SessionId),
    Libp2p(Libp2pPeerId),
}

impl std::fmt::Display for PeerIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Tentacle(s) => write!(f, "tentacle session id {}", s.value()),
            Self::Libp2p(p) => write!(f, "libp2p peer id {}", p),
        }
    }
}

impl From<SessionId> for PeerIndex {
    fn from(s: SessionId) -> Self {
        Self::Tentacle(s)
    }
}

impl From<&SessionId> for PeerIndex {
    fn from(s: &SessionId) -> Self {
        Self::Tentacle(*s)
    }
}

impl From<Libp2pPeerId> for PeerIndex {
    fn from(s: Libp2pPeerId) -> Self {
        Self::Libp2p(s)
    }
}

impl From<&Libp2pPeerId> for PeerIndex {
    fn from(s: &Libp2pPeerId) -> Self {
        Self::Libp2p(*s)
    }
}

#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq)]
pub enum ConnectionType {
    /// Connection type unknown (may occur when backend (e.g. libp2p) does not report connection type)
    Unknown,
    /// Connection to peer is initiatated by us.
    Outbound,
    /// Connection to peer is outbound
    Inbound,
}

impl From<SessionType> for ConnectionType {
    fn from(value: SessionType) -> Self {
        match value {
            SessionType::Inbound => ConnectionType::Inbound,
            SessionType::Outbound => ConnectionType::Outbound,
        }
    }
}

impl ConnectionType {
    pub fn is_outbound(&self) -> bool {
        match self {
            ConnectionType::Outbound => true,
            _ => false,
        }
    }

    pub fn is_inbound(&self) -> bool {
        match self {
            ConnectionType::Inbound => true,
            _ => false,
        }
    }
}

pub enum BroadcastTarget {
    Tentacle(TargetSession),
}

impl std::fmt::Debug for BroadcastTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            &BroadcastTarget::Tentacle(t) => match t {
                TargetSession::All => write!(f, "tentacle target all"),
                TargetSession::Filter(_) => write!(f, "tentacle target filter"),
                TargetSession::Multi(_) => write!(f, "tentacle target multi"),
                TargetSession::Single(s) => write!(f, "tentacle target single ({})", s),
            },
        }
    }
}

impl From<TargetSession> for BroadcastTarget {
    fn from(t: TargetSession) -> Self {
        Self::Tentacle(t)
    }
}

impl TryFrom<BroadcastTarget> for TargetSession {
    type Error = String;
    fn try_from(t: BroadcastTarget) -> Result<Self, Self::Error> {
        match t {
            BroadcastTarget::Tentacle(t) => Ok(t),
        }
    }
}
