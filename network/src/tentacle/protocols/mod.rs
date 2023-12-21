pub(crate) mod disconnect_message;
pub(crate) mod discovery;
pub(crate) mod feeler;
pub(crate) mod identify;
pub(crate) mod ping;

#[cfg(test)]
mod tests;

use ckb_logger::{debug, trace};
use futures::Future;
use p2p::{
    async_trait,
    builder::MetaBuilder,
    bytes::Bytes,
    context::{ProtocolContext, ProtocolContextMutRef},
    service::{ProtocolHandle, ProtocolMeta, ServiceAsyncControl, ServiceControl, TargetSession},
    traits::ServiceProtocol,
    ProtocolId, SessionId,
};
use std::{pin::Pin, sync::Arc, time::Duration};
use tokio::{select, sync::mpsc};
use tokio_util::codec::length_delimited;

use crate::{Command, CommandSender, PeerIndex};

/// Boxed future task
pub type BoxedFutureTask = Pin<Box<dyn Future<Output = ()> + 'static + Send>>;

use crate::{
    compress::{compress, decompress},
    network::{tentacle_async_disconnect_with_message, tentacle_disconnect_with_message},
    Behaviour, Error, NetworkState, Peer, ProtocolVersion, SupportProtocols,
};

/// Abstract protocol context
#[async_trait]
pub trait CKBProtocolContext: Send {
    /// Get ckb2023 flag
    fn ckb2023(&self) -> bool;
    /// Set notify to tentacle
    // Interact with underlying p2p service
    async fn set_notify(&self, interval: Duration, token: u64) -> Result<(), Error>;
    /// Remove notify
    async fn remove_notify(&self, token: u64) -> Result<(), Error>;
    /// Send message through quick queue
    async fn async_quick_send_message(
        &self,
        proto_id: ProtocolId,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error>;
    /// Send message through quick queue
    async fn async_quick_send_message_to(
        &self,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error>;
    /// Filter broadcast message through quick queue
    async fn async_quick_filter_broadcast(
        &self,
        target: TargetSession,
        data: Bytes,
    ) -> Result<(), Error>;
    /// Send message
    async fn async_send_message(
        &self,
        proto_id: ProtocolId,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error>;
    /// Send message
    async fn async_send_message_to(&self, peer_index: PeerIndex, data: Bytes) -> Result<(), Error>;
    /// Filter broadcast message
    async fn async_filter_broadcast(&self, target: TargetSession, data: Bytes)
        -> Result<(), Error>;
    /// Disconnect session
    async fn async_disconnect(&self, peer_index: PeerIndex, message: &str) -> Result<(), Error>;
    /// Send message through quick queue
    fn quick_send_message(
        &self,
        proto_id: ProtocolId,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error>;
    /// Send message through quick queue
    fn quick_send_message_to(&self, peer_index: PeerIndex, data: Bytes) -> Result<(), Error>;
    /// Filter broadcast message through quick queue
    fn quick_filter_broadcast(&self, target: TargetSession, data: Bytes) -> Result<(), Error>;
    /// Send message
    fn send_message(
        &self,
        proto_id: ProtocolId,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error>;
    /// Send message
    fn send_message_to(&self, peer_index: PeerIndex, data: Bytes) -> Result<(), Error>;
    /// Filter broadcast message
    fn filter_broadcast(&self, target: TargetSession, data: Bytes) -> Result<(), Error>;
    /// Disconnect session
    fn disconnect(&self, peer_index: PeerIndex, message: &str) -> Result<(), Error>;
    // Interact with NetworkState
    /// Get peer info
    fn get_peer(&self, peer_index: PeerIndex) -> Option<Peer>;
    /// Modify peer info
    fn with_peer_mut(&self, peer_index: PeerIndex, f: Box<dyn FnOnce(&mut Peer)>);
    /// Get all session id
    fn connected_peers(&self) -> Vec<PeerIndex>;
    /// Report peer behavior
    fn report_peer(&self, peer_index: PeerIndex, behaviour: Behaviour);
    /// Ban peer
    fn ban_peer(&self, peer_index: PeerIndex, duration: Duration, reason: String);
    /// current protocol id
    fn protocol_id(&self) -> ProtocolId;
    /// Raw tentacle controller
    fn p2p_control(&self) -> Option<&ServiceControl> {
        None
    }
    async fn process_command(&self, command: Command) {
        match command {
            Command::SendMessage {
                protocol,
                peer_index,
                message,
            } => {
                let result = self.send_message(protocol.protocol_id(), peer_index, message);
                match result {
                    Err(e) => debug!("Failed to send message to peer {}: {:?}", peer_index, e),
                    Ok(_) => {}
                };
            }
            Command::Ban {
                peer_index,
                duration,
                reason,
            } => self.ban_peer(peer_index, duration, reason),
            Command::Disconnect {
                peer_index,
                message,
            } => {
                let result = self.disconnect(peer_index, &message);
                match result {
                    Err(e) => debug!("Failed to disconnect from peer {}: {:?}", peer_index, e),
                    Ok(_) => {}
                };
            }
            Command::GetPeer { peer_index, sender } => {
                let result = sender.send(self.get_peer(peer_index));
                match result {
                    Err(e) => debug!(
                        "Failed to send response of get_peer (peer: {}): {:?}",
                        peer_index, e
                    ),
                    Ok(_) => {}
                };
            }
            Command::GetConnectedPeers { sender } => {
                let result = sender.send(self.connected_peers());
                match result {
                    Err(e) => debug!("Failed to send response of get connected peers: {:?}", e),
                    Ok(_) => {}
                };
            }
            Command::Report {
                peer_index,
                behaviour,
            } => self.report_peer(peer_index, behaviour),
            Command::FilterBroadCast {
                // TODO: need to send message to the specific protocol.
                protocol,
                target,
                message,
                quick,
            } => {
                let result = if quick {
                    self.quick_filter_broadcast(target, message)
                } else {
                    self.filter_broadcast(target, message)
                };
                match result {
                    Err(e) => debug!("Failed to send broadcast: {:?}", e),
                    Ok(_) => {}
                };
            }
        }
    }
    async fn process_command_stream(&self, mut stream: mpsc::Receiver<Command>) {
        loop {
            select! {
                Some(command) = stream.recv() => self.process_command(command).await,
                else => break
            }
        }
    }
}
/// Abstract protocol handle base on tentacle service handle
#[async_trait]
pub trait CKBProtocolHandler: Sync + Send {
    /// Init action on service run
    async fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>);
    /// Called when opening protocol
    async fn connected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        _peer_index: SessionId,
        _version: &str,
    ) {
    }
    /// Called when closing protocol
    async fn disconnected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        _peer_index: SessionId,
    ) {
    }
    /// Called when the corresponding protocol message is received
    async fn received(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        _peer_index: SessionId,
        _data: Bytes,
    ) {
    }
    /// Called when the Service receives the notify task
    async fn notify(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, _token: u64) {}
    /// Behave like `Stream::poll`
    async fn poll(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>) -> Option<()> {
        None
    }
}

/// Help to build protocol meta
pub struct CKBProtocol {
    protocol: SupportProtocols,
    // for example: b"/ckb/"
    protocol_name: String,
    // supported version, used to check protocol version
    supported_versions: Vec<ProtocolVersion>,
    max_frame_length: usize,
    handler: Box<dyn CKBProtocolHandler>,
    network_state: Arc<NetworkState>,
}

impl CKBProtocol {
    /// New with support protocol
    // a helper constructor to build `CKBProtocol` with `SupportProtocols` enum
    pub fn new_with_support_protocol(
        support_protocol: SupportProtocols,
        handler: Box<dyn CKBProtocolHandler>,
        network_state: Arc<NetworkState>,
    ) -> Self {
        CKBProtocol {
            protocol: support_protocol,
            protocol_name: support_protocol.name(),
            max_frame_length: support_protocol.max_frame_length(),
            supported_versions: support_protocol.support_versions(),
            network_state,
            handler,
        }
    }

    /// New with all config
    pub fn new(
        protocol_name: String,
        id: ProtocolId,
        versions: &[ProtocolVersion],
        max_frame_length: usize,
        handler: Box<dyn CKBProtocolHandler>,
        network_state: Arc<NetworkState>,
    ) -> Self {
        CKBProtocol {
            protocol: id.into(),
            max_frame_length,
            network_state,
            handler,
            protocol_name: format!("/ckb/{protocol_name}"),
            supported_versions: {
                let mut versions: Vec<_> = versions.to_vec();
                versions.sort_by(|a, b| b.cmp(a));
                versions.to_vec()
            },
        }
    }

    /// Protocol id
    pub fn id(&self) -> ProtocolId {
        self.protocol.protocol_id()
    }

    /// Protocol name
    pub fn protocol_name(&self) -> String {
        self.protocol_name.clone()
    }

    /// Whether support this version
    pub fn match_version(&self, version: ProtocolVersion) -> bool {
        self.supported_versions.contains(&version)
    }

    /// Build to tentacle protocol meta
    pub fn build(self) -> ProtocolMeta {
        let protocol_name = self.protocol_name();
        let max_frame_length = self.max_frame_length;
        let supported_versions = self
            .supported_versions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        MetaBuilder::default()
            .id(self.id())
            .name(move |_| protocol_name.clone())
            .codec(move || {
                Box::new(
                    length_delimited::Builder::new()
                        .max_frame_length(max_frame_length)
                        .new_codec(),
                )
            })
            .support_versions(supported_versions)
            .service_handle(move || {
                ProtocolHandle::Callback(Box::new(CKBHandler {
                    proto_id: self.id(),
                    network_state: Arc::clone(&self.network_state),
                    handler: self.handler,
                }))
            })
            .before_send(compress)
            .before_receive(|| Some(Box::new(decompress)))
            .build()
    }
}

struct CKBHandler {
    proto_id: ProtocolId,
    network_state: Arc<NetworkState>,
    handler: Box<dyn CKBProtocolHandler>,
}

// Just proxy to inner handler, this struct exists for convenient unit test.
#[async_trait]
impl ServiceProtocol for CKBHandler {
    async fn init(&mut self, context: &mut ProtocolContext) {
        let nc = DefaultCKBProtocolContext {
            proto_id: self.proto_id,
            network_state: Arc::clone(&self.network_state),
            p2p_control: context.control().to_owned().into(),
            async_p2p_control: context.control().to_owned(),
        };
        self.handler.init(Arc::new(nc)).await;
    }

    async fn connected(&mut self, context: ProtocolContextMutRef<'_>, version: &str) {
        // This judgment will be removed in the first release after 2023 hardfork
        if self
            .network_state
            .ckb2023
            .load(std::sync::atomic::Ordering::SeqCst)
            && version != crate::support_protocols::LASTEST_VERSION
            && context.proto_id != SupportProtocols::RelayV2.protocol_id()
        {
            debug!(
                "session {}, protocol {} with version {}, not 3, so disconnect it",
                context.session.id, context.proto_id, version
            );
            let id = context.session.id;
            let _ignore = context.disconnect(id).await;
            return;
        }
        self.network_state.with_peer_registry_mut(|reg| {
            if let Some(peer) = reg.get_peer_mut(context.session.id) {
                peer.protocols.insert(self.proto_id, version.to_owned());
            }
        });

        if !self.network_state.is_active() {
            return;
        }

        let nc = DefaultCKBProtocolContext {
            proto_id: self.proto_id,
            network_state: Arc::clone(&self.network_state),
            p2p_control: context.control().to_owned().into(),
            async_p2p_control: context.control().to_owned(),
        };
        let peer_index = context.session.id;

        self.handler
            .connected(Arc::new(nc), peer_index, version)
            .await;
    }

    async fn disconnected(&mut self, context: ProtocolContextMutRef<'_>) {
        self.network_state.with_peer_registry_mut(|reg| {
            if let Some(peer) = reg.get_peer_mut(context.session.id) {
                peer.protocols.remove(&self.proto_id);
            }
        });

        if !self.network_state.is_active() {
            return;
        }

        let nc = DefaultCKBProtocolContext {
            proto_id: self.proto_id,
            network_state: Arc::clone(&self.network_state),
            p2p_control: context.control().to_owned().into(),
            async_p2p_control: context.control().to_owned(),
        };
        let peer_index = context.session.id;
        self.handler.disconnected(Arc::new(nc), peer_index).await;
    }

    async fn received(&mut self, context: ProtocolContextMutRef<'_>, data: Bytes) {
        if !self.network_state.is_active() {
            return;
        }

        trace!(
            "[received message]: {}, {}, length={}",
            self.proto_id,
            context.session.id,
            data.len()
        );
        let nc = DefaultCKBProtocolContext {
            proto_id: self.proto_id,
            network_state: Arc::clone(&self.network_state),
            p2p_control: context.control().to_owned().into(),
            async_p2p_control: context.control().to_owned(),
        };
        let peer_index = context.session.id;
        self.handler.received(Arc::new(nc), peer_index, data).await;
    }

    async fn notify(&mut self, context: &mut ProtocolContext, token: u64) {
        if !self.network_state.is_active() {
            return;
        }
        let nc = DefaultCKBProtocolContext {
            proto_id: self.proto_id,
            network_state: Arc::clone(&self.network_state),
            p2p_control: context.control().to_owned().into(),
            async_p2p_control: context.control().to_owned(),
        };
        self.handler.notify(Arc::new(nc), token).await;
    }

    async fn poll(&mut self, context: &mut ProtocolContext) -> Option<()> {
        let nc = DefaultCKBProtocolContext {
            proto_id: self.proto_id,
            network_state: Arc::clone(&self.network_state),
            p2p_control: context.control().to_owned().into(),
            async_p2p_control: context.control().to_owned(),
        };
        self.handler.poll(Arc::new(nc)).await
    }
}

struct DefaultCKBProtocolContext {
    proto_id: ProtocolId,
    network_state: Arc<NetworkState>,
    p2p_control: ServiceControl,
    async_p2p_control: ServiceAsyncControl,
}

#[async_trait]
impl CKBProtocolContext for DefaultCKBProtocolContext {
    fn ckb2023(&self) -> bool {
        self.network_state
            .ckb2023
            .load(std::sync::atomic::Ordering::SeqCst)
    }
    async fn set_notify(&self, interval: Duration, token: u64) -> Result<(), Error> {
        self.async_p2p_control
            .set_service_notify(self.proto_id, interval, token)
            .await?;
        Ok(())
    }
    async fn remove_notify(&self, token: u64) -> Result<(), Error> {
        self.async_p2p_control
            .remove_service_notify(self.proto_id, token)
            .await?;
        Ok(())
    }
    async fn async_quick_send_message(
        &self,
        proto_id: ProtocolId,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error> {
        trace!(
            "[send message]: {}, to={:?}, length={}",
            proto_id,
            peer_index,
            data.len()
        );
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.async_p2p_control
            .quick_send_message_to(session_id, proto_id, data)
            .await?;
        Ok(())
    }
    async fn async_quick_send_message_to(
        &self,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error> {
        trace!(
            "[send message to]: {}, to={}, length={}",
            self.proto_id,
            peer_index,
            data.len()
        );
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.async_p2p_control
            .quick_send_message_to(session_id, self.proto_id, data)
            .await?;
        Ok(())
    }
    async fn async_quick_filter_broadcast(
        &self,
        target: TargetSession,
        data: Bytes,
    ) -> Result<(), Error> {
        self.async_p2p_control
            .quick_filter_broadcast(target, self.proto_id, data)
            .await?;
        Ok(())
    }
    async fn async_send_message(
        &self,
        proto_id: ProtocolId,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error> {
        trace!(
            "[send message]: {}, to={}, length={}",
            proto_id,
            peer_index,
            data.len()
        );
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.async_p2p_control
            .send_message_to(session_id, proto_id, data)
            .await?;
        Ok(())
    }
    async fn async_send_message_to(&self, peer_index: PeerIndex, data: Bytes) -> Result<(), Error> {
        trace!(
            "[send message to]: {}, to={}, length={}",
            self.proto_id,
            peer_index,
            data.len()
        );
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.async_p2p_control
            .send_message_to(session_id, self.proto_id, data)
            .await?;
        Ok(())
    }
    async fn async_filter_broadcast(
        &self,
        target: TargetSession,
        data: Bytes,
    ) -> Result<(), Error> {
        self.async_p2p_control
            .filter_broadcast(target, self.proto_id, data)
            .await?;
        Ok(())
    }
    async fn async_disconnect(&self, peer_index: PeerIndex, message: &str) -> Result<(), Error> {
        debug!("disconnect peer: {}, message: {}", peer_index, message);
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        tentacle_async_disconnect_with_message(&self.async_p2p_control, session_id, message)
            .await?;
        Ok(())
    }
    fn quick_send_message(
        &self,
        proto_id: ProtocolId,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error> {
        trace!(
            "[send message]: {}, to={}, length={}",
            proto_id,
            peer_index,
            data.len()
        );
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.p2p_control
            .quick_send_message_to(session_id, proto_id, data)?;
        Ok(())
    }
    fn quick_send_message_to(&self, peer_index: PeerIndex, data: Bytes) -> Result<(), Error> {
        trace!(
            "[send message to]: {}, to={}, length={}",
            self.proto_id,
            peer_index,
            data.len()
        );
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.p2p_control
            .quick_send_message_to(session_id, self.proto_id, data)?;
        Ok(())
    }
    fn quick_filter_broadcast(&self, target: TargetSession, data: Bytes) -> Result<(), Error> {
        self.p2p_control
            .quick_filter_broadcast(target, self.proto_id, data)?;
        Ok(())
    }
    fn send_message(
        &self,
        proto_id: ProtocolId,
        peer_index: PeerIndex,
        data: Bytes,
    ) -> Result<(), Error> {
        trace!(
            "[send message]: {}, to={}, length={}",
            proto_id,
            peer_index,
            data.len()
        );
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.p2p_control
            .send_message_to(session_id, proto_id, data)?;
        Ok(())
    }
    fn send_message_to(&self, peer_index: PeerIndex, data: Bytes) -> Result<(), Error> {
        trace!(
            "[send message to]: {}, to={}, length={}",
            self.proto_id,
            peer_index,
            data.len()
        );
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.p2p_control
            .send_message_to(session_id, self.proto_id, data)?;
        Ok(())
    }
    fn filter_broadcast(&self, target: TargetSession, data: Bytes) -> Result<(), Error> {
        self.p2p_control
            .filter_broadcast(target, self.proto_id, data)?;
        Ok(())
    }
    fn disconnect(&self, peer_index: PeerIndex, message: &str) -> Result<(), Error> {
        debug!("disconnect peer: {}, message: {}", peer_index, message);
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        tentacle_disconnect_with_message(&self.p2p_control, session_id, message)?;
        Ok(())
    }

    fn get_peer(&self, peer_index: PeerIndex) -> Option<Peer> {
        self.network_state
            .with_peer_registry(|reg| reg.get_peer(peer_index).cloned())
    }
    fn with_peer_mut(&self, peer_index: PeerIndex, f: Box<dyn FnOnce(&mut Peer)>) {
        self.network_state.with_peer_registry_mut(|reg| {
            reg.get_peer_mut(peer_index).map(f);
        })
    }

    fn connected_peers(&self) -> Vec<PeerIndex> {
        self.network_state.with_peer_registry(|reg| {
            reg.peers()
                .iter()
                .filter_map(|(peer_index, peer)| {
                    if peer.protocols.contains_key(&self.proto_id) {
                        Some(*peer_index)
                    } else {
                        None
                    }
                })
                .collect()
        })
    }
    fn report_peer(&self, peer_index: PeerIndex, behaviour: Behaviour) {
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.network_state
            .report_session(&self.p2p_control, session_id, behaviour);
    }
    fn ban_peer(&self, peer_index: PeerIndex, duration: Duration, reason: String) {
        let session_id = match peer_index {
            PeerIndex::Tentacle(s) => s,
        };
        self.network_state
            .ban_session(&self.p2p_control, session_id, duration, reason);
    }

    fn protocol_id(&self) -> ProtocolId {
        self.proto_id
    }

    fn p2p_control(&self) -> Option<&ServiceControl> {
        Some(&self.p2p_control)
    }
}
