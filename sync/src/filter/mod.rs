mod get_block_filter_check_points_process;
mod get_block_filter_hashes_process;
mod get_block_filters_process;

use crate::{types::SyncShared, Status};
use ckb_network::{Command, CommandSender};
use get_block_filter_check_points_process::GetBlockFilterCheckPointsProcess;
use get_block_filter_hashes_process::GetBlockFilterHashesProcess;
use get_block_filters_process::GetBlockFiltersProcess;

use crate::utils::{metric_ckb_message_bytes, MetricDirection};
use ckb_constant::sync::BAD_MESSAGE_BAN_TIME;
use ckb_logger::{debug_target, error_target, info_target, warn_target};
use ckb_network::{
    async_trait, bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex, SupportProtocols,
    TentacleSessionId,
};
use ckb_types::{packed, prelude::*};
use std::sync::Arc;
use std::time::Instant;

/// Filter protocol handle
#[derive(Clone)]
pub struct BlockFilter {
    /// Sync shared state
    shared: Arc<SyncShared>,
}

impl BlockFilter {
    /// Create a new block filter protocol handler
    pub fn new(shared: Arc<SyncShared>) -> Self {
        Self { shared }
    }

    fn try_process(
        &mut self,
        command_sender: CommandSender,
        peer: PeerIndex,
        message: packed::BlockFilterMessageUnionReader<'_>,
    ) -> Status {
        match message {
            packed::BlockFilterMessageUnionReader::GetBlockFilters(msg) => {
                GetBlockFiltersProcess::new(msg, self, command_sender, peer).execute()
            }
            packed::BlockFilterMessageUnionReader::GetBlockFilterHashes(msg) => {
                GetBlockFilterHashesProcess::new(msg, self, command_sender, peer).execute()
            }
            packed::BlockFilterMessageUnionReader::GetBlockFilterCheckPoints(msg) => {
                GetBlockFilterCheckPointsProcess::new(msg, self, command_sender, peer).execute()
            }
            packed::BlockFilterMessageUnionReader::BlockFilters(_)
            | packed::BlockFilterMessageUnionReader::BlockFilterHashes(_)
            | packed::BlockFilterMessageUnionReader::BlockFilterCheckPoints(_) => {
                // remote peer should not send block filter to us without asking
                // TODO: ban remote peer
                warn_target!(
                    crate::LOG_TARGET_FILTER,
                    "Received unexpected message from peer: {:?}",
                    peer
                );
                Status::ignored()
            }
        }
    }

    fn process(
        &mut self,
        command_sender: CommandSender,
        peer: PeerIndex,
        message: packed::BlockFilterMessageUnionReader<'_>,
    ) {
        let item_name = message.item_name();
        let item_bytes = message.as_slice().len() as u64;
        let status = self.try_process(command_sender.clone(), peer, message);

        metric_ckb_message_bytes(
            MetricDirection::In,
            &SupportProtocols::Filter.name(),
            message.item_name(),
            Some(status.code()),
            item_bytes,
        );

        if let Some(ban_time) = status.should_ban() {
            error_target!(
                crate::LOG_TARGET_RELAY,
                "receive {} from {}, ban {:?} for {}",
                item_name,
                peer,
                ban_time,
                status
            );
            command_sender.send(Command::Ban {
                peer,
                duration: ban_time,
                reason: status.to_string(),
            });
        } else if status.should_warn() {
            warn_target!(
                crate::LOG_TARGET_RELAY,
                "receive {} from {}, {}",
                item_name,
                peer,
                status
            );
        } else if !status.is_ok() {
            debug_target!(
                crate::LOG_TARGET_RELAY,
                "receive {} from {}, {}",
                item_name,
                peer,
                status
            );
        }
    }
}

#[async_trait]
impl CKBProtocolHandler for BlockFilter {
    async fn init(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>) {}

    async fn received(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        session_id: TentacleSessionId,
        data: Bytes,
    ) {
        let peer_index = session_id.into();
        let msg = match packed::BlockFilterMessageReader::from_compatible_slice(&data) {
            Ok(msg) => msg.to_enum(),
            _ => {
                info_target!(
                    crate::LOG_TARGET_FILTER,
                    "Peer {} sends us a malformed message",
                    peer_index
                );
                nc.ban_peer(
                    peer_index,
                    BAD_MESSAGE_BAN_TIME,
                    String::from("send us a malformed message"),
                );
                return;
            }
        };

        debug_target!(
            crate::LOG_TARGET_FILTER,
            "received msg {} from {}",
            msg.item_name(),
            peer_index
        );
        let start_time = Instant::now();
        let (command_sender, command_receiver) = CommandSender::new_from_nc(nc.clone());
        tokio::task::block_in_place(move || {
            tokio::task::block_in_place(move || self.process(command_sender, peer_index, msg));
        });
        let _ = nc.process_command_stream(command_receiver).await;
        debug_target!(
            crate::LOG_TARGET_FILTER,
            "process message={}, peer={}, cost={:?}",
            msg.item_name(),
            peer_index,
            Instant::now().saturating_duration_since(start_time),
        );
    }

    async fn connected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: TentacleSessionId,
        _version: &str,
    ) {
        info_target!(
            crate::LOG_TARGET_FILTER,
            "FilterProtocol.connected peer={}",
            peer_index
        );
    }

    async fn disconnected(
        &mut self,
        _nc: Arc<dyn CKBProtocolContext + Sync>,
        peer_index: TentacleSessionId,
    ) {
        info_target!(
            crate::LOG_TARGET_FILTER,
            "FilterProtocol.disconnected peer={}",
            peer_index
        );
    }
}
