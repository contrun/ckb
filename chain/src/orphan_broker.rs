#![allow(missing_docs)]

use crate::utils::orphan_block_pool::{OrphanBlockPool, ParentHash};
use crate::{LonelyBlockHash, VerifyResult};
use ckb_channel::Sender;
use ckb_error::InternalErrorKind;
use ckb_logger::internal::trace;
use ckb_logger::{debug, error, info};
use ckb_shared::block_status::BlockStatus;
use ckb_shared::Shared;
use ckb_store::ChainStore;
use ckb_types::{core::BlockView, packed::Byte32, U256};
use dashmap::DashSet;
use std::sync::Arc;

pub(crate) struct OrphanBroker {
    shared: Shared,

    orphan_blocks_broker: Arc<OrphanBlockPool>,
    is_pending_verify: Arc<DashSet<Byte32>>,
    preload_unverified_tx: Sender<LonelyBlockHash>,
}

impl OrphanBroker {
    pub(crate) fn new(
        shared: Shared,
        orphan_block_pool: Arc<OrphanBlockPool>,
        preload_unverified_tx: Sender<LonelyBlockHash>,
        is_pending_verify: Arc<DashSet<Byte32>>,
    ) -> OrphanBroker {
        OrphanBroker {
            shared: shared.clone(),
            orphan_blocks_broker: orphan_block_pool,
            is_pending_verify,
            preload_unverified_tx,
        }
    }

    fn search_orphan_leader(&self, leader_hash: ParentHash) {
        let leader_status = self
            .shared
            .get_block_status(self.shared.store(), &leader_hash);

        if leader_status.eq(&BlockStatus::BLOCK_INVALID) {
            let descendants: Vec<LonelyBlockHash> = self
                .orphan_blocks_broker
                .remove_blocks_by_parent(&leader_hash);
            for descendant in descendants {
                self.process_invalid_block(descendant);
            }
            return;
        }

        let leader_is_pending_verify = self.is_pending_verify.contains(&leader_hash);
        if !leader_is_pending_verify && !leader_status.contains(BlockStatus::BLOCK_STORED) {
            trace!(
                "orphan leader: {} not stored {:?} and not in is_pending_verify: {}",
                leader_hash,
                leader_status,
                leader_is_pending_verify
            );
            return;
        }

        let descendants: Vec<LonelyBlockHash> = self
            .orphan_blocks_broker
            .remove_blocks_by_parent(&leader_hash);
        if descendants.is_empty() {
            error!(
                "leader {} does not have any descendants, this shouldn't happen",
                leader_hash
            );
            return;
        }
        self.accept_descendants(descendants);
    }

    fn search_orphan_leaders(&self) {
        for leader_hash in self.orphan_blocks_broker.clone_leaders() {
            self.search_orphan_leader(leader_hash);
        }
    }

    fn delete_invalid_block(&self, lonely_block: &LonelyBlockHash) {
        let block_hash = lonely_block.block_number_and_hash.hash();
        let block_number = lonely_block.block_number_and_hash.number();
        let parent_hash = lonely_block.parent_hash();

        info!(
            "parent: {} is INVALID, deleting this block {}-{}",
            parent_hash, block_number, block_hash,
        );

        let db_txn = self.shared.store().begin_transaction();
        let invalid_block_op: Option<BlockView> = db_txn.get_block(&block_hash);
        match invalid_block_op {
            Some(invalid_block) => {
                if let Err(err) = db_txn.delete_block(&invalid_block) {
                    error!(
                        "delete invalid block {}-{} failed {:?}",
                        block_number, block_hash, err
                    );
                    return;
                }
                if let Err(err) = db_txn.commit() {
                    error!(
                        "commit delete invalid block {}-{} failed {:?}",
                        block_number, block_hash, err
                    );
                    return;
                }

                info!(
                    "parent: {} is INVALID, deleted this block {}-{}",
                    parent_hash, block_number, block_hash,
                );
            }
            None => {
                error!(
                    "want to delete block {}-{}, but it not found in db",
                    block_number, block_hash
                );
                return;
            }
        }
    }

    fn process_invalid_block(&self, lonely_block: LonelyBlockHash) {
        let block_hash = lonely_block.block_number_and_hash.hash();
        let block_number = lonely_block.block_number_and_hash.number();
        let parent_hash = lonely_block.parent_hash();

        self.delete_invalid_block(&lonely_block);

        let err: VerifyResult = Err(InternalErrorKind::Other
            .other(format!(
                "parent {} is invalid, so block {}-{} is invalid too",
                parent_hash, block_number, block_hash
            ))
            .into());
        lonely_block.execute_callback(err);
    }

    pub(crate) fn process_lonely_block(&self, lonely_block: LonelyBlockHash) {
        let block_hash = lonely_block.block_number_and_hash.hash();
        let block_number = lonely_block.block_number_and_hash.number();
        let parent_hash = lonely_block.parent_hash();
        let parent_is_pending_verify = self.is_pending_verify.contains(&parent_hash);
        let parent_status = self
            .shared
            .get_block_status(self.shared.store(), &parent_hash);
        if parent_is_pending_verify || parent_status.contains(BlockStatus::BLOCK_STORED) {
            debug!(
                "parent {} has stored: {:?} or is_pending_verify: {}, processing descendant directly {}-{}",
                parent_hash,
                parent_status,
                parent_is_pending_verify,
                block_number,
                block_hash,
            );
            self.process_descendant(lonely_block);
        } else if parent_status.eq(&BlockStatus::BLOCK_INVALID) {
            self.process_invalid_block(lonely_block);
        } else {
            self.orphan_blocks_broker.insert(lonely_block);
        }

        self.search_orphan_leaders();

        ckb_metrics::handle().map(|handle| {
            handle
                .ckb_chain_orphan_count
                .set(self.orphan_blocks_broker.len() as i64)
        });
    }

    fn send_unverified_block(&self, lonely_block: LonelyBlockHash) {
        let block_number = lonely_block.block_number_and_hash.number();
        let block_hash = lonely_block.block_number_and_hash.hash();

        if let Some(metrics) = ckb_metrics::handle() {
            metrics
                .ckb_chain_preload_unverified_block_ch_len
                .set(self.preload_unverified_tx.len() as i64)
        }

        match self.preload_unverified_tx.send(lonely_block) {
            Ok(_) => {
                debug!(
                    "process desendant block success {}-{}",
                    block_number, block_hash
                );
            }
            Err(_) => {
                info!("send unverified_block_tx failed, the receiver has been closed");
                return;
            }
        };
        if block_number > self.shared.snapshot().tip_number() {
            self.shared.set_unverified_tip(ckb_shared::HeaderIndex::new(
                block_number,
                block_hash.clone(),
                U256::from(0u64),
            ));

            if let Some(handle) = ckb_metrics::handle() {
                handle.ckb_chain_unverified_tip.set(block_number as i64);
            }
            debug!(
                "set unverified_tip to {}-{}, while unverified_tip - verified_tip = {}",
                block_number.clone(),
                block_hash.clone(),
                block_number.saturating_sub(self.shared.snapshot().tip_number())
            )
        }
    }

    pub(crate) fn process_descendant(&self, lonely_block: LonelyBlockHash) {
        self.is_pending_verify
            .insert(lonely_block.block_number_and_hash.hash());

        self.send_unverified_block(lonely_block)
    }

    fn accept_descendants(&self, descendants: Vec<LonelyBlockHash>) {
        for descendant_block in descendants {
            self.process_descendant(descendant_block);
        }
    }
}
