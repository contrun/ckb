#![allow(unused_imports)]
#![allow(dead_code)]

use crate::tests::util::{build_chain, inherit_block};
use crate::SyncShared;
use ckb_chain::{start_chain_services, RemoteBlock, VerifyResult};
use ckb_logger::info;
use ckb_shared::block_status::BlockStatus;
use ckb_shared::{Shared, SharedBuilder};
use ckb_store::{self, ChainStore};
use ckb_test_chain_utils::always_success_cellbase;
use ckb_types::core::{BlockBuilder, BlockView, Capacity};
use ckb_types::packed::Byte32;
use ckb_types::prelude::*;
use std::fmt::format;
use std::sync::Arc;

fn wait_for_expected_block_status(
    shared: &SyncShared,
    hash: &Byte32,
    expect_status: BlockStatus,
) -> bool {
    let now = std::time::Instant::now();
    while now.elapsed().as_secs() < 2 {
        let current_status = shared.shared().get_block_status(hash);
        if current_status == expect_status {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_micros(100));
    }
    false
}

#[test]
fn test_insert_new_block() {
    let (shared, chain) = build_chain(2);
    let new_block = {
        let tip_hash = shared.active_chain().tip_header().hash();
        let next_block = inherit_block(shared.shared(), &tip_hash).build();
        Arc::new(next_block)
    };

    assert!(shared
        .blocking_insert_new_block(&chain, Arc::clone(&new_block))
        .expect("insert valid block"));
    assert!(!shared
        .blocking_insert_new_block(&chain, Arc::clone(&new_block))
        .expect("insert duplicated valid block"),);
}

#[test]
fn test_insert_invalid_block() {
    let (shared, chain) = build_chain(2);
    let invalid_block = {
        let active_chain = shared.active_chain();
        let tip_number = active_chain.tip_number();
        let tip_hash = active_chain.tip_hash();
        let invalid_cellbase =
            always_success_cellbase(tip_number, Capacity::zero(), shared.consensus());
        let next_block = inherit_block(shared.shared(), &tip_hash)
            .transaction(invalid_cellbase)
            .build();
        Arc::new(next_block)
    };

    assert!(shared
        .blocking_insert_new_block(&chain, Arc::clone(&invalid_block))
        .is_err(),);
}

#[test]
fn test_insert_parent_unknown_block() {
    let (shared1, _) = build_chain(2);
    let (shared, chain) = {
        let (shared, mut pack) = SharedBuilder::with_temp_db()
            .consensus(shared1.consensus().clone())
            .build()
            .unwrap();
        let chain_controller = start_chain_services(pack.take_chain_services_builder());
        (
            SyncShared::new(shared, Default::default(), pack.take_relay_tx_receiver()),
            chain_controller,
        )
    };

    let block = shared1
        .store()
        .get_block(&shared1.active_chain().tip_header().hash())
        .unwrap();
    let parent = {
        let parent = shared1
            .store()
            .get_block(&block.header().parent_hash())
            .unwrap();
        Arc::new(parent)
    };
    let invalid_orphan = {
        let invalid_orphan = block
            .as_advanced_builder()
            .header(block.header())
            .number(1000.pack())
            .build();

        Arc::new(invalid_orphan)
    };
    let valid_orphan = Arc::new(block);
    let valid_hash = valid_orphan.header().hash();
    let invalid_hash = invalid_orphan.header().hash();
    let parent_hash = parent.header().hash();
    shared.accept_remote_block(
        &chain,
        RemoteBlock {
            block: Arc::clone(&valid_orphan),

            verify_callback: Box::new(|_: VerifyResult| {}),
        },
    );
    shared.accept_remote_block(
        &chain,
        RemoteBlock {
            block: Arc::clone(&invalid_orphan),
            verify_callback: Box::new(|_: VerifyResult| {}),
        },
    );

    let wait_for_block_status_match = |hash: &Byte32, expect_status: BlockStatus| -> bool {
        let mut status_match = false;
        let now = std::time::Instant::now();
        while now.elapsed().as_secs() < 2 {
            if shared.active_chain().get_block_status(hash) == expect_status {
                status_match = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_micros(100));
        }
        status_match
    };

    assert_eq!(
        shared.active_chain().get_block_status(&valid_hash),
        BlockStatus::BLOCK_RECEIVED
    );

    if shared.active_chain().get_block_status(&invalid_hash) == BlockStatus::BLOCK_RECEIVED {
        wait_for_block_status_match(&invalid_hash, BlockStatus::BLOCK_INVALID);
    }

    // This block won't pass non_contextual_check, and will be BLOCK_INVALID immediately
    assert_eq!(
        shared.active_chain().get_block_status(&invalid_hash),
        BlockStatus::BLOCK_INVALID
    );

    // After inserting parent of an orphan block

    assert!(shared
        .blocking_insert_new_block(&chain, Arc::clone(&parent))
        .expect("insert parent of orphan block"));

    assert!(wait_for_block_status_match(
        &valid_hash,
        BlockStatus::BLOCK_VALID
    ));
    assert!(wait_for_block_status_match(
        &invalid_hash,
        BlockStatus::BLOCK_INVALID
    ));
    assert!(wait_for_block_status_match(
        &parent_hash,
        BlockStatus::BLOCK_VALID
    ));
}

#[test]
fn test_insert_child_block_with_stored_but_unverified_parent() {
    let (shared1, _) = build_chain(2);

    let block = shared1
        .store()
        .get_block(&shared1.active_chain().tip_header().hash())
        .unwrap();
    let parent = {
        let parent = shared1
            .store()
            .get_block(&block.header().parent_hash())
            .unwrap();
        Arc::new(parent)
    };

    let _logger = ckb_logger_service::init_for_test("info,ckb-chain=debug").expect("init log");

    let parent_hash = parent.header().hash();
    let child = Arc::new(block);
    let child_hash = child.header().hash();

    let (shared, chain) = {
        let (shared, mut pack) = SharedBuilder::with_temp_db()
            .consensus(shared1.consensus().clone())
            .build()
            .unwrap();

        let db_txn = shared.store().begin_transaction();
        info!("inserting parent: {}-{}", parent.number(), parent.hash());
        db_txn.insert_block(&parent).expect("insert parent");
        db_txn.commit().expect("commit parent");

        assert!(
            shared.store().get_block(&parent_hash).is_some(),
            "parent block should be stored"
        );

        let chain_controller = start_chain_services(pack.take_chain_services_builder());

        while chain_controller.is_verifying_unverified_blocks_on_startup() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        (
            SyncShared::new(shared, Default::default(), pack.take_relay_tx_receiver()),
            chain_controller,
        )
    };

    assert!(shared
        .blocking_insert_new_block(&chain, Arc::clone(&child))
        .expect("insert child block"));

    assert!(wait_for_expected_block_status(
        &shared,
        &child_hash,
        BlockStatus::BLOCK_VALID
    ));
    assert!(wait_for_expected_block_status(
        &shared,
        &parent_hash,
        BlockStatus::BLOCK_VALID
    ));
}

#[test]
fn test_switch_valid_fork() {
    let (shared, chain) = build_chain(5);
    // Insert the valid fork. The fork blocks would not been verified until the fork switches as
    // the main chain. And `block_status_map` would mark the fork blocks as `BLOCK_STORED`
    let fork_tip = 2;
    let (fork_shared, fork_chain) = build_chain(fork_tip);
    let fork_tip_hash = fork_shared.store().get_block_hash(fork_tip).unwrap();
    let mut valid_fork = Vec::new();
    let mut parent_header = fork_shared
        .store()
        .get_block_header(&fork_tip_hash)
        .unwrap();
    for _ in 3..shared.active_chain().tip_number() {
        let block = inherit_block(fork_shared.shared(), &parent_header.hash())
            .timestamp((parent_header.timestamp() + 3).pack())
            .build();
        let arc_block = Arc::new(block.clone());
        assert!(fork_shared
            .blocking_insert_new_block(&fork_chain, Arc::clone(&arc_block))
            .expect("insert fork"),);
        assert!(shared
            .blocking_insert_new_block(&chain, arc_block)
            .expect("insert fork"),);
        parent_header = block.header().clone();
        valid_fork.push(block);
    }
    for block in valid_fork.iter() {
        assert_eq!(
            shared
                .active_chain()
                .get_block_status(&block.header().hash()),
            BlockStatus::BLOCK_STORED,
        );
    }

    let tip_number = shared.active_chain().tip_number();
    // Make the fork switch as the main chain.
    for _ in tip_number..tip_number + 2 {
        let block = inherit_block(fork_shared.shared(), &parent_header.hash())
            .timestamp((parent_header.timestamp() + 3).pack())
            .build();
        let arc_block = Arc::new(block.clone());
        assert!(fork_shared
            .blocking_insert_new_block(&fork_chain, Arc::clone(&arc_block))
            .expect("insert fork"),);
        assert!(shared
            .blocking_insert_new_block(&chain, arc_block)
            .expect("insert fork"),);
        parent_header = block.header().clone();
        valid_fork.push(block);
    }
    for block in valid_fork.iter() {
        assert_eq!(
            shared
                .active_chain()
                .get_block_status(&block.header().hash()),
            BlockStatus::BLOCK_VALID,
        );
    }
}
