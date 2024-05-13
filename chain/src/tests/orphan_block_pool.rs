#![allow(dead_code)]
use crate::{LonelyBlock, LonelyBlockWithCallback};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_systemtime::unix_time_as_millis;
use ckb_types::core::{BlockBuilder, BlockView, EpochNumberWithFraction, HeaderView};
use ckb_types::prelude::*;
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;

use crate::utils::orphan_block_pool::OrphanBlockPool;

fn gen_lonely_block_with_callback(parent_header: &HeaderView) -> LonelyBlockWithCallback {
    let number = parent_header.number() + 1;
    let block = BlockBuilder::default()
        .parent_hash(parent_header.hash())
        .timestamp(unix_time_as_millis().pack())
        .number(number.pack())
        .epoch(EpochNumberWithFraction::new(number / 1000, number % 1000, 1000).pack())
        .nonce((parent_header.nonce() + 1).pack())
        .build();
    LonelyBlockWithCallback {
        lonely_block: LonelyBlock {
            block: Arc::new(block),
            peer_id: None,
            switch: None,
        },
        verify_callback: None,
    }
}

#[test]
fn test_remove_blocks_by_parent() {
    let consensus = ConsensusBuilder::default().build();
    let block_number = 200;
    let mut blocks = Vec::new();
    let mut parent = consensus.genesis_block().header();
    let pool = OrphanBlockPool::with_capacity(200);
    let mut total_size = 0;
    for _ in 1..block_number {
        let new_block = gen_lonely_block_with_callback(&parent);
        total_size += new_block.data().total_size();
        blocks.push(new_block.clone());
        pool.insert(new_block.clone());
        parent = new_block.header();
    }
    assert_eq!(total_size, pool.total_size());

    let orphan = pool.remove_blocks_by_parent(&consensus.genesis_block().hash());

    let mut parent_hash = consensus.genesis_block().hash();
    assert_eq!(orphan[0].block.header().parent_hash(), parent_hash);
    let mut windows = orphan.windows(2);
    // Orphans are sorted in a BFS manner. We iterate through them and check that this is the case.
    // The `parent_or_sibling` may be a sibling or child of current `parent_hash`,
    // and `child_or_sibling` may be a sibling or child of `parent_or_sibling`.
    while let Some([parent_or_sibling, child_or_sibling]) = windows.next() {
        // `parent_or_sibling` is a child of the block with current `parent_hash`.
        // Make `parent_or_sibling`'s parent the current `parent_hash`.
        if parent_or_sibling.block.header().parent_hash() != parent_hash {
            parent_hash = parent_or_sibling.block.header().parent_hash();
        }

        // If `child_or_sibling`'s parent is not the current `parent_hash`, i.e. it is not a sibling of
        // `parent_or_sibling`, then it must be a child of `parent_or_sibling`.
        if child_or_sibling.block.header().parent_hash() != parent_hash {
            // Move `parent_hash` forward.
            parent_hash = child_or_sibling.block.header().parent_hash();
            assert_eq!(child_or_sibling.block.header().parent_hash(), parent_hash);
        }
    }
    let orphan_set: HashSet<_> = orphan.into_iter().map(|b| b.block).collect();
    let blocks_set: HashSet<_> = blocks.into_iter().map(|b| b.to_owned()).collect();
    assert_eq!(orphan_set, blocks_set)
}

#[test]
fn test_remove_blocks_by_parent_and_get_block_should_not_deadlock() {
    let consensus = ConsensusBuilder::default().build();
    let pool = OrphanBlockPool::with_capacity(1024);
    let mut header = consensus.genesis_block().header();
    let mut hashes = Vec::new();
    for _ in 1..1024 {
        let new_block = gen_lonely_block_with_callback(&header);
        pool.insert(new_block.clone());
        header = new_block.header();
        hashes.push(header.hash());
    }

    let pool_arc1 = Arc::new(pool);
    let pool_arc2 = Arc::clone(&pool_arc1);

    let thread1 = thread::spawn(move || {
        pool_arc1.remove_blocks_by_parent(&consensus.genesis_block().hash());
    });

    for hash in hashes.iter().rev() {
        pool_arc2.get_block(hash);
    }

    thread1.join().unwrap();
}

#[test]
fn test_leaders() {
    let consensus = ConsensusBuilder::default().build();
    let block_number = 20;
    let mut blocks = Vec::new();
    let mut parent = consensus.genesis_block().header();
    let pool = OrphanBlockPool::with_capacity(20);
    for i in 0..block_number - 1 {
        let new_block = gen_lonely_block_with_callback(&parent);
        blocks.push(new_block.clone());
        parent = new_block.header();
        if i % 5 != 0 {
            pool.insert(new_block.clone());
        }
    }

    assert_eq!(pool.len(), 15);
    assert_eq!(pool.leaders_len(), 4);

    pool.insert(blocks[5].clone());
    assert_eq!(pool.len(), 16);
    assert_eq!(pool.leaders_len(), 3);

    pool.insert(blocks[10].clone());
    assert_eq!(pool.len(), 17);
    assert_eq!(pool.leaders_len(), 2);

    // index 0 doesn't in the orphan pool, so do nothing
    let orphan = pool.remove_blocks_by_parent(&consensus.genesis_block().hash());
    assert!(orphan.is_empty());
    assert_eq!(pool.len(), 17);
    assert_eq!(pool.leaders_len(), 2);

    pool.insert(blocks[0].clone());
    assert_eq!(pool.len(), 18);
    assert_eq!(pool.leaders_len(), 2);

    let orphan = pool.remove_blocks_by_parent(&consensus.genesis_block().hash());
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.leaders_len(), 1);

    pool.insert(blocks[15].clone());
    assert_eq!(pool.len(), 4);
    assert_eq!(pool.leaders_len(), 1);

    let orphan_1 = pool.remove_blocks_by_parent(&blocks[14].hash());

    let orphan_set: HashSet<BlockView> = orphan.into_iter().chain(orphan_1).collect();
    let blocks_set: HashSet<BlockView> = blocks.into_iter().collect();
    assert_eq!(orphan_set, blocks_set);
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.leaders_len(), 0);
}

#[test]
fn test_remove_expired_blocks() {
    let consensus = ConsensusBuilder::default().build();
    let block_number = 20;
    let mut parent = consensus.genesis_block().header();
    let pool = OrphanBlockPool::with_capacity(block_number);

    let deprecated = EpochNumberWithFraction::new(10, 0, 10);

    for _ in 1..block_number {
        let new_block = BlockBuilder::default()
            .parent_hash(parent.hash())
            .timestamp(unix_time_as_millis().pack())
            .number((parent.number() + 1).pack())
            .epoch(deprecated.clone().pack())
            .nonce((parent.nonce() + 1).pack())
            .build();

        parent = new_block.header();
        let lonely_block_with_callback = LonelyBlockWithCallback {
            lonely_block: LonelyBlock {
                block: Arc::new(new_block),
                peer_id: None,
                switch: None,
            },
            verify_callback: None,
        };
        pool.insert(lonely_block_with_callback);
    }
    assert_eq!(pool.leaders_len(), 1);

    let v = pool.clean_expired_blocks(20_u64);
    assert_eq!(v.len(), 19);
    assert_eq!(pool.leaders_len(), 0);
    assert_eq!(pool.total_size(), 0)
}
