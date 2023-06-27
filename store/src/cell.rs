use crate::{ChainStore, StoreTransaction};
use ckb_error::Error;
use ckb_types::{core::BlockView, packed, prelude::*};
use ckb_types::{
    core::{cell::CellMeta, TransactionInfo},
    packed::OutPoint,
};
use rpds::{HashTrieMap, HashTrieMapSync, Queue, QueueSync};
use std::collections::HashMap;

/**
 * Live cell entry.
 *
 *  table CellEntry {
 *      output:                CellOutput,
 *      block_hash:            Byte32,
 *      block_number:          Uint64,
 *      block_epoch:           Uint64,
 *      index:                 Uint32,
 *      data_size:             Uint64,
 *  }
 *
 *
 *  table CellDataEntry {
 *      output_data:           Bytes,
 *      output_data_hash:      Byte32,
 *  }
 */

const LIVE_CELL_CACHE_LIMIT: usize = 20000;

#[derive(Debug, Clone)]
pub struct LiveCellCache {
    cache: HashTrieMapSync<OutPoint, CellMeta>,
}

fn build_cell_meta_from_entry(out_point: OutPoint, entry: &packed::CellEntry) -> CellMeta {
    CellMeta {
        out_point,
        cell_output: entry.output(),
        transaction_info: Some(TransactionInfo {
            block_number: entry.block_number().unpack(),
            block_hash: entry.block_hash(),
            block_epoch: entry.block_epoch().unpack(),
            index: entry.index().unpack(),
        }),
        data_bytes: entry.data_size().unpack(),
        mem_cell_data: None,
        mem_cell_data_hash: None,
    }
}

impl LiveCellCache {
    pub fn new() -> LiveCellCache {
        LiveCellCache {
            cache: HashTrieMap::new_sync(),
        }
    }

    pub fn insert(&mut self, key: OutPoint, value: CellMeta) -> LiveCellCache {
        let cache = self.cache.insert(key.clone(), value);
        LiveCellCache { cache }
    }

    pub fn insert_entry(&mut self, key: OutPoint, entry: &packed::CellEntry) -> LiveCellCache {
        let cell_meta = build_cell_meta_from_entry(key.clone(), entry);
        self.insert(key, cell_meta)
    }

    pub fn remove(&mut self, key: &OutPoint) -> LiveCellCache {
        let cache = self.cache.remove(key);
        LiveCellCache { cache }
    }

    pub fn get(&self, key: &OutPoint) -> Option<&CellMeta> {
        self.cache.get(key)
    }
}

// Apply the effects of this block on the live cell set.
pub fn attach_block_cell(
    txn: &StoreTransaction,
    block: &BlockView,
    mut cache: LiveCellCache,
) -> Result<LiveCellCache, Error> {
    let transactions = block.transactions();

    // add new live cells
    let new_cells = transactions
        .iter()
        .enumerate()
        .flat_map(move |(tx_index, tx)| {
            let tx_hash = tx.hash();
            let block_hash = block.header().hash();
            let block_number = block.header().number();
            let block_epoch = block.header().epoch();

            tx.outputs_with_data_iter()
                .enumerate()
                .map(move |(index, (cell_output, data))| {
                    let out_point = packed::OutPoint::new_builder()
                        .tx_hash(tx_hash.clone())
                        .index(index.pack())
                        .build();

                    let entry = packed::CellEntryBuilder::default()
                        .output(cell_output)
                        .block_hash(block_hash.clone())
                        .block_number(block_number.pack())
                        .block_epoch(block_epoch.pack())
                        .index(tx_index.pack())
                        .data_size((data.len() as u64).pack())
                        .build();

                    let data_entry = if !data.is_empty() {
                        let data_hash = packed::CellOutput::calc_data_hash(&data);
                        Some(
                            packed::CellDataEntryBuilder::default()
                                .output_data(data.pack())
                                .output_data_hash(data_hash)
                                .build(),
                        )
                    } else {
                        None
                    };

                    (out_point, entry, data_entry)
                })
        });
    cache = txn.insert_cells(new_cells, cache)?;

    // mark inputs dead
    // skip cellbase
    let deads = transactions
        .iter()
        .skip(1)
        .flat_map(|tx| tx.input_pts_iter());
    cache = txn.delete_cells(deads, cache)?;

    Ok(cache)
}

/// Undoes the effects of this block on the live cell set.
pub fn detach_block_cell(
    txn: &StoreTransaction,
    block: &BlockView,
    mut cache: LiveCellCache,
) -> Result<LiveCellCache, Error> {
    let transactions = block.transactions();
    let mut input_pts = HashMap::with_capacity(transactions.len());

    for tx in transactions.iter().skip(1) {
        for pts in tx.input_pts_iter() {
            let tx_hash = pts.tx_hash();
            let index: usize = pts.index().unpack();
            let indexes = input_pts.entry(tx_hash).or_insert_with(Vec::new);
            indexes.push(index);
        }
    }

    // restore inputs
    // skip cellbase
    let undo_deads = input_pts
        .iter()
        .filter_map(|(tx_hash, indexes)| {
            txn.get_transaction_with_info(tx_hash)
                .map(move |(tx, info)| {
                    let block_hash = info.block_hash;
                    let block_number = info.block_number;
                    let block_epoch = info.block_epoch;
                    let tx_index = info.index;

                    indexes.iter().filter_map(move |index| {
                        tx.output_with_data(*index).map(|(cell_output, data)| {
                            let out_point = packed::OutPoint::new_builder()
                                .tx_hash(tx_hash.clone())
                                .index(index.pack())
                                .build();

                            let entry = packed::CellEntryBuilder::default()
                                .output(cell_output)
                                .block_hash(block_hash.clone())
                                .block_number(block_number.pack())
                                .block_epoch(block_epoch.pack())
                                .index(tx_index.pack())
                                .data_size((data.len() as u64).pack())
                                .build();

                            let data_entry = if !data.is_empty() {
                                let data_hash = packed::CellOutput::calc_data_hash(&data);
                                Some(
                                    packed::CellDataEntryBuilder::default()
                                        .output_data(data.pack())
                                        .output_data_hash(data_hash)
                                        .build(),
                                )
                            } else {
                                None
                            };

                            (out_point, entry, data_entry)
                        })
                    })
                })
        })
        .flatten();
    cache = txn.insert_cells(undo_deads, cache)?;

    // undo live cells
    let undo_cells = transactions.iter().flat_map(|tx| tx.output_pts_iter());
    cache = txn.delete_cells(undo_cells, cache)?;

    Ok(cache)
}
