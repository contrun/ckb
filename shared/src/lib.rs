//! TODO(doc): @quake

// num_cpus is used in proc_macro
pub mod shared;
mod shared_builder;

pub use ckb_snapshot::{Snapshot, SnapshotMgr};
pub use shared::Shared;
