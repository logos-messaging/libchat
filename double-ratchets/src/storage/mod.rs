//! Storage module for persisting ratchet state.
//!
//! This module provides storage implementations for the double ratchet state,
//! built on top of the shared `storage` crate.

mod ratchet_storage;
mod session;
mod types;

pub use ratchet_storage::RatchetStorage;
pub use session::{RatchetSession, SessionError};
pub use storage::{SqliteDb, StorageConfig, StorageError};
pub use types::RatchetStateRecord;
