//! Storage module for persisting ratchet state.
//!
//! This module provides storage implementations for the double ratchet state,
//! built on top of the shared `storage` crate.

mod db;
mod errors;
mod session;
mod types;

pub use db::RatchetStorage;
pub use errors::SessionError;
pub use session::RatchetSession;
pub use storage::{SqliteDb, StorageConfig, StorageError};
pub use types::RatchetStateRecord;
