//! Storage module for persisting chat state.
//!
//! This module provides storage implementations for the chat manager state,
//! built on top of the shared `storage` crate.

mod db;
mod session;
mod types;

pub use db::ChatStorage;
pub use session::{ChatSession, SessionError};
pub use storage::{SqliteDb, StorageConfig, StorageError};
pub use types::{ChatRecord, IdentityRecord, InboxKeyRecord};
