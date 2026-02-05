//! Storage module for persisting chat state.
//!
//! This module provides storage implementations for the chat manager state,
//! built on top of the shared `storage` crate.
//!
//! Note: This module is internal. Users should use `ChatManager` which
//! handles all storage operations automatically.

mod db;
mod types;

pub(crate) use db::ChatStorage;
pub(crate) use storage::StorageError;
pub(crate) use types::ChatRecord;
