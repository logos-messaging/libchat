//! Storage module for persisting ratchet state.
//!
//! This module provides session management for the double ratchet state,
//! built on top of the `RatchetStore` trait from the `storage` crate.

mod errors;
mod session;
mod types;

pub use errors::SessionError;
pub use session::RatchetSession;
pub use storage::{RatchetStateRecord, RatchetStore, SkippedKeyRecord, StorageError};
pub use types::{restore_ratchet_state, to_ratchet_record, to_skipped_key_records};
