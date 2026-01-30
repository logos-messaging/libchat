//! Storage module for persisting ratchet state.
//!
//! This module provides a trait-based abstraction for storage, allowing
//! the double ratchet to be agnostic to how data is persisted.
//!
//! # Architecture
//!
//! - [`RatchetStore`] - Trait defining storage needs for double ratchet state
//! - [`RatchetSession`] - High-level wrapper with automatic persistence
//! - [`EphemeralStore`] - In-memory implementation for testing
//! - [`SqliteRatchetStore`] - SQLite/SQLCipher implementation for production

mod ephemeral;
mod errors;
mod session;
mod sqlite;
mod store;

pub use ephemeral::EphemeralStore;
pub use errors::SessionError;
pub use session::RatchetSession;
pub use sqlite::SqliteRatchetStore;
pub use store::{RatchetStateData, RatchetStore, SkippedKeyId, SkippedMessageKey, StoreError};
