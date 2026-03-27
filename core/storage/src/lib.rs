//! Shared storage layer for libchat.
//!
//! This crate provides a common storage abstraction that can be used by
//! multiple crates in the libchat workspace (double-ratchets, conversations, etc.).
//!
//! Uses SQLCipher for encrypted SQLite storage.

mod errors;
mod sqlite;
mod store;

pub use errors::StorageError;
pub use sqlite::{SqliteDb, StorageConfig};
pub use store::{
    ChatStore, ConversationKind, ConversationMeta, ConversationStore, EphemeralKeyStore,
    IdentityStore,
};

// Re-export rusqlite types that domain crates will need
pub use rusqlite::{Connection, Error as RusqliteError, Transaction, params};
