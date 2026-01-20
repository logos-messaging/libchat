//! Error types for the storage module.

use thiserror::Error;

/// Errors that can occur during storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
    /// Database operation failed.
    #[cfg(any(feature = "sqlite", feature = "sqlcipher"))]
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    /// Field-level encryption failed.
    #[error("encryption failed: {0}")]
    Encryption(String),

    /// Field-level decryption failed.
    #[error("decryption failed: {0}")]
    Decryption(String),

    /// Stored state is corrupted or invalid.
    #[error("corrupted state: {0}")]
    CorruptedState(String),

    /// Session was not found in storage.
    #[error("session not found: {}", hex::encode(.session_id))]
    SessionNotFound {
        /// The session ID that was not found.
        session_id: [u8; 32],
    },

    /// I/O operation failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Key reconstruction failed.
    #[error("key reconstruction failed: {0}")]
    KeyReconstruction(String),
}

/// Helper module for hex encoding (used in error messages).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
