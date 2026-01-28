use thiserror::Error;

/// Common storage errors.
#[derive(Debug, Error)]
pub enum StorageError {
    /// Database error (wraps rusqlite::Error when sqlite feature is enabled).
    #[error("database error: {0}")]
    Database(String),

    /// Record not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Deserialization error.
    #[error("deserialization error: {0}")]
    Deserialization(String),

    /// Schema migration error.
    #[error("migration error: {0}")]
    Migration(String),

    /// Transaction error.
    #[error("transaction error: {0}")]
    Transaction(String),
}

impl From<rusqlite::Error> for StorageError {
    fn from(e: rusqlite::Error) -> Self {
        StorageError::Database(e.to_string())
    }
}
