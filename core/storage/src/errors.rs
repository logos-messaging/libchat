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

    /// Invalid data error.
    #[error("invalid data: {0}")]
    InvalidData(String),
}
