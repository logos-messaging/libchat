use storage::StorageError;
use thiserror::Error;

use crate::errors::RatchetError;

#[derive(Debug, Error)]
pub enum SessionError {
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("ratchet error: {0}")]
    Ratchet(#[from] RatchetError),

    #[error("conversation already exists: {0}")]
    ConvAlreadyExists(String),
}
