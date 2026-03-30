use storage::StorageError;
use thiserror::Error;

// #[derive(Debug, thiserror::Error, Display)]
// pub struct SqliteError(pub rusqlite::Error);
//
// #[derive(Debug, thiserror::Error)]
// pub enum SqliteError {
//     #[error(transparent)]
//     Rusqlite(#[from] rusqlite::Error),

//     #[error(transparent)]
//     Storage(#[from] StorageError),
// }

#[derive(Debug, Error)]
pub enum SqliteError {
    #[error("sqlite error: {0}")]
    Rusqlite(#[from] rusqlite::Error),

    #[error(transparent)]
    Storage(#[from] StorageError),
}

// impl From<SqliteError> for StorageError {
//     fn from(err: SqliteError) -> Self {
//         match err {
//             SqliteError::Storage(e) => e,
//             SqliteError::Rusqlite(e) => StorageError::Database(e.to_string()),
//         }
//     }
// }
