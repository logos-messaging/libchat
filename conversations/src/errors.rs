pub use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChatError {
    #[error("protocol error: {0:?}")]
    Protocol(String),
}
