use libchat::ChatError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Chat(#[from] ChatError),
}
