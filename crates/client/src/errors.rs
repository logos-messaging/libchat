use libchat::ChatError;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error(transparent)]
    Chat(#[from] ChatError),
    #[error("received credential could not be parsed")]
    BadlyFormedCredential,
    #[error("failed to start the transport: {0}")]
    Transport(String),
}
