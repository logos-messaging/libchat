pub use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChatError {
    #[error("protocol error: {0:?}")]
    Protocol(String),
    #[error("protocol error: Got {0:?} expected {1:?}")]
    ProtocolExpectation(&'static str, String),
    #[error("Failed to decode payload: {0}")]
    DecodeError(#[from] prost::DecodeError),
    #[error("incorrect bundle value: {0:?}")]
    UnexpectedPayload(String),
    #[error("unexpected payload contents: {0}")]
    BadBundleValue(String),
    #[error("handshake initiated with a unknown ephemeral key")]
    UnknownEphemeralKey(),
    #[error("expected a different key length")]
    InvalidKeyLength,
    #[error("bytes provided to {0} failed")]
    BadParsing(&'static str),
    #[error("convo with id: {0} was not found")]
    NoConvo(String),
}

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("decryption: {0}")]
    Decryption(String),
}
