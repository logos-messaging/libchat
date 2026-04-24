use openmls::{framing::errors::MlsMessageError, prelude::tls_codec};
pub use thiserror::Error;

use storage::StorageError;

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
    #[error("unsupported conversation type: {0}")]
    UnsupportedConvoType(String),
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    #[error("mls error: {0}")]
    MlsMessageError(#[from] MlsMessageError),
    #[error("TlsCodec: {0}")]
    TlsCodec(#[from] tls_codec::Error),
    #[error("generic: {0}")]
    Generic(String),
    #[error("KeyPackage: {0}")]
    KeyPackage(#[from] openmls::prelude::KeyPackageVerifyError),
    #[error("Delivery: {0}")]
    Delivery(String),
}

impl ChatError {
    // This is a stopgap until there is a proper error system in place
    pub fn generic(e: impl ToString) -> Self {
        Self::Generic(e.to_string())
    }
}

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("decryption: {0}")]
    Decryption(String),
}
