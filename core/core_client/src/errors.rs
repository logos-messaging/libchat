use de_mls::{app::UserError, mls_crypto::MlsError};
use openmls::prelude::tls_codec;
pub use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChatError {
    #[error("generic: {0}")]
    Generic(String),
    #[error("TlsCodec: {0}")]
    TlsCodec(#[from] tls_codec::Error),
    #[error("Protobuf decode: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("delivery: {0}")]
    Delivery(String),
    #[error("Demls: {0}")]
    DemlsWrapped(#[from] MlsError),
    #[error("Demls generic: {0}")]
    DeMlsGeneric(#[from] UserError),
}

impl ChatError {
    // This is a stopgap until there is a proper error system in place
    pub fn generic(e: impl ToString) -> Self {
        Self::Generic(e.to_string())
    }
}
