use thiserror::Error;

/// Errors produced by the Double Ratchet protocol
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RatchetError {
    #[error("ciphertext too short")]
    CiphertextTooShort,

    #[error("invalid nonce")]
    InvalidNonce,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("message replay detected")]
    MessageReplay,

    #[error("too many skipped messages")]
    TooManySkippedMessages,

    #[error("missing remote DH key")]
    MissingRemoteDhKey,

    #[error("missing receiving chain")]
    MissingReceivingChain,
}
