pub use thiserror::Error;

#[derive(Error, Debug)]
pub enum AccountError {
    #[error("Generic: {0}")]
    Generic(String),
    #[error("No account entry for id: {0} ")]
    MissingEntry(String),
    #[error("invalid account address")]
    InvalidAddress,
    #[error(transparent)]
    Log(#[from] AccountLogError),
}

/// Failures decoding, verifying, or replaying an account log.
#[derive(Debug, Error)]
pub enum AccountLogError {
    #[error("payload shorter than its declared layout")]
    Short,
    #[error("payload is missing the account-log domain prefix")]
    Domain,
    #[error("unsupported log version {0}")]
    Version(String),
    #[error("unknown entry tag {0}")]
    Tag(u8),
    #[error("payload has bytes past its declared entries")]
    Trailing,
    #[error("text entry is not valid UTF-8")]
    Utf8,
    #[error("account signature verification failed")]
    SignatureInvalid,
    #[error("remove at position {position} does not point at an earlier live add ({index})")]
    InvalidRemove { position: usize, index: u32 },
    #[error("new log does not have more entries than the old ({new} <= {old})")]
    NotLonger { old: u32, new: u32 },
    #[error("new log rewrites history instead of extending it (fork)")]
    Forked,
}
