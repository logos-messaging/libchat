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

/// Failures decoding, verifying, or replaying an account log. Variants are
/// the distinctions callers act on; everything else is message detail.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AccountLogError {
    /// The bytes or entries are not a valid log. Detail is diagnostic only —
    /// every malformed log is handled the same way: rejected.
    #[error("malformed log: {0}")]
    Malformed(String),
    #[error("unsupported log version {0}")]
    Version(String),
    #[error("account signature verification failed")]
    SignatureInvalid,
    #[error("stale: log does not extend the stored one")]
    Stale,
    #[error("fork: log rewrites history instead of extending it")]
    Forked,
}
