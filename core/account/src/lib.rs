//! Account identity and the signed account log.
//!
//! An account is known by its [`AccountAddr`], an opaque routable id. The
//! account endorses device keys and data by appending to an [`AccountLog`],
//! signed whole on every update and verifiable against the account's address
//! — see that module for the design and its invariants.
//!
//! Applications read account state through [`AccountRegistry`].

#[cfg(feature = "dev")]
mod account;
mod account_log;
mod addr;
mod codec;
mod error;

use crypto::Ed25519VerifyingKey;

pub use account_log::{AccountEntry, AccountLog, EncodedAccountLog, EntryData, SignedAccountLog};
pub use addr::AccountAddr;
pub use codec::{ACCOUNT_LOG_DOMAIN, verify_extension, verify_log};
pub use error::{AccountError, AccountLogError};

#[cfg(feature = "dev")]
pub use account::{TestAccountService, TestLogosAccount};

/// What applications may ask about any account.
pub trait AccountRegistry {
    type Error: std::fmt::Display + std::fmt::Debug;

    /// Keys currently endorsed by `addr`. `Ok(None)`: account never published.
    fn endorsed_ed25519_keys(
        &self,
        addr: &AccountAddr,
    ) -> Result<Option<Vec<Ed25519VerifyingKey>>, Self::Error>;

    /// Is `signer` currently endorsed by `addr`? Provided — one derivation,
    /// so implementations cannot diverge on what "endorsed" means.
    fn is_ed25519_endorsed(
        &self,
        signer: &Ed25519VerifyingKey,
        addr: &AccountAddr,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .endorsed_ed25519_keys(addr)?
            .is_some_and(|keys| keys.contains(signer)))
    }
}

/// Where an account publishes its signed log — the write side of what
/// [`AccountRegistry`] serves to readers.
///
/// An account holds one of these and publishes through it, so the log it
/// extends and the log others read are the same log.
pub trait AccountLogStore {
    type Error: std::fmt::Display + std::fmt::Debug;

    /// Store `log` as `addr`'s log, replacing any earlier one. The store is
    /// untrusted, so it proves nothing: readers verify what they fetch.
    ///
    /// Taken by value: an account has no use for the log once published, and a
    /// store that keeps it would otherwise have to copy it.
    fn publish_log(
        &mut self,
        addr: &AccountAddr,
        log: SignedAccountLog,
    ) -> Result<(), Self::Error>;
}
