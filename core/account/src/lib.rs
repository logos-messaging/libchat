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
mod directory;
mod error;

use crypto::Ed25519VerifyingKey;

pub use account_log::{AccountEntry, AccountLog, EncodedAccountLog, EntryData, SignedAccountLog};
pub use addr::AccountAddr;
pub use codec::{ACCOUNT_LOG_DOMAIN, verify_extension, verify_log};
pub use error::{AccountError, AccountLogError};

pub use directory::{
    AccountDirectory, BUNDLE_VERSION, BundleError, DecodedBundle, DeviceId, DeviceSet, Lamport,
    ResolveError, SignedDeviceBundle, decode_bundle_payload, encode_bundle_payload,
    resolve_device_ids, verify_bundle,
};

#[cfg(feature = "dev")]
pub use account::{TestAccountService, TestLogosAccount};

/// What applications may ask about any account.
pub trait AccountRegistry {
    type Error: std::fmt::Display + std::fmt::Debug;

    /// Keys currently endorsed by `addr`. `Ok(None)`: account never published.
    fn associated_ed25519_keys(
        &self,
        addr: &AccountAddr,
    ) -> Result<Option<Vec<Ed25519VerifyingKey>>, Self::Error>;

    /// Is `signer` currently endorsed by `addr`? Provided — one derivation,
    /// so implementations cannot diverge on what "associated" means.
    fn is_ed25519_associated(
        &self,
        signer: &Ed25519VerifyingKey,
        addr: &AccountAddr,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .associated_ed25519_keys(addr)?
            .is_some_and(|keys| keys.contains(signer)))
    }
}
