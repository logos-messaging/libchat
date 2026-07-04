#[cfg(feature = "dev")]
mod account;
mod addr;
mod codec;
mod directory;
mod error;
mod account_log;

use crypto::Ed25519VerifyingKey;
pub use directory::{
    AccountDirectory, BUNDLE_VERSION, BundleError, DecodedBundle, DeviceId, DeviceSet, Lamport,
    ResolveError, SignedDeviceBundle, decode_bundle_payload, encode_bundle_payload,
    resolve_device_ids, verify_bundle,
};
pub use codec::{ACCOUNT_LOG_DOMAIN, verify_extension, verify_log};
pub use error::{AccountError, AccountLogError};
pub use account_log::{AccountEntry, AccountLog, EncodedAccountLog, EntryData, SignedAccountLog};
pub use addr::AccountAddr;

#[cfg(feature = "dev")]
pub use account::TestLogosAccount;

