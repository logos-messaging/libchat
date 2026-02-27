//! Storage record types for serialization/deserialization.

use crate::crypto::PrivateKey;
use crate::identity::Identity;

/// Record for storing identity (secret key).
#[derive(Debug)]
pub struct IdentityRecord {
    /// The identity name.
    pub name: String,
    /// The secret key bytes (32 bytes).
    pub secret_key: [u8; 32],
}

impl From<IdentityRecord> for Identity {
    fn from(record: IdentityRecord) -> Self {
        let secret = PrivateKey::from(record.secret_key);
        Identity::from_secret(record.name, secret)
    }
}
