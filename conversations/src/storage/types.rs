//! Storage record types for serialization/deserialization.
//!
//! Note: Ratchet state types (RatchetStateRecord, SkippedKeyRecord) are in
//! double_ratchets::storage module and handled by RatchetStorage.

use x25519_dalek::{PublicKey, StaticSecret};

use crate::identity::Identity;

/// Record for storing identity (secret key).
#[derive(Debug)]
pub struct IdentityRecord {
    /// The secret key bytes (32 bytes).
    pub secret_key: [u8; 32],
}

impl From<&Identity> for IdentityRecord {
    fn from(identity: &Identity) -> Self {
        Self {
            secret_key: identity.secret().to_bytes(),
        }
    }
}

impl From<IdentityRecord> for Identity {
    fn from(record: IdentityRecord) -> Self {
        let secret = StaticSecret::from(record.secret_key);
        Identity::from_secret(secret)
    }
}

/// Record for storing chat metadata.
/// Note: The actual double ratchet state is stored separately by RatchetStorage.
#[derive(Debug, Clone)]
pub struct ChatRecord {
    /// Unique chat identifier.
    pub chat_id: String,
    /// Type of chat (e.g., "private_v1", "group_v1").
    pub chat_type: String,
    /// Remote party's public key (for private chats).
    pub remote_public_key: Option<[u8; 32]>,
    /// Remote party's delivery address.
    pub remote_address: String,
    /// Creation timestamp (unix millis).
    pub created_at: i64,
}

impl ChatRecord {
    pub fn new_private(
        chat_id: String,
        remote_public_key: PublicKey,
        remote_address: String,
    ) -> Self {
        Self {
            chat_id,
            chat_type: "private_v1".to_string(),
            remote_public_key: Some(remote_public_key.to_bytes()),
            remote_address,
            created_at: crate::utils::timestamp_millis() as i64,
        }
    }
}
