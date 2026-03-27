//! Storage record types for serialization/deserialization.

use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::crypto::PrivateKey;
use crate::identity::Identity;

/// Record for storing identity (secret key).
/// Implements ZeroizeOnDrop to securely clear secret key from memory.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct IdentityRecord {
    /// The identity name.
    pub name: String,
    /// The secret key bytes (32 bytes).
    pub secret_key: [u8; 32],
}

impl From<IdentityRecord> for Identity {
    fn from(record: IdentityRecord) -> Self {
        let secret = PrivateKey::from(record.secret_key);
        Identity::from_secret(record.name.clone(), secret)
    }
}

#[derive(Debug)]
pub struct ConversationRecord {
    pub local_convo_id: String,
    pub remote_convo_id: String,
    pub convo_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_record_zeroize() {
        let secret_key = [0xAB_u8; 32];
        let mut record = IdentityRecord {
            name: "test".to_string(),
            secret_key,
        };

        // Get a pointer to the secret key before zeroizing
        let ptr = record.secret_key.as_ptr();

        // Manually zeroize (simulates what ZeroizeOnDrop does)
        record.zeroize();

        // Verify the memory is zeroed
        // SAFETY: ptr still points to valid memory within record
        unsafe {
            let slice = std::slice::from_raw_parts(ptr, 32);
            assert!(slice.iter().all(|&b| b == 0), "secret_key should be zeroed");
        }

        // Also verify via the struct field
        assert!(
            record.secret_key.iter().all(|&b| b == 0),
            "secret_key field should be zeroed"
        );
        assert!(record.name.is_empty(), "name should be cleared");
    }
}
