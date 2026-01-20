//! Serializable types for ratchet state storage.

use std::collections::HashMap;

use double_ratchets::state::RatchetState;
use double_ratchets::hkdf::HkdfInfo;
use double_ratchets::InstallationKeyPair;
use serde::{Deserialize, Serialize};
use x25519_dalek::PublicKey;

use crate::error::StorageError;

/// A skipped message key entry for storage.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SkippedKey {
    /// The public key associated with this skipped message.
    pub public_key: [u8; 32],
    /// The message number.
    pub msg_num: u32,
    /// The 32-byte message key.
    pub message_key: [u8; 32],
}

/// Serializable version of `RatchetState`.
///
/// This struct stores all keys as raw byte arrays for easy serialization
/// and database storage. Use `from_ratchet_state()` and `to_ratchet_state()`
/// for conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorableRatchetState {
    /// The current root key (32 bytes).
    pub root_key: [u8; 32],

    /// The current sending chain key, if any (32 bytes).
    pub sending_chain: Option<[u8; 32]>,

    /// The current receiving chain key, if any (32 bytes).
    pub receiving_chain: Option<[u8; 32]>,

    /// Our DH secret key (32 bytes).
    ///
    /// **Security**: This should be encrypted before storage.
    pub dh_self_secret: [u8; 32],

    /// Our DH public key (32 bytes).
    pub dh_self_public: [u8; 32],

    /// Remote party's DH public key, if known (32 bytes).
    pub dh_remote: Option<[u8; 32]>,

    /// Number of messages sent in the current sending chain.
    pub msg_send: u32,

    /// Number of messages received in the current receiving chain.
    pub msg_recv: u32,

    /// Length of the previous sending chain.
    pub prev_chain_len: u32,

    /// Skipped message keys for out-of-order message handling.
    pub skipped_keys: Vec<SkippedKey>,

    /// Domain identifier for HKDF info.
    pub domain_id: String,
}

impl StorableRatchetState {
    /// Convert a `RatchetState` into a `StorableRatchetState`.
    ///
    /// # Type Parameters
    ///
    /// * `D` - The HKDF domain type implementing `HkdfInfo`.
    ///
    /// # Arguments
    ///
    /// * `state` - The ratchet state to convert.
    /// * `domain_id` - A string identifier for the domain (used to reconstruct the correct domain type).
    pub fn from_ratchet_state<D: HkdfInfo>(state: &RatchetState<D>, domain_id: &str) -> Self {
        let skipped_keys: Vec<SkippedKey> = state
            .skipped_keys
            .iter()
            .map(|((pub_key, msg_num), msg_key)| SkippedKey {
                public_key: *pub_key.as_bytes(),
                msg_num: *msg_num,
                message_key: *msg_key,
            })
            .collect();

        StorableRatchetState {
            root_key: state.root_key,
            sending_chain: state.sending_chain,
            receiving_chain: state.receiving_chain,
            dh_self_secret: state.dh_self.secret_bytes(),
            dh_self_public: *state.dh_self.public().as_bytes(),
            dh_remote: state.dh_remote.map(|pk| *pk.as_bytes()),
            msg_send: state.msg_send,
            msg_recv: state.msg_recv,
            prev_chain_len: state.prev_chain_len,
            skipped_keys,
            domain_id: domain_id.to_string(),
        }
    }

    /// Convert this `StorableRatchetState` back into a `RatchetState`.
    ///
    /// # Type Parameters
    ///
    /// * `D` - The HKDF domain type implementing `HkdfInfo`.
    ///
    /// # Returns
    ///
    /// * `Ok(RatchetState)` on success.
    /// * `Err(StorageError)` if key reconstruction fails.
    pub fn to_ratchet_state<D: HkdfInfo>(&self) -> Result<RatchetState<D>, StorageError> {
        // Reconstruct the keypair
        let dh_self = InstallationKeyPair::from_bytes(self.dh_self_secret, self.dh_self_public)
            .map_err(|e| StorageError::KeyReconstruction(e.to_string()))?;

        // Reconstruct skipped keys HashMap
        let skipped_keys: HashMap<(PublicKey, u32), [u8; 32]> = self
            .skipped_keys
            .iter()
            .map(|sk| {
                let pub_key = PublicKey::from(sk.public_key);
                ((pub_key, sk.msg_num), sk.message_key)
            })
            .collect();

        Ok(RatchetState::from_parts(
            self.root_key,
            self.sending_chain,
            self.receiving_chain,
            dh_self,
            self.dh_remote.map(PublicKey::from),
            self.msg_send,
            self.msg_recv,
            self.prev_chain_len,
            skipped_keys,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use double_ratchets::hkdf::DefaultDomain;

    #[test]
    fn test_roundtrip_sender_state() {
        // Create a sender state
        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let state: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, *bob_keypair.public());

        // Convert to storable and back
        let storable = StorableRatchetState::from_ratchet_state(&state, "default");
        let restored: RatchetState<DefaultDomain> = storable.to_ratchet_state().unwrap();

        // Verify fields match
        assert_eq!(state.root_key, restored.root_key);
        assert_eq!(state.sending_chain, restored.sending_chain);
        assert_eq!(state.receiving_chain, restored.receiving_chain);
        assert_eq!(state.dh_self.public().as_bytes(), restored.dh_self.public().as_bytes());
        assert_eq!(state.dh_remote.map(|pk| *pk.as_bytes()), restored.dh_remote.map(|pk| *pk.as_bytes()));
        assert_eq!(state.msg_send, restored.msg_send);
        assert_eq!(state.msg_recv, restored.msg_recv);
        assert_eq!(state.prev_chain_len, restored.prev_chain_len);
    }

    #[test]
    fn test_roundtrip_receiver_state() {
        // Create a receiver state
        let keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let state: RatchetState<DefaultDomain> =
            RatchetState::init_receiver(shared_secret, keypair);

        // Convert to storable and back
        let storable = StorableRatchetState::from_ratchet_state(&state, "default");
        let restored: RatchetState<DefaultDomain> = storable.to_ratchet_state().unwrap();

        // Verify fields match
        assert_eq!(state.root_key, restored.root_key);
        assert_eq!(state.dh_self.public().as_bytes(), restored.dh_self.public().as_bytes());
        assert!(restored.dh_remote.is_none());
    }

    #[test]
    fn test_roundtrip_with_skipped_keys() {
        // Create states and exchange messages to generate skipped keys
        let bob_keypair = InstallationKeyPair::generate();
        let shared_secret = [0x42u8; 32];
        let mut alice: RatchetState<DefaultDomain> =
            RatchetState::init_sender(shared_secret, *bob_keypair.public());
        let mut bob: RatchetState<DefaultDomain> =
            RatchetState::init_receiver(shared_secret, bob_keypair);

        // Alice sends multiple messages
        let mut messages = vec![];
        for i in 0..3 {
            let (ct, header) = alice.encrypt_message(&format!("Message {}", i).into_bytes());
            messages.push((ct, header));
        }

        // Bob receives them out of order to create skipped keys
        bob.decrypt_message(&messages[0].0, messages[0].1.clone()).unwrap();
        bob.decrypt_message(&messages[2].0, messages[2].1.clone()).unwrap();
        // Message 1 key is now in skipped_keys

        assert!(!bob.skipped_keys.is_empty());

        // Convert to storable and back
        let storable = StorableRatchetState::from_ratchet_state(&bob, "default");
        let restored: RatchetState<DefaultDomain> = storable.to_ratchet_state().unwrap();

        // Verify skipped keys are preserved
        assert_eq!(bob.skipped_keys.len(), restored.skipped_keys.len());

        // The restored state should be able to decrypt the skipped message
        let mut restored = restored;
        let pt = restored.decrypt_message(&messages[1].0, messages[1].1.clone()).unwrap();
        assert_eq!(pt, b"Message 1");
    }
}
