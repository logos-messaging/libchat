use blake2::{
    Blake2bMac,
    digest::{FixedOutput, consts::U32},
};
use crypto::{PrekeyBundle, X3Handshake};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::{PublicKey, StaticSecret};

type Blake2bMac256 = Blake2bMac<U32>;

/// Represents an encrypted session initialized with X3DH
pub struct InboxHandshake {
    seed_key: [u8; 32],
    _symmetric_encryption_key: [u8; 32],
}

impl InboxHandshake {
    /// Initialize as the initiator (sender) using X3DH
    ///
    /// # Arguments
    /// * `identity_keypair` - Your long-term identity key pair
    /// * `recipient_bundle` - Recipient's prekey bundle
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// A tuple of (InboxEncryption, ephemeral_public_key) to send to recipient
    pub fn init_as_initiator<R: RngCore + CryptoRng>(
        identity_keypair: &StaticSecret,
        recipient_bundle: &PrekeyBundle,
        rng: &mut R,
    ) -> (Self, PublicKey) {
        // Perform X3DH to get shared secret
        let (shared_secret, ephemeral_public) =
            X3Handshake::initator(identity_keypair, recipient_bundle, rng);

        let session = Self::new(shared_secret);

        (session, ephemeral_public)
    }

    /// Initialize as the responder (receiver) using X3DH
    ///
    /// # Arguments
    /// * `identity_keypair` - Your long-term identity key pair
    /// * `signed_prekey` - Your signed prekey (private)
    /// * `onetime_prekey` - Your one-time prekey (private, if used)
    /// * `initiator_identity` - Initiator's identity public key
    /// * `initiator_ephemeral` - Initiator's ephemeral public key
    pub fn init_as_responder(
        identity_keypair: &StaticSecret,
        signed_prekey: &StaticSecret,
        onetime_prekey: Option<&StaticSecret>,
        initiator_identity: &PublicKey,
        initiator_ephemeral: &PublicKey,
    ) -> Self {
        // Perform X3DH to get shared secret
        let shared_secret = X3Handshake::responder(
            identity_keypair,
            signed_prekey,
            onetime_prekey,
            initiator_identity,
            initiator_ephemeral,
        );

        Self::new(shared_secret)
    }

    fn new(shared_secret: [u8; 32]) -> Self {
        // Derive necessary keys
        let (seed_key, symmetric_encryption_key) =
            Self::derive_keys_from_shared_secret(&shared_secret);

        Self {
            seed_key,
            _symmetric_encryption_key: symmetric_encryption_key,
        }
    }

    /// Derive root key and encryption keys from X3DH shared secret
    fn derive_keys_from_shared_secret(shared_secret: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
        let seed_key = Blake2bMac256::new_with_salt_and_personal(
            shared_secret,
            &[], // No salt - input already has high entropy
            b"InboxV1-Seed",
        )
        .unwrap()
        .finalize_fixed()
        .into();

        let encryption_key = Blake2bMac256::new_with_salt_and_personal(
            shared_secret,
            &[], // No salt - input already has high entropy
            b"InboxV1-Encrypt",
        )
        .unwrap()
        .finalize_fixed()
        .into();

        (seed_key, encryption_key)
    }

    pub fn get_seed_key(&self) -> [u8; 32] {
        self.seed_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_inbox_encryption_initialization() {
        let mut rng = OsRng;

        // Alice (initiator) generates her identity key
        let alice_identity = StaticSecret::random_from_rng(&mut rng);
        let alice_identity_pub = PublicKey::from(&alice_identity);

        // Bob (responder) generates his keys
        let bob_identity = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey_pub = PublicKey::from(&bob_signed_prekey);

        // Create Bob's prekey bundle
        let bob_bundle = PrekeyBundle {
            identity_key: PublicKey::from(&bob_identity),
            signed_prekey: bob_signed_prekey_pub,
            signature: [0u8; 64],
            onetime_prekey: None,
        };

        // Alice initializes session
        let (alice_session, alice_ephemeral_pub) =
            InboxHandshake::init_as_initiator(&alice_identity, &bob_bundle, &mut rng);

        // Bob initializes session
        let bob_session = InboxHandshake::init_as_responder(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity_pub,
            &alice_ephemeral_pub,
        );

        // Both should derive the same root key
        assert_eq!(alice_session.get_seed_key(), bob_session.get_seed_key());
    }
}
