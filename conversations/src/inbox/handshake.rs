use blake2::{
    Blake2bMac,
    digest::{FixedOutput, consts::U32},
};
use crypto::{DomainSeparator, PrekeyBundle, SymmetricKey32, X3Handshake};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::{X25519PrivateKey, X25519PublicKey};

type Blake2bMac256 = Blake2bMac<U32>;

pub struct InboxDomain;
impl DomainSeparator for InboxDomain {
    const BYTES: &'static [u8] = b"logos_chat_inbox";
}

type InboxKeyExchange = X3Handshake<InboxDomain>;

pub struct InboxHandshake {}

impl InboxHandshake {
    /// Performs
    pub fn perform_as_initiator<R: RngCore + CryptoRng>(
        identity_keypair: &X25519PrivateKey,
        recipient_bundle: &PrekeyBundle,
        rng: &mut R,
    ) -> (SymmetricKey32, X25519PublicKey) {
        // Perform X3DH handshake to get shared secret
        let (shared_secret, ephemeral_public) =
            InboxKeyExchange::initator(identity_keypair, recipient_bundle, rng);

        let seed_key = Self::derive_keys_from_shared_secret(shared_secret);
        (seed_key, ephemeral_public)
    }

    /// Perform the Inbox Handshake after receiving a keyBundle
    ///
    /// # Arguments
    /// * `identity_keypair` - Your long-term identity key pair
    /// * `signed_prekey` - Your signed prekey (private)
    /// * `onetime_prekey` - Your one-time prekey (private, if used)
    /// * `initiator_identity` - Initiator's identity public key
    /// * `initiator_ephemeral` - Initiator's ephemeral public key
    pub fn perform_as_responder(
        identity_keypair: &X25519PrivateKey,
        signed_prekey: &X25519PrivateKey,
        onetime_prekey: Option<&X25519PrivateKey>,
        initiator_identity: &X25519PublicKey,
        initiator_ephemeral: &X25519PublicKey,
    ) -> SymmetricKey32 {
        // Perform X3DH to get shared secret
        let shared_secret = InboxKeyExchange::responder(
            identity_keypair,
            signed_prekey,
            onetime_prekey,
            initiator_identity,
            initiator_ephemeral,
        );

        Self::derive_keys_from_shared_secret(shared_secret)
    }

    /// Derive keys from X3DH shared secret
    fn derive_keys_from_shared_secret(shared_secret: SymmetricKey32) -> SymmetricKey32 {
        let seed_key: [u8; 32] = Blake2bMac256::new_with_salt_and_personal(
            shared_secret.as_bytes(),
            &[], // No salt - input already has high entropy
            b"InboxV1-Seed",
        )
        .unwrap()
        .finalize_fixed()
        .into(); // digest uses an incompatible version of GenericArray. use array as intermediary

        seed_key.into()
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
        let alice_identity = X25519PrivateKey::random_from_rng(rng);
        let alice_identity_pub = X25519PublicKey::from(&alice_identity);

        // Bob (responder) generates his keys
        let bob_identity = X25519PrivateKey::random_from_rng(rng);
        let bob_signed_prekey = X25519PrivateKey::random_from_rng(rng);
        let bob_signed_prekey_pub = X25519PublicKey::from(&bob_signed_prekey);

        // Create Bob's prekey bundle
        let bob_bundle = PrekeyBundle {
            identity_key: X25519PublicKey::from(&bob_identity),
            signed_prekey: bob_signed_prekey_pub,
            signature: crypto::Ed25519Signature([0u8; 64]),
            onetime_prekey: None,
        };

        // Alice performs handshake
        let (alice_secret, alice_ephemeral_pub) =
            InboxHandshake::perform_as_initiator(&alice_identity, &bob_bundle, &mut rng);

        // Bob performs handshake
        let bob_secret = InboxHandshake::perform_as_responder(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity_pub,
            &alice_ephemeral_pub,
        );

        // Both should derive the same root key
        assert_eq!(alice_secret, bob_secret);
    }
}
