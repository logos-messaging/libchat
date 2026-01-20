use blake2::{
    Blake2bMac,
    digest::{FixedOutput, consts::U32},
};
use crypto::{DomainSeparator, PrekeyBundle, SecretKey, X3Handshake};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::{PublicKey, StaticSecret};

type Blake2bMac256 = Blake2bMac<U32>;

pub struct InboxDomain;
impl DomainSeparator for InboxDomain {
    const BYTES: &'static [u8] = b"logos_chat_inbox";
}

type X3DH = X3Handshake<InboxDomain>;

pub struct InboxHandshake {}

impl InboxHandshake {
    /// Performs
    pub fn perform_as_initiator<R: RngCore + CryptoRng>(
        identity_keypair: &StaticSecret,
        recipient_bundle: &PrekeyBundle,
        rng: &mut R,
    ) -> (SecretKey, PublicKey) {
        // Perform X3DH handshake to get shared secret
        let (shared_secret, ephemeral_public) =
            X3DH::initator(identity_keypair, recipient_bundle, rng);

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
        identity_keypair: &StaticSecret,
        signed_prekey: &StaticSecret,
        onetime_prekey: Option<&StaticSecret>,
        initiator_identity: &PublicKey,
        initiator_ephemeral: &PublicKey,
    ) -> SecretKey {
        // Perform X3DH to get shared secret
        let shared_secret = X3DH::responder(
            identity_keypair,
            signed_prekey,
            onetime_prekey,
            initiator_identity,
            initiator_ephemeral,
        );

        Self::derive_keys_from_shared_secret(shared_secret)
    }

    /// Derive keys from X3DH shared secret
    fn derive_keys_from_shared_secret(shared_secret: SecretKey) -> SecretKey {
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
