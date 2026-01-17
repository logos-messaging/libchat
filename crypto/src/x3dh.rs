use std::marker::PhantomData;

use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

/// A prekey bundle containing the public keys needed to initiate an X3DH key exchange.
#[derive(Clone, Debug)]
pub struct PrekeyBundle {
    pub identity_key: PublicKey,
    pub signed_prekey: PublicKey,
    pub signature: [u8; 64],
    pub onetime_prekey: Option<PublicKey>,
}

pub trait DomainSeparator {
    const BYTES: &'static [u8];
}

pub struct X3Handshake<D: DomainSeparator> {
    _phantom: PhantomData<D>,
}

impl<D: DomainSeparator> X3Handshake<D> {
    fn domain_separator() -> &'static [u8] {
        D::BYTES
    }

    /// Derive the shared secret from DH outputs using HKDF-SHA256
    fn derive_shared_secret(
        dh1: &SharedSecret,
        dh2: &SharedSecret,
        dh3: &SharedSecret,
        dh4: Option<&SharedSecret>,
    ) -> [u8; 32] {
        // Concatenate all DH outputs
        let mut km = Vec::new();
        km.extend_from_slice(dh1.as_bytes());
        km.extend_from_slice(dh2.as_bytes());
        km.extend_from_slice(dh3.as_bytes());
        if let Some(dh4) = dh4 {
            km.extend_from_slice(dh4.as_bytes());
        }

        // Use HKDF to derive the shared secret
        // Using "X3DH" as the info parameter as per Signal protocol
        let hk = Hkdf::<Sha256>::new(None, &km);
        let mut output = [0u8; 32];
        hk.expand(Self::domain_separator(), &mut output)
            .expect("32 bytes is valid HKDF output length");

        output
    }

    /// Perform X3DH key agreement as the initiator
    ///
    /// # Arguments
    /// * `identity_keypair` - Initiator's long-term identity key pair
    /// * `recipient_bundle` - Recipient's prekey bundle
    /// * `rng` - Cryptographically secure random number generator
    ///
    /// # Returns
    /// A tuple of (shared secret bytes, ephemeral public key)
    pub fn initator<R: RngCore + CryptoRng>(
        identity_keypair: &StaticSecret,
        recipient_bundle: &PrekeyBundle,
        rng: &mut R,
    ) -> ([u8; 32], PublicKey) {
        // Generate ephemeral key for this session (using StaticSecret for multiple DH operations)
        let ephemeral_secret = StaticSecret::random_from_rng(rng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);

        // Perform the 4 Diffie-Hellman operations
        let dh1 = identity_keypair.diffie_hellman(&recipient_bundle.signed_prekey);
        let dh2 = ephemeral_secret.diffie_hellman(&recipient_bundle.identity_key);
        let dh3 = ephemeral_secret.diffie_hellman(&recipient_bundle.signed_prekey);
        let dh4 = recipient_bundle
            .onetime_prekey
            .as_ref()
            .map(|opk| ephemeral_secret.diffie_hellman(opk));

        // Combine all DH outputs into shared secret
        let shared_secret = Self::derive_shared_secret(&dh1, &dh2, &dh3, dh4.as_ref());

        (shared_secret, ephemeral_public)
    }

    /// Perform X3DH key agreement as the responder
    ///
    /// # Arguments
    /// * `identity_keypair` - Responder's long-term identity key pair
    /// * `signed_prekey` - Responder's signed prekey (private)
    /// * `onetime_prekey` - Responder's one-time prekey (private, if used)
    /// * `initiator_identity` - Initiator's identity public key
    /// * `initiator_ephemeral` - Initiator's ephemeral public key
    ///
    /// # Returns
    /// The derived shared secret bytes
    pub fn responder(
        identity_keypair: &StaticSecret,
        signed_prekey: &StaticSecret,
        onetime_prekey: Option<&StaticSecret>,
        initiator_identity: &PublicKey,
        initiator_ephemeral: &PublicKey,
    ) -> [u8; 32] {
        let dh1 = signed_prekey.diffie_hellman(initiator_identity);
        let dh2 = identity_keypair.diffie_hellman(initiator_ephemeral);
        let dh3 = signed_prekey.diffie_hellman(initiator_ephemeral);
        let dh4 = onetime_prekey.map(|opk| opk.diffie_hellman(initiator_ephemeral));

        // Combine all DH outputs into shared secret
        Self::derive_shared_secret(&dh1, &dh2, &dh3, dh4.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    pub struct TestProtocol;
    impl DomainSeparator for TestProtocol {
        const BYTES: &'static [u8] = b"x3dh_tests_v1";
    }

    type X3DH = X3Handshake<TestProtocol>;

    #[test]
    fn test_x3dh_with_onetime_key() {
        let mut rng = OsRng;

        // Alice (initiator) generates her identity key
        let alice_identity = StaticSecret::random_from_rng(&mut rng);
        let alice_identity_pub = PublicKey::from(&alice_identity);

        // Bob (responder) generates his keys
        let bob_identity = StaticSecret::random_from_rng(&mut rng);
        let bob_identity_pub = PublicKey::from(&bob_identity);

        let bob_signed_prekey = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey_pub = PublicKey::from(&bob_signed_prekey);

        let bob_onetime_prekey = StaticSecret::random_from_rng(&mut rng);
        let bob_onetime_prekey_pub = PublicKey::from(&bob_onetime_prekey);

        // Create Bob's prekey bundle (with one-time prekey)
        let bob_bundle = PrekeyBundle {
            identity_key: bob_identity_pub,
            signed_prekey: bob_signed_prekey_pub,
            signature: [0u8; 64], // Placeholder for signature
            onetime_prekey: Some(bob_onetime_prekey_pub),
        };

        // Alice performs X3DH
        let (alice_shared_secret, alice_ephemeral_pub) =
            X3DH::initator(&alice_identity, &bob_bundle, &mut rng);

        // Bob performs X3DH
        let bob_shared_secret = X3DH::responder(
            &bob_identity,
            &bob_signed_prekey,
            Some(&bob_onetime_prekey),
            &alice_identity_pub,
            &alice_ephemeral_pub,
        );

        // Both should derive the same shared secret
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }

    #[test]
    fn test_x3dh_without_onetime_key() {
        let mut rng = OsRng;

        // Alice (initiator) generates her identity key
        let alice_identity = StaticSecret::random_from_rng(&mut rng);
        let alice_identity_pub = PublicKey::from(&alice_identity);

        // Bob (responder) generates his keys
        let bob_identity = StaticSecret::random_from_rng(&mut rng);
        let bob_identity_pub = PublicKey::from(&bob_identity);

        let bob_signed_prekey = StaticSecret::random_from_rng(&mut rng);
        let bob_signed_prekey_pub = PublicKey::from(&bob_signed_prekey);

        // Create Bob's prekey bundle (without one-time prekey)
        let bob_bundle = PrekeyBundle {
            identity_key: bob_identity_pub,
            signed_prekey: bob_signed_prekey_pub,
            signature: [0u8; 64], // Placeholder for signature
            onetime_prekey: None,
        };

        // Alice performs X3DH
        let (alice_shared_secret, alice_ephemeral_pub) =
            X3DH::initator(&alice_identity, &bob_bundle, &mut rng);

        // Bob performs X3DH
        let bob_shared_secret = X3DH::responder(
            &bob_identity,
            &bob_signed_prekey,
            None,
            &alice_identity_pub,
            &alice_ephemeral_pub,
        );

        // Both should derive the same shared secret
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }
}
