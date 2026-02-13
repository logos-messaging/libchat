//! XEdDSA signing using X25519 keys.
//!
//! This module provides generic XEdDSA sign and verify functions
//! that allow signing arbitrary messages with X25519 keys.

use rand_core::{CryptoRng, RngCore};
use xeddsa::{Sign, Verify, xed25519};

use crate::keys::{X25519PrivateKey, X25519PublicKey};

/// A 64-byte XEdDSA signature over an Ed25519-compatible curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Signature(pub [u8; 64]);

impl Ed25519Signature {
    pub fn empty() -> Self {
        Self([0u8; 64])
    }
}

impl AsRef<[u8; 64]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8; 64] {
        &self.0
    }
}

impl From<[u8; 64]> for Ed25519Signature {
    fn from(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }
}

/// Error type for signature verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("signature verification failed")]
pub struct SignatureError;

/// Sign a message using XEdDSA with an X25519 secret key.
///
/// # Arguments
/// * `secret` - The X25519 secret key to sign with
/// * `message` - The message to sign
/// * `rng` - A cryptographically secure random number generator
///
/// # Returns
/// An `Ed25519Signature`
pub fn xeddsa_sign<R: RngCore + CryptoRng>(
    secret: &X25519PrivateKey,
    message: &[u8],
    mut rng: R,
) -> Ed25519Signature {
    let signing_key = xed25519::PrivateKey::from(secret);
    Ed25519Signature(signing_key.sign(message, &mut rng))
}

/// Verify an XEdDSA signature using an X25519 public key.
///
/// # Arguments
/// * `pubkey` - The X25519 public key to verify with
/// * `message` - The message that was signed
/// * `signature` - The 64-byte XEdDSA signature to verify
///
/// # Returns
/// `Ok(())` if the signature is valid, `Err(SignatureError)` otherwise
pub fn xeddsa_verify(
    pubkey: &X25519PublicKey,
    message: &[u8],
    signature: &Ed25519Signature,
) -> Result<(), SignatureError> {
    let verify_key = xed25519::PublicKey::from(pubkey);
    verify_key
        .verify(message, &signature.0)
        .map_err(|_| SignatureError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let secret = X25519PrivateKey::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        let message = b"test message";

        let signature = xeddsa_sign(&secret, message, OsRng);

        assert!(xeddsa_verify(&public, message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_key_fails() {
        let secret = X25519PrivateKey::random_from_rng(OsRng);
        let message = b"test message";

        let signature = xeddsa_sign(&secret, message, OsRng);

        let wrong_secret = X25519PrivateKey::random_from_rng(OsRng);
        let wrong_public = X25519PublicKey::from(&wrong_secret);

        assert_eq!(
            xeddsa_verify(&wrong_public, message, &signature),
            Err(SignatureError)
        );
    }

    #[test]
    fn test_wrong_message_fails() {
        let secret = X25519PrivateKey::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        let message = b"test message";

        let signature = xeddsa_sign(&secret, message, OsRng);

        assert_eq!(
            xeddsa_verify(&public, b"wrong message", &signature),
            Err(SignatureError)
        );
    }

    #[test]
    fn test_corrupted_signature_fails() {
        let secret = X25519PrivateKey::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        let message = b"test message";

        let mut signature = xeddsa_sign(&secret, message, OsRng);
        signature.0[0] ^= 0xFF;

        assert_eq!(
            xeddsa_verify(&public, message, &signature),
            Err(SignatureError)
        );
    }
}
