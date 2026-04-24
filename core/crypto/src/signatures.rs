// use generic_array::{GenericArray, typenum::U32};

// use rand_core::{CryptoRng, OsRng, RngCore};
use ed25519_dalek::{self, Signer};
use rand_core::OsRng;
use std::{fmt::Debug, ops::Deref};
use thiserror::Error;

#[derive(Debug, Error)]
#[error("verification failed of the Ed25519 Signature")]
pub struct SignatureVerificationError {}

/// A 64-byte XEdDSA signature over an Ed25519-compatible curve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ed25519Signature([u8; 64]);

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

#[derive(Clone)]
pub struct Ed25519SigningKey(ed25519_dalek::SigningKey);

impl Ed25519SigningKey {
    pub fn generate() -> Self {
        Self(ed25519_dalek::SigningKey::generate(&mut OsRng))
    }

    pub fn sign(&self, msg: &[u8]) -> Ed25519Signature {
        let signature_bytes: [u8; 64] = self.0.sign(msg).to_bytes();
        signature_bytes.into()
    }

    pub fn verifying_key(&self) -> Ed25519VerifyingKey {
        self.0.verifying_key().into()
    }
}

pub struct Ed25519VerifyingKey(ed25519_dalek::VerifyingKey);

impl Ed25519VerifyingKey {
    pub fn verify(
        &self,
        msg: &[u8],
        signature: &Ed25519Signature,
    ) -> Result<(), SignatureVerificationError> {
        let inner_signature = signature.0;
        self.0
            .verify_strict(msg, &ed25519_dalek::Signature::from_bytes(&inner_signature))
            .map_err(|e| SignatureVerificationError {})
    }
}

impl From<ed25519_dalek::VerifyingKey> for Ed25519VerifyingKey {
    fn from(value: ed25519_dalek::VerifyingKey) -> Self {
        Ed25519VerifyingKey(value)
    }
}

impl AsRef<[u8]> for Ed25519VerifyingKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}
