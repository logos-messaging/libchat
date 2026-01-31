use generic_array::{GenericArray, typenum::U32};
use rand_core::{CryptoRng, OsRng, RngCore};
use std::{
    fmt::Debug,
    ops::{Deref, DerefMut},
};
use x25519_dalek;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PublicKey32(x25519_dalek::PublicKey);

impl From<&PrivateKey32> for PublicKey32 {
    fn from(value: &PrivateKey32) -> Self {
        Self(x25519_dalek::PublicKey::from(&value.0))
    }
}

impl From<[u8; 32]> for PublicKey32 {
    fn from(value: [u8; 32]) -> Self {
        Self(x25519_dalek::PublicKey::from(value))
    }
}

impl Deref for PublicKey32 {
    type Target = x25519_dalek::PublicKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for PublicKey32 {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl AsRef<[u8]> for PublicKey32 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey32(x25519_dalek::StaticSecret);

impl PrivateKey32 {
    pub fn random_from_rng<T: RngCore + CryptoRng>(mut csprng: T) -> Self {
        Self(x25519_dalek::StaticSecret::random_from_rng(csprng))
    }

    //TODO: Remove. Force internal callers provide Rng to make deterministic testing possible
    pub fn random() -> PrivateKey32 {
        Self::random_from_rng(&mut OsRng)
    }

    // Convenience function to generate a PublicKey32
    pub fn public_key(&self) -> PublicKey32 {
        PublicKey32::from(self)
    }
}

impl From<[u8; 32]> for PrivateKey32 {
    fn from(value: [u8; 32]) -> Self {
        Self(x25519_dalek::StaticSecret::from(value))
    }
}

impl Deref for PrivateKey32 {
    type Target = x25519_dalek::StaticSecret;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq)]
pub struct SecretKey32([u8; 32]);

impl SecretKey32 {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<[u8; 32]> for SecretKey32 {
    fn from(value: [u8; 32]) -> Self {
        SecretKey32(value)
    }
}

impl From<GenericArray<u8, U32>> for SecretKey32 {
    fn from(value: GenericArray<u8, U32>) -> Self {
        SecretKey32(value.into())
    }
}

impl Debug for SecretKey32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretKey").field(&"<32 bytes>").finish()
    }
}
