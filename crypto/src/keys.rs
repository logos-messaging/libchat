use generic_array::{GenericArray, typenum::U32};
use std::{fmt::Debug, ops::Deref};
use x25519_dalek;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Debug, Copy, Clone)]
pub struct PublicKey32(x25519_dalek::PublicKey);

impl From<x25519_dalek::PublicKey> for PublicKey32 {
    fn from(value: x25519_dalek::PublicKey) -> Self {
        Self(value)
    }
}

impl From<&x25519_dalek::StaticSecret> for PublicKey32 {
    fn from(value: &x25519_dalek::StaticSecret) -> Self {
        Self(x25519_dalek::PublicKey::from(value))
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

impl AsRef<[u8]> for PublicKey32 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
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
