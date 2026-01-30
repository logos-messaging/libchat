use generic_array::{GenericArray, typenum::U32};
use std::fmt::Debug;
use zeroize::{Zeroize, ZeroizeOnDrop};

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
