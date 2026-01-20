use std::fmt::Debug;

pub use generic_array::{GenericArray, typenum::U32};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq)]
pub struct SecretKey([u8; 32]);

impl SecretKey {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<[u8; 32]> for SecretKey {
    fn from(value: [u8; 32]) -> Self {
        SecretKey(value)
    }
}

impl From<GenericArray<u8, U32>> for SecretKey {
    fn from(value: GenericArray<u8, U32>) -> Self {
        SecretKey(value.into())
    }
}

impl Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SecretKey").field(&"<32 bytes>").finish()
    }
}
