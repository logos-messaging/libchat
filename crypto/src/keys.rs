use std::fmt::Debug;

pub use generic_array::{GenericArray, typenum::U32};
use x25519_dalek::SharedSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A Generic secret key container for symmetric keys.
/// SymmetricKey retains ownership of bytes to ensure they are Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop, PartialEq)]
pub struct SymmetricKey<const N: usize>([u8; N]);

impl<const N: usize> SymmetricKey<N> {
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns internal [u8; N].
    /// This function by passes zeroize_on_drop, and will be deprecated once all consumers have been migrated
    #[allow(nonstandard_style)]
    pub fn DANGER_to_bytes(self) -> [u8; N] {
        // TODO: (P3) Remove once DR ported to use safe keys.
        self.0
    }
}

impl<const N: usize> From<[u8; N]> for SymmetricKey<N> {
    fn from(value: [u8; N]) -> Self {
        SymmetricKey(value)
    }
}

impl<const N: usize> Debug for SymmetricKey<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricKey(...{N} Bytes Redacted...)")
    }
}

// TODO: (P5) look into typenum::generic_const_mappings to avoid having to implment From<U>
pub type SymmetricKey32 = SymmetricKey<32>;

impl From<GenericArray<u8, U32>> for SymmetricKey32 {
    fn from(value: GenericArray<u8, U32>) -> Self {
        SymmetricKey(value.into())
    }
}

impl From<&SharedSecret> for SymmetricKey32 {
    // This relies on the feature 'zeroize' being set for x25519-dalek.
    // If not the SharedSecret will need to manually zeroized
    fn from(value: &SharedSecret) -> Self {
        value.to_bytes().into()
    }
}
