pub use blake2::Digest;
use blake2::{Blake2b, digest};
use prost::bytes::Bytes;
pub use x25519_dalek::{PublicKey, StaticSecret};

pub trait CopyBytes {
    fn copy_to_bytes(&self) -> Bytes;
}

impl CopyBytes for PublicKey {
    fn copy_to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self.as_bytes())
    }
}

#[allow(dead_code)]
pub type Blake2b128 = Blake2b<digest::consts::U16>;
