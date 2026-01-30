pub use blake2::Digest;
use blake2::{Blake2b, digest};
use prost::bytes::Bytes;

pub use crypto::{PrivateKey32, PublicKey32};

// TODO: (P4) Make handing of Keys in Prost easier
pub trait CopyBytes {
    fn copy_to_bytes(&self) -> Bytes;
}

impl CopyBytes for PublicKey32 {
    fn copy_to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self.as_bytes())
    }
}

#[allow(dead_code)]
pub type Blake2b128 = Blake2b<digest::consts::U16>;
