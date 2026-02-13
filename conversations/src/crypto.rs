pub use crypto::X25519PublicKey;
pub use x25519_dalek::StaticSecret;

use prost::bytes::Bytes;

pub trait CopyBytes {
    fn copy_to_bytes(&self) -> Bytes;
}

impl CopyBytes for X25519PublicKey {
    fn copy_to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self.as_bytes())
    }
}
