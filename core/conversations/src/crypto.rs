pub use crypto::{PrivateKey, PublicKey};
use prost::bytes::Bytes;

pub trait CopyBytes {
    fn copy_to_bytes(&self) -> Bytes;
}

impl CopyBytes for PublicKey {
    fn copy_to_bytes(&self) -> Bytes {
        Bytes::copy_from_slice(self.as_bytes())
    }
}
