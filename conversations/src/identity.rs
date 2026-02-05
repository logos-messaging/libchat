use blake2::{Blake2b512, Digest};
use std::fmt;
pub use x25519_dalek::{PublicKey, StaticSecret};

pub struct Identity {
    secret: StaticSecret,
}

impl fmt::Debug for Identity {
    // Manually implement debug to not reveal secret key material
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn new() -> Self {
        Self {
            secret: StaticSecret::random(),
        }
    }

    /// Create an Identity from an existing secret key.
    pub fn from_secret(secret: StaticSecret) -> Self {
        Self { secret }
    }

    /// Create an Identity from raw secret key bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    pub fn address(&self) -> String {
        hex::encode(Blake2b512::digest(self.public_key()))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    pub fn secret(&self) -> &StaticSecret {
        &self.secret
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}
