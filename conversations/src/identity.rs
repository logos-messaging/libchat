use blake2::{Blake2b512, Digest};
use std::fmt;

use crate::crypto::{PrivateKey32, PublicKey32};

pub struct Identity {
    secret: PrivateKey32,
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
            secret: PrivateKey32::random(),
        }
    }

    pub fn address(&self) -> String {
        hex::encode(Blake2b512::digest(self.public_key()))
    }

    pub fn public_key(&self) -> PublicKey32 {
        PublicKey32::from(&self.secret)
    }

    pub fn secret(&self) -> &PrivateKey32 {
        &self.secret
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}
