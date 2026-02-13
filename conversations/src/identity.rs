use std::fmt;

use crate::crypto::{PrivateKey, PublicKey};

pub struct Identity {
    secret: PrivateKey,
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
            secret: PrivateKey::random(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    pub fn secret(&self) -> &PrivateKey {
        &self.secret
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::new()
    }
}
