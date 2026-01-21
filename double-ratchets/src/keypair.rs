use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::SharedSecret;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InstallationKeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl InstallationKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn dh(&self, their_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(their_public).to_bytes()
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// Export the secret key as raw bytes for serialization/storage.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Import the secret key from raw bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}
