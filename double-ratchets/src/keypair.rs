use crypto::{PrivateKey32, PublicKey32};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::SharedSecret;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InstallationKeyPair {
    secret: PrivateKey32,
    public: PublicKey32,
}

impl InstallationKeyPair {
    pub fn generate() -> Self {
        let secret = PrivateKey32::random_from_rng(OsRng);
        let public = PublicKey32::from(&secret);
        Self { secret, public }
    }

    pub fn dh(&self, their_public: &PublicKey32) -> SharedSecret {
        self.secret.diffie_hellman(their_public).to_bytes()
    }

    pub fn public(&self) -> &PublicKey32 {
        &self.public
    }

    /// Export the secret key as raw bytes for serialization/storage.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.secret.as_bytes()
    }

    /// Import the secret key from raw bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = PrivateKey32::from(bytes);
        let public = PublicKey32::from(&secret);
        Self { secret, public }
    }
}
