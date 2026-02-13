use crypto::X25519PublicKey;
use rand_core::OsRng;
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::SharedSecret;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InstallationKeyPair {
    secret: StaticSecret,
    public: X25519PublicKey,
}

impl InstallationKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn dh(&self, their_public: &X25519PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(their_public).to_bytes()
    }

    pub fn public(&self) -> &X25519PublicKey {
        &self.public
    }

    /// Export the secret key as raw bytes for serialization/storage.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.secret.as_bytes()
    }

    /// Import the secret key from raw bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }
}

impl From<StaticSecret> for InstallationKeyPair {
    fn from(value: StaticSecret) -> Self {
        let public = X25519PublicKey::from(&value);
        Self {
            secret: value,
            public,
        }
    }
}
