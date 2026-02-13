use crypto::{X25519PrivateKey, X25519PublicKey};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::SharedSecret;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InstallationKeyPair {
    secret: X25519PrivateKey,
    public: X25519PublicKey,
}

impl InstallationKeyPair {
    pub fn generate() -> Self {
        let secret = X25519PrivateKey::random_from_rng(OsRng);
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
        let secret = X25519PrivateKey::from(bytes);
        let public = X25519PublicKey::from(&secret);
        Self { secret, public }
    }
}

impl From<X25519PrivateKey> for InstallationKeyPair {
    fn from(value: X25519PrivateKey) -> Self {
        let public = X25519PublicKey::from(&value);
        Self {
            secret: value,
            public,
        }
    }
}
