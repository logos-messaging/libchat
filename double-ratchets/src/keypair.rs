use crypto::{PrivateKey, PublicKey};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::types::SharedSecret;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct InstallationKeyPair {
    secret: PrivateKey,
    public: PublicKey,
}

impl InstallationKeyPair {
    pub fn generate() -> Self {
        let secret = PrivateKey::random_from_rng(OsRng);
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
    pub fn secret_bytes(&self) -> &[u8; 32] {
        self.secret.as_bytes()
    }

    /// Import the secret key from raw bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = PrivateKey::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }
}

impl From<PrivateKey> for InstallationKeyPair {
    fn from(value: PrivateKey) -> Self {
        let public = PublicKey::from(&value);
        Self {
            secret: value,
            public,
        }
    }
}
