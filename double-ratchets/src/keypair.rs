use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::types::SharedSecret;

#[derive(Clone)]
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
    ///
    /// # Security Warning
    ///
    /// The returned bytes contain the private key material. Handle with care
    /// and ensure proper encryption when storing.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    /// Reconstruct a keypair from raw secret and public key bytes.
    ///
    /// # Arguments
    ///
    /// * `secret` - The 32-byte secret key.
    /// * `public` - The 32-byte public key.
    ///
    /// # Returns
    ///
    /// * `Ok(InstallationKeyPair)` if the keys are valid and consistent.
    /// * `Err(&'static str)` if the public key doesn't match the secret key.
    pub fn from_bytes(secret: [u8; 32], public: [u8; 32]) -> Result<Self, &'static str> {
        let secret = StaticSecret::from(secret);
        let expected_public = PublicKey::from(&secret);
        let public = PublicKey::from(public);

        if expected_public.as_bytes() != public.as_bytes() {
            return Err("public key does not match secret key");
        }

        Ok(Self { secret, public })
    }
}
