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
}
