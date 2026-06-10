use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use shared_traits::{IdentId, IdentIdRef};

use libchat::IdentityProvider;

/// A Test Focused LogosAccount using a pre-defined identifier.
/// The test account is not persisted, and uses a single user provided id.
/// This account type should not be used in a production system.
pub struct TestLogosAccount {
    id: IdentId,
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl TestLogosAccount {
    pub fn new(explicit_id: impl Into<String>) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            id: IdentId::new(explicit_id.into()),
            signing_key,
            verifying_key,
        }
    }
}

impl IdentityProvider for TestLogosAccount {
    fn id(&self) -> IdentIdRef<'_> {
        &self.id
    }

    fn display_name(&self) -> String {
        self.id.to_string()
    }

    fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}
