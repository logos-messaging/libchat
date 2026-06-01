use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};

use libchat::{AccountId, IdentityProvider};

/// A Test Focused LogosAccount.
/// The test account is not persisted, and derives its `AccountId` from the
/// generated Ed25519 verifying key so that signatures over the id can be
/// verified by anyone holding the id alone.
/// This account type should not be used in a production system.
pub struct TestLogosAccount {
    id: AccountId,
    display_name: String,
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl TestLogosAccount {
    pub fn new(display_name: impl Into<String>) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let id = AccountId::new(hex::encode(verifying_key.as_ref()));
        Self {
            id,
            display_name: display_name.into(),
            signing_key,
            verifying_key,
        }
    }
}

impl IdentityProvider for TestLogosAccount {
    fn account_id(&self) -> &AccountId {
        &self.id
    }

    fn display_name(&self) -> String {
        self.display_name.clone()
    }

    fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }
}
