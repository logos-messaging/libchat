use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use openmls::prelude::SignatureScheme;
use openmls_traits::signatures::Signer;

use crate::types::AccountId;

/// Logos Account represents a single account across
/// multiple installations and services.
pub struct LogosAccount {
    id: AccountId,
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl LogosAccount {
    /// Create an LogosAccount using a pre-defined identifier.
    /// This should only be used in test scenarios where the identifiers can be chosen
    /// to ensure no conflicts between instances. Not suitable for production use.
    pub fn new_test(explicit_id: impl Into<String>) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            id: AccountId::new(explicit_id.into()),
            signing_key,
            verifying_key,
        }
    }

    pub fn account_id(&self) -> &AccountId {
        &self.id
    }
}

impl Signer for LogosAccount {
    // TODO: (P2) Remove OpenMLS dependency to make accounts more portable
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        Ok(self.signing_key.sign(payload).as_ref().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
