use crypto::Ed25519SigningKey;
use openmls::prelude::SignatureScheme;
use openmls_traits::signatures::Signer;

use crate::types::AccountId;

/// Logos Account represents a single account across
/// multiple installations and services.
pub struct LogosAccount {
    id: AccountId,
    signing_key: Ed25519SigningKey,
}

impl LogosAccount {
    /// Create a test LogosAccount using a pre-defined identifier.
    /// This should only be used during MLS integration. Not suitable for production use.
    /// TODO: (P1) Remove once implementation is ready.
    pub fn new_test(explicit_id: impl Into<String>) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        Self {
            id: AccountId::new(explicit_id.into()),
            signing_key,
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
