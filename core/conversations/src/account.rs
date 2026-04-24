use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use openmls::prelude::SignatureScheme;
use openmls_traits::signatures::Signer;

use crate::{conversation::IdentityProvider, types::AccountId};

pub struct LogosAccount {
    id: AccountId,
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl LogosAccount {
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
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, openmls_traits::signatures::SignerError> {
        Ok(self.signing_key.sign(payload).as_ref().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl IdentityProvider for LogosAccount {
    fn friendly_name(&self) -> String {
        self.id.to_string()
    }

    fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }
}
