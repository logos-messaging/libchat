use crypto::{Ed25519Signature, Ed25519SigningKey, Ed25519VerifyingKey};
use openmls::prelude::SignatureScheme;
use openmls_traits::signatures::Signer;

use crate::account_directory::AccountAuthority;
use crate::{AccountId, IdentityProvider};

/// Logos Account represents a single account across
/// multiple installations and services.
///
/// Deprecated!
pub struct LogosAccount {
    id: AccountId,
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl LogosAccount {
    /// Create a test LogosAccount. The `AccountId` is derived from the
    /// generated Ed25519 verifying key (hex-encoded) so signatures over the
    /// id can be verified by anyone holding the id alone.
    /// The supplied `_display_name` is currently ignored — id is the key.
    /// This should only be used during MLS integration. Not suitable for production use.
    /// TODO: (P1) Remove once implementation is ready.
    pub fn new_test(_display_name: impl Into<String>) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let id = AccountId::new(hex::encode(verifying_key.as_ref()));
        Self {
            id,
            signing_key,
            verifying_key,
        }
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

impl IdentityProvider for LogosAccount {
    fn account_id(&self) -> &AccountId {
        &self.id
    }

    fn display_name(&self) -> String {
        self.id.to_string()
    }

    fn sign(&self, payload: &[u8]) -> Ed25519Signature {
        self.signing_key.sign(payload)
    }

    fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }
}

/// On testnet the account key lives on-device (it is the same key that backs the
/// LocalIdentity), so signing the device-list bundle never fails — `Error` is
/// [`Infallible`]. An external signer would supply its own `AccountAuthority`
/// with a fallible `sign`.
///
/// [`Infallible`]: std::convert::Infallible
impl AccountAuthority for LogosAccount {
    type Error = std::convert::Infallible;

    fn account_id(&self) -> &AccountId {
        &self.id
    }

    fn sign(&self, payload: &[u8]) -> Result<Ed25519Signature, Self::Error> {
        Ok(self.signing_key.sign(payload))
    }
}
