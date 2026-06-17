use std::ops::Deref;

use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use openmls::credentials::{BasicCredential, CredentialWithKey};
use openmls_traits::{
    signatures::{Signer, SignerError},
    types::SignatureScheme,
};
use shared_traits::IdentIdRef;

use crate::AccountAuthority;
use crate::ChatError;
use crate::IdentityProvider;

/// A Wrapper for an IdentityProvider which provides MLS specific functionality
///
/// This type stops OpenMLS internal from leaking outside of the crate.
/// Developers provider a simple IdentitityProvider, and Signer and Credential generation
/// is provided
pub struct MlsIdentityProvider<T: IdentityProvider>(T);

impl<T: IdentityProvider> MlsIdentityProvider<T> {
    pub fn new(inner: T) -> Self {
        Self(inner)
    }

    /// Build the MLS leaf credential for this identity.
    ///
    /// The credential content binds this device (LocalIdentity) to its Account:
    /// the leaf's signature key is the device key, and the content carries the
    /// Account key plus the Account's endorsement of that device key. A receiver
    /// recovers both via [`logos_account::resolve_sender`]. On testnet the
    /// account key *is* the device key, so the endorsement is self-signed.
    pub fn get_credential(&self) -> Result<CredentialWithKey, ChatError> {
        let account = AccountAuthority::account_pub(self).clone();
        let device = self.public_key().clone();
        let endorsement = logos_account::endorse_local_identity(&account, &device, |msg| {
            AccountAuthority::sign(self, msg)
        })
        .map_err(|e| ChatError::Generic(e.to_string()))?;
        let content = logos_account::encode_credential(&account, &endorsement);
        Ok(CredentialWithKey {
            credential: BasicCredential::new(content).into(),
            signature_key: device.as_ref().into(),
        })
    }
}

impl<T: IdentityProvider> Deref for MlsIdentityProvider<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: IdentityProvider> IdentityProvider for MlsIdentityProvider<T> {
    fn id(&self) -> IdentIdRef<'_> {
        self.0.id()
    }

    fn display_name(&self) -> String {
        self.0.display_name()
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.0.sign(payload)
    }

    fn public_key(&self) -> &crypto::Ed25519VerifyingKey {
        self.0.public_key()
    }
}

// On testnet the installation identity is also the account authority: the
// account key is the installation's own key, so the device bundle is signed and
// addressed under `public_key()`. A real deployment injects a separate
// `AccountAuthority` (wallet/enclave) whose key custody lives outside libchat.
impl<T: IdentityProvider> AccountAuthority for MlsIdentityProvider<T> {
    type Error = std::convert::Infallible;

    fn account_pub(&self) -> &Ed25519VerifyingKey {
        self.public_key()
    }

    fn sign(&self, payload: &[u8]) -> Result<Ed25519Signature, Self::Error> {
        Ok(IdentityProvider::sign(self, payload))
    }
}

// Implement Signer directly for MlsIdentityProvider, so that openmls Signer contstraint
// does not leave the module.
impl<T: IdentityProvider> Signer for MlsIdentityProvider<T> {
    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SignerError> {
        Ok(self.0.sign(payload).as_ref().to_vec())
    }

    fn signature_scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}
