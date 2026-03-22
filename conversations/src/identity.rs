use std::fmt;

use crate::crypto::{PrivateKey, PublicKey};

use openmls::{
    prelude::{hash_ref::make_key_package_ref, *},
    treesync::RatchetTree,
};
use openmls_basic_credential::SignatureKeyPair;

use openmls_libcrux_crypto::Provider as LibcruxProvider;

pub struct Identity {
    name: String,
    secret: PrivateKey,
    provider: LibcruxProvider,
    cred: CredentialWithKey,
    signer: SignatureKeyPair,
}

// Each participant needs their own crypto provider and credential
fn make_participant(
    name: &str,
    provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
    let credential = BasicCredential::new(name.as_bytes().to_vec());
    let signature_keys = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
    signature_keys.store(provider.storage()).unwrap();

    let credential_with_key = CredentialWithKey {
        credential: credential.into(),
        signature_key: signature_keys.to_public_vec().into(),
    };

    (credential_with_key, signature_keys)
}

// Each participant generates a key package — this is what you share
// with others so they can add you to a group
fn make_key_package(
    credential_with_key: CredentialWithKey,
    signer: &SignatureKeyPair,
    provider: &impl OpenMlsProvider,
) -> KeyPackage {
    KeyPackage::builder()
        .build(
            Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519,
            provider,
            signer,
            credential_with_key,
        )
        .unwrap()
        .key_package()
        .clone() // TODO: (!) Check clone
}

impl fmt::Debug for Identity {
    // Manually implement debug to not reveal secret key material
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("public_key", &self.public_key())
            .finish_non_exhaustive()
    }
}

impl Identity {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        let provider = LibcruxProvider::new().unwrap();
        let (cred, signer) = make_participant(&name, &provider);

        Self {
            name,
            secret: PrivateKey::random(),
            provider,
            cred,
            signer,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey::from(&self.secret)
    }

    pub fn secret(&self) -> &PrivateKey {
        &self.secret
    }

    // Returns an associated name for this Identity.
    // Names are a friendly developer chosen identifier for an Identity which
    // can provide between logging.
    pub fn get_name(&self) -> &str {
        &self.name
    }

    pub fn credential(&self) -> &CredentialWithKey {
        &self.cred
    }

    pub fn signer(&self) -> &SignatureKeyPair {
        &self.signer
    }

    pub fn key_package(&self) -> KeyPackage {
        make_key_package(self.credential().clone(), &self.signer, self.provider())
    }

    pub fn provider(&self) -> &LibcruxProvider {
        &self.provider
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self::new("default")
    }
}
