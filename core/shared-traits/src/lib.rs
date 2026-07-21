use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentId(String);
pub type IdentIdRef<'a> = &'a IdentId;

impl IdentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for IdentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl AsRef<str> for IdentId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct SignerId(Vec<u8>);

impl SignerId {
    pub fn from_ed25519(key: &Ed25519VerifyingKey) -> Self {
        Self(key.as_ref().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl From<Vec<u8>> for SignerId {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for SignerId {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl AsRef<[u8]> for SignerId {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// Represents an external Identity
/// Implement this to provide an Authentication model for users/installations
pub trait IdentityProvider {
    fn id(&self) -> IdentIdRef<'_>;
    // Display name is not garenteed to be consistent. It should only be used to
    // provded a more readable identifier for the account.
    fn display_name(&self) -> String;
    fn sign(&self, payload: &[u8]) -> Ed25519Signature;
    fn public_key(&self) -> &Ed25519VerifyingKey;
}
