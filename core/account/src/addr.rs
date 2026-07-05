use std::fmt;

use crypto::Ed25519VerifyingKey;

use crate::error::AccountError;

/// A routable representation of an account
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountAddr {
    pubkey: Ed25519VerifyingKey,
}

impl AccountAddr {
    pub fn to_bytes(&self) -> &[u8] {
        self.pubkey.as_ref()
    }

    /// The verifying key this address wraps — what signatures are checked under.
    pub(crate) fn verifying_key(&self) -> &Ed25519VerifyingKey {
        &self.pubkey
    }
}

/// Displays as the hex of the account verifying key — the same form the
/// directory and keypackage registry use for ids.
impl fmt::Display for AccountAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.pubkey.as_ref()))
    }
}

impl From<&Ed25519VerifyingKey> for AccountAddr {
    fn from(value: &Ed25519VerifyingKey) -> Self {
        Self {
            pubkey: value.clone(),
        }
    }
}

/// Not every byte string is an address: exactly 32 bytes forming a valid
/// Ed25519 key.
impl TryFrom<&[u8]> for AccountAddr {
    type Error = AccountError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let bytes: [u8; 32] = value.try_into().map_err(|_| AccountError::InvalidAddress)?;
        let pubkey =
            Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| AccountError::InvalidAddress)?;
        Ok(Self { pubkey })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;

    /// Display is the hex of the key; TryFrom round-trips the bytes.
    #[test]
    fn display_and_try_from_roundtrip() {
        let key = Ed25519SigningKey::generate().verifying_key();
        let addr = AccountAddr::from(&key);
        assert_eq!(addr.to_string(), hex::encode(key.as_ref()));
        assert_eq!(AccountAddr::try_from(addr.to_bytes()).unwrap(), addr);
    }

    #[test]
    fn try_from_rejects_wrong_length() {
        assert!(AccountAddr::try_from(&[0u8; 31][..]).is_err());
    }
}
