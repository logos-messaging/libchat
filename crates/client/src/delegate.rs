use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use libchat::{IdentId, IdentityProvider, trunc};

use crate::ClientError;

type AccountAddr = String;

/// A local signing identity that holds an Ed25519 keypair.
///
/// Can be standalone (unassociated) or authorized to act on behalf of an account
/// via [`DelegateSigner::associate`].
pub struct DelegateSigner {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
    identifier: IdentId,
    account_addr: Option<AccountAddr>,
}

impl DelegateSigner {
    /// Create a new signer with a randomly generated keypair.
    pub fn random() -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        let identifier = DelegateCredential::unassociated(&verifying_key).into();
        Self {
            signing_key,
            verifying_key,
            identifier,
            account_addr: None,
        }
    }

    /// Associate a DelegateSigner with an Account.
    pub fn associate(&mut self, account_addr: AccountAddr) {
        self.identifier =
            DelegateCredential::associated(&self.verifying_key, account_addr.as_str()).into();
        self.account_addr = Some(account_addr);
    }

    pub fn account_addr(&self) -> Option<&str> {
        self.account_addr.as_deref()
    }
}

impl IdentityProvider for DelegateSigner {
    fn id(&self) -> libchat::IdentIdRef<'_> {
        &self.identifier
    }

    fn display_name(&self) -> String {
        trunc(self.identifier.as_str())
    }

    fn sign(&self, payload: &[u8]) -> crypto::Ed25519Signature {
        self.signing_key.sign(payload)
    }

    fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }
}

/// A credential issued to a delegate key, optionally bound to an account address.
///
/// Serialized as a TLV byte sequence prefixed with magic bytes `0x23 0x23`.
/// A credential without an `account_addr` is *unassociated* — it identifies the
/// delegate key but has not yet been linked to an account.
#[derive(Debug)]
pub struct DelegateCredential {
    delegate_id: Ed25519VerifyingKey,
    account_addr: Option<AccountAddr>,
}

impl DelegateCredential {
    const TAG_DELEGATE_ID: u8 = 0x01;
    const TAG_ACCOUNT_ADDR: u8 = 0x02;

    pub fn unassociated(delegate: &Ed25519VerifyingKey) -> Self {
        Self {
            delegate_id: delegate.clone(),
            account_addr: None,
        }
    }

    pub fn associated(delegate: &Ed25519VerifyingKey, account: &str) -> Self {
        Self {
            delegate_id: delegate.clone(),
            account_addr: Some(account.to_string()),
        }
    }

    pub fn serialize(self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x23, 0x23]);
        let key_bytes = self.delegate_id.as_ref();
        debug_assert!(
            key_bytes.len() <= 255,
            "delegate_id too large for 1-byte TLV length"
        );
        data.extend_from_slice(&[Self::TAG_DELEGATE_ID, key_bytes.len() as u8]);
        data.extend_from_slice(key_bytes);
        if let Some(addr) = self.account_addr {
            let addr_bytes = addr.as_bytes();
            debug_assert!(
                addr_bytes.len() <= 255,
                "account_addr too large for 1-byte TLV length"
            );
            data.extend_from_slice(&[Self::TAG_ACCOUNT_ADDR, addr_bytes.len() as u8]);
            data.extend_from_slice(addr_bytes);
        }
        data
    }
}

impl From<DelegateCredential> for Vec<u8> {
    fn from(value: DelegateCredential) -> Self {
        value.serialize()
    }
}

impl TryFrom<Vec<u8>> for DelegateCredential {
    type Error = ClientError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.get(..2) != Some(&[0x23, 0x23]) {
            return Err(ClientError::BadlyFormedCredential);
        }
        let mut delegate_id = None;
        let mut account_addr = None;
        let mut i = 2;
        while i + 2 <= value.len() {
            let tag = value[i];
            let len = value[i + 1] as usize;
            i += 2;
            let v = value
                .get(i..i + len)
                .ok_or(ClientError::BadlyFormedCredential)?;
            i += len;
            match tag {
                DelegateCredential::TAG_DELEGATE_ID => {
                    let bytes: &[u8; 32] = v
                        .try_into()
                        .map_err(|_| ClientError::BadlyFormedCredential)?;
                    delegate_id = Some(
                        Ed25519VerifyingKey::from_bytes(bytes)
                            .map_err(|_| ClientError::BadlyFormedCredential)?,
                    );
                }
                DelegateCredential::TAG_ACCOUNT_ADDR => {
                    account_addr = Some(
                        String::from_utf8(v.to_vec())
                            .map_err(|_| ClientError::BadlyFormedCredential)?,
                    );
                }
                _ => {}
            }
        }
        Ok(Self {
            delegate_id: delegate_id.ok_or(ClientError::BadlyFormedCredential)?,
            account_addr,
        })
    }
}

impl From<DelegateCredential> for IdentId {
    fn from(value: DelegateCredential) -> Self {
        IdentId::new(hex::encode(value.serialize()))
    }
}

impl TryFrom<IdentId> for DelegateCredential {
    type Error = ClientError;

    fn try_from(value: IdentId) -> Result<Self, Self::Error> {
        hex::decode(value.as_str())
            .map_err(|_| ClientError::BadlyFormedCredential)?
            .try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;

    fn test_key() -> Ed25519VerifyingKey {
        Ed25519SigningKey::generate().verifying_key()
    }

    #[test]
    fn roundtrip_unassociated() {
        let key = test_key();
        let bytes = DelegateCredential::unassociated(&key).serialize();
        let recovered: DelegateCredential = bytes.clone().try_into().unwrap();
        assert_eq!(recovered.serialize(), bytes);
    }

    #[test]
    fn roundtrip_associated() {
        let key = test_key();
        let bytes = DelegateCredential::associated(&key, "user@example.com").serialize();
        let recovered: DelegateCredential = bytes.clone().try_into().unwrap();
        assert_eq!(recovered.serialize(), bytes);
    }

    #[test]
    fn ident_id_roundtrip_unassociated() {
        let key = test_key();
        let original = DelegateCredential::unassociated(&key).serialize();
        let ident_id: IdentId = DelegateCredential::unassociated(&key).into();
        let recovered: DelegateCredential = ident_id.try_into().unwrap();
        assert_eq!(recovered.serialize(), original);
    }

    #[test]
    fn ident_id_roundtrip_associated() {
        let key = test_key();
        let addr = "user@example.com";
        let original = DelegateCredential::associated(&key, addr).serialize();
        let ident_id: IdentId = DelegateCredential::associated(&key, addr).into();
        let recovered: DelegateCredential = ident_id.try_into().unwrap();
        assert_eq!(recovered.serialize(), original);
    }

    #[test]
    fn account_addr_preserved_across_roundtrip() {
        let key = test_key();
        let addr = "alice@libchat.example";
        let recovered: DelegateCredential = DelegateCredential::associated(&key, addr)
            .serialize()
            .try_into()
            .unwrap();
        assert_eq!(recovered.account_addr.as_deref(), Some(addr));
    }

    #[test]
    fn unassociated_has_no_account_after_roundtrip() {
        let key = test_key();
        let recovered: DelegateCredential = DelegateCredential::unassociated(&key)
            .serialize()
            .try_into()
            .unwrap();
        assert!(recovered.account_addr.is_none());
    }

    #[test]
    fn bad_magic_bytes_rejected() {
        let bytes = vec![0x00, 0x00, 0x01, 0x20];
        assert!(matches!(
            DelegateCredential::try_from(bytes),
            Err(ClientError::BadlyFormedCredential)
        ));
    }

    #[test]
    fn truncated_payload_rejected() {
        // Magic + TAG_DELEGATE_ID + len=32, but only 16 bytes of key data
        let mut bytes = vec![0x23, 0x23, 0x01, 32];
        bytes.extend_from_slice(&[0u8; 16]);
        assert!(matches!(
            DelegateCredential::try_from(bytes),
            Err(ClientError::BadlyFormedCredential)
        ));
    }

    #[test]
    fn missing_delegate_id_rejected() {
        // Valid magic but no TLV fields
        let bytes = vec![0x23, 0x23];
        assert!(matches!(
            DelegateCredential::try_from(bytes),
            Err(ClientError::BadlyFormedCredential)
        ));
    }

    #[test]
    fn invalid_utf8_account_addr_rejected() {
        let key = test_key();
        // Build a valid credential then corrupt the account_addr bytes
        let mut bytes = DelegateCredential::unassociated(&key).serialize();
        // Append a TAG_ACCOUNT_ADDR field with invalid UTF-8
        bytes.push(DelegateCredential::TAG_ACCOUNT_ADDR);
        bytes.push(3); // len
        bytes.extend_from_slice(&[0xFF, 0xFE, 0xFD]); // invalid UTF-8
        assert!(matches!(
            DelegateCredential::try_from(bytes),
            Err(ClientError::BadlyFormedCredential)
        ));
    }
}
