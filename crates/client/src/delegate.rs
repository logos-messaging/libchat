use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
use libchat::{IdentId, IdentityProvider, trunc};

use crate::ClientError;

type AccountAddr = String;

pub struct DelegateSigner {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
    identifier: IdentId,
    account_addr: Option<AccountAddr>,
}

impl DelegateSigner {
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

/// Represents the senders information for received frames.
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

    pub fn to_vec(self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0x23, 0x23]);
        let key_bytes = self.delegate_id.as_ref();
        data.extend_from_slice(&[Self::TAG_DELEGATE_ID, key_bytes.len() as u8]);
        data.extend_from_slice(key_bytes);
        if let Some(addr) = self.account_addr {
            let addr_bytes = addr.as_bytes();
            data.extend_from_slice(&[Self::TAG_ACCOUNT_ADDR, addr_bytes.len() as u8]);
            data.extend_from_slice(addr_bytes);
        }
        data
    }
}

impl From<DelegateCredential> for Vec<u8> {
    fn from(value: DelegateCredential) -> Self {
        value.to_vec()
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
        IdentId::new(hex::encode(value.to_vec()))
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
