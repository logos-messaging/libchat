//! The MLS leaf credential as a plain Account claim, plus the service that
//! validates it.
//!
//! Two identity scopes meet in a group message:
//!
//! - **Signer** — the device key. MLS proves the sender controls it; it *is* the
//!   LocalIdentity. Surfaced as the leaf's signature key.
//! - **Credential** — a public *claim* `(AccountId, device public key)`. The
//!   credential content carries only the claimed Account; the device key is the
//!   leaf signature key MLS hands us.
//!
//! A claim is not trusted on its own — anyone can staple any account id next to
//! their own device key. Trust comes from an account service (the account →
//! device directory): it answers "is this device key actually registered to
//! that account?". Decoding ([`decode_credential`]) is therefore separate from
//! validation: core surfaces the raw [`SenderCredential`], and the client
//! validates it before reporting an identifier to the application.

use crypto::Ed25519VerifyingKey;
use shared_traits::IdentId;
use thiserror::Error;

/// Current credential content version. Bump when [`encode_credential`] changes.
pub const CREDENTIAL_VERSION: u8 = 1;

/// Domain-separation tag prepended to the credential content, so these bytes
/// can't be confused with any other signed/encoded payload in the system. The
/// trailing NUL keeps it from being a prefix of any other domain.
pub const CREDENTIAL_DOMAIN: &[u8] = b"libchat:account-local-identity\0";

/// The raw, *unvalidated* sender of a group message, decoded from the MLS
/// credential: the claimed Account and the device (LocalIdentity) it was sent
/// from. Both are hex-encoded Ed25519 verifying keys.
///
/// The `local_identity` is trustworthy on its own — MLS verified the message
/// against that device key. The `account` is only a *claim* until an
/// [`AccountService`] confirms the device belongs to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SenderCredential {
    /// The Account the sender *claims* to belong to (hex of the account key).
    pub account: IdentId,
    /// The device/LocalIdentity that sent the message (hex of the leaf key).
    pub local_identity: IdentId,
}

/// The validated identifier handed to the application: a [`SenderCredential`]
/// whose account claim an [`AccountService`] has confirmed. Same shape as the
/// credential, but the distinct type marks that validation has happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSender {
    /// The confirmed Account the sending device belongs to.
    pub account: IdentId,
    /// The specific LocalIdentity (device) that sent the message.
    pub local_identity: IdentId,
}

impl MessageSender {
    /// Promote a validated credential to an identifier. Call only *after* an
    /// [`AccountService`] has confirmed the claim.
    pub fn validated(cred: SenderCredential) -> Self {
        Self {
            account: cred.account,
            local_identity: cred.local_identity,
        }
    }
}

/// Failures decoding a credential.
#[derive(Debug, Error)]
pub enum CredentialError {
    #[error("credential is missing the account-local-identity domain prefix")]
    Domain,
    #[error("credential shorter than its declared layout")]
    Short,
    #[error("unsupported credential version {0}")]
    Version(u8),
    #[error("credential carries a malformed account key")]
    AccountKey,
}

/// Encode the MLS credential content: the Account claim.
///
/// The device key is *not* embedded — it is the leaf's signature key, supplied
/// out-of-band by MLS on the receiving side and paired in [`decode_credential`].
///
/// ```text
/// domain      : CREDENTIAL_DOMAIN    (constant prefix, NUL-terminated)
/// version     : u8        (1 byte)
/// account_pub : [u8; 32]  (32 bytes)
/// ```
pub fn encode_credential(account: &Ed25519VerifyingKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(CREDENTIAL_DOMAIN.len() + 1 + 32);
    out.extend_from_slice(CREDENTIAL_DOMAIN);
    out.push(CREDENTIAL_VERSION);
    out.extend_from_slice(account.as_ref());
    out
}

/// Decode `credential_content` into the raw claim, pairing the embedded Account
/// with `device_key` (the key the MLS leaf actually signs with). This does *not*
/// validate the claim — the account is only asserted until checked against an
/// [`AccountService`].
pub fn decode_credential(
    credential_content: &[u8],
    device_key: &Ed25519VerifyingKey,
) -> Result<SenderCredential, CredentialError> {
    const HEADER: usize = 1 + 32;
    let rest = credential_content
        .strip_prefix(CREDENTIAL_DOMAIN)
        .ok_or(CredentialError::Domain)?;
    if rest.len() < HEADER {
        return Err(CredentialError::Short);
    }
    let version = rest[0];
    if version != CREDENTIAL_VERSION {
        return Err(CredentialError::Version(version));
    }
    let account_bytes: [u8; 32] = rest[1..33].try_into().expect("33 - 1 == 32");
    let account =
        Ed25519VerifyingKey::from_bytes(&account_bytes).map_err(|_| CredentialError::AccountKey)?;

    Ok(SenderCredential {
        account: IdentId::new(hex::encode(account.as_ref())),
        local_identity: IdentId::new(hex::encode(device_key.as_ref())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;

    /// encode → decode pairs the embedded account with the supplied device key.
    #[test]
    fn decodes_well_formed_credential() {
        let account = Ed25519SigningKey::generate().verifying_key();
        let device = Ed25519SigningKey::generate().verifying_key();

        let content = encode_credential(&account);
        let cred = decode_credential(&content, &device).unwrap();

        assert_eq!(cred.account.as_str(), hex::encode(account.as_ref()));
        assert_eq!(cred.local_identity.as_str(), hex::encode(device.as_ref()));
    }

    #[test]
    fn rejects_missing_domain_short_and_bad_version() {
        let account = Ed25519SigningKey::generate().verifying_key();
        let device = Ed25519SigningKey::generate().verifying_key();
        let content = encode_credential(&account);

        assert!(matches!(
            decode_credential(&content[CREDENTIAL_DOMAIN.len()..], &device),
            Err(CredentialError::Domain)
        ));
        assert!(matches!(
            decode_credential(&content[..CREDENTIAL_DOMAIN.len() + 1], &device),
            Err(CredentialError::Short)
        ));
        let mut bad_version = content.clone();
        bad_version[CREDENTIAL_DOMAIN.len()] = 99;
        assert!(matches!(
            decode_credential(&bad_version, &device),
            Err(CredentialError::Version(99))
        ));
    }
}
