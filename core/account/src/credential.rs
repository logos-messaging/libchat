//! Account ↔ LocalIdentity binding carried inside the MLS leaf credential.
//!
//! A group message in MLS is signed by a per-device key — the **LocalIdentity**
//! (a device/installation). On its own that key says nothing about which
//! **Account** the device belongs to, so multiple LocalIdentities of one Account
//! cannot be collapsed back to that Account on the receiving side.
//!
//! This module binds the two together *inside the credential itself*, so a
//! receiver resolves both without any network round-trip or trusted directory:
//!
//! - the MLS leaf's signature key is the LocalIdentity device key (MLS already
//!   proves the sender holds its private half), and
//! - the credential content carries the Account key plus the Account's signature
//!   endorsing that exact device key.
//!
//! [`resolve_sender`] verifies the endorsement against the device key the leaf
//! actually signs with, yielding a [`MessageSender`] the application can trust.
//! This is the inverse of the account → device directory in `libchat`
//! (`account_directory`): that resolves an Account *to* its devices for invites;
//! this resolves a device *back to* its Account on receipt.

use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use shared_traits::IdentId;
use thiserror::Error;

/// Current credential content version. Bump when [`encode_credential`] changes.
pub const CREDENTIAL_VERSION: u8 = 1;

/// Domain-separation tag prepended to the credential content and folded into the
/// endorsement message. The account key may sign other things (e.g. the device
/// bundle in `account_directory`), so binding to this exact purpose stops a
/// signature obtained elsewhere from being replayed here. The trailing NUL keeps
/// it from being a prefix of any other domain.
pub const CREDENTIAL_DOMAIN: &[u8] = b"libchat:account-local-identity\0";

/// The verified sender of a group message: which Account, and which device
/// (LocalIdentity) of that Account it was sent from. Both are hex-encoded
/// Ed25519 verifying keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSender {
    /// The Account the sending device belongs to.
    pub account: IdentId,
    /// The specific LocalIdentity (device/installation) that sent the message.
    pub local_identity: IdentId,
}

/// Failures decoding or verifying an account-bound credential.
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
    #[error("account endorsement of the local identity failed verification")]
    SignatureInvalid,
}

/// The bytes the Account signs to endorse `device` as one of its LocalIdentities.
///
/// `account` is folded in alongside the device key so the signature is bound to
/// the specific (account, device) pair, not just the device key in isolation.
fn endorsement_message(account: &Ed25519VerifyingKey, device: &Ed25519VerifyingKey) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CREDENTIAL_DOMAIN.len() + 32 + 32);
    msg.extend_from_slice(CREDENTIAL_DOMAIN);
    msg.extend_from_slice(account.as_ref());
    msg.extend_from_slice(device.as_ref());
    msg
}

/// Produce the Account's endorsement of `device`, using the Account's signing
/// capability. `sign` is the account authority's signer (a local key on testnet,
/// or an external wallet/enclave), so the closure is fallible.
pub fn endorse_local_identity<E>(
    account: &Ed25519VerifyingKey,
    device: &Ed25519VerifyingKey,
    sign: impl FnOnce(&[u8]) -> Result<Ed25519Signature, E>,
) -> Result<Ed25519Signature, E> {
    sign(&endorsement_message(account, device))
}

/// Encode the MLS credential content that binds a LocalIdentity to its Account.
///
/// The device key is *not* embedded: it is the leaf's signature key, supplied
/// out-of-band by MLS on the receiving side and passed to [`resolve_sender`].
///
/// ```text
/// domain      : CREDENTIAL_DOMAIN    (constant prefix, NUL-terminated)
/// version     : u8        (1 byte)
/// account_pub : [u8; 32]  (32 bytes)
/// endorsement : [u8; 64]  (64 bytes) — account signature over endorsement_message
/// ```
pub fn encode_credential(account: &Ed25519VerifyingKey, endorsement: &Ed25519Signature) -> Vec<u8> {
    let mut out = Vec::with_capacity(CREDENTIAL_DOMAIN.len() + 1 + 32 + 64);
    out.extend_from_slice(CREDENTIAL_DOMAIN);
    out.push(CREDENTIAL_VERSION);
    out.extend_from_slice(account.as_ref());
    out.extend_from_slice(endorsement.as_ref());
    out
}

/// Decode `credential_content` and verify the Account's endorsement against
/// `device_key` — the key the MLS leaf actually signs with. On success the
/// caller learns both the LocalIdentity (`device_key`) and the Account that
/// vouches for it.
pub fn resolve_sender(
    credential_content: &[u8],
    device_key: &Ed25519VerifyingKey,
) -> Result<MessageSender, CredentialError> {
    const HEADER: usize = 1 + 32 + 64;
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
    let sig_bytes: [u8; 64] = rest[33..97].try_into().expect("97 - 33 == 64");
    let endorsement = Ed25519Signature::from(sig_bytes);

    // Verifying under the account key, over a message that includes the *leaf's*
    // device key, is what binds this device to this account. A credential lifted
    // from another sender won't verify against the device key MLS hands us here.
    account
        .verify(&endorsement_message(&account, device_key), &endorsement)
        .map_err(|_| CredentialError::SignatureInvalid)?;

    Ok(MessageSender {
        account: IdentId::new(hex::encode(account.as_ref())),
        local_identity: IdentId::new(hex::encode(device_key.as_ref())),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;
    use std::convert::Infallible;

    /// Sign with the account key, resolve under the device key: both identities
    /// come back, hex-encoded.
    #[test]
    fn resolves_well_formed_credential() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();
        let device_key = Ed25519SigningKey::generate();
        let device_pub = device_key.verifying_key();

        let endorsement = endorse_local_identity::<Infallible>(&account_pub, &device_pub, |m| {
            Ok(account_key.sign(m))
        })
        .unwrap();
        let content = encode_credential(&account_pub, &endorsement);

        let sender = resolve_sender(&content, &device_pub).unwrap();
        assert_eq!(sender.account.as_str(), hex::encode(account_pub.as_ref()));
        assert_eq!(
            sender.local_identity.as_str(),
            hex::encode(device_pub.as_ref())
        );
    }

    /// On testnet the account key *is* the device key (one device == one
    /// account); resolution then reports the same id for both.
    #[test]
    fn single_key_account_resolves_to_itself() {
        let key = Ed25519SigningKey::generate();
        let pubkey = key.verifying_key();

        let endorsement =
            endorse_local_identity::<Infallible>(&pubkey, &pubkey, |m| Ok(key.sign(m))).unwrap();
        let content = encode_credential(&pubkey, &endorsement);

        let sender = resolve_sender(&content, &pubkey).unwrap();
        assert_eq!(sender.account, sender.local_identity);
    }

    /// An endorsement for device A, presented with device B's key (as MLS would
    /// hand it over if B forged a leaf), fails: the signature covers A's key.
    #[test]
    fn rejects_endorsement_for_a_different_device() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();
        let device_a = Ed25519SigningKey::generate().verifying_key();
        let device_b = Ed25519SigningKey::generate().verifying_key();

        let endorsement = endorse_local_identity::<Infallible>(&account_pub, &device_a, |m| {
            Ok(account_key.sign(m))
        })
        .unwrap();
        let content = encode_credential(&account_pub, &endorsement);

        assert!(matches!(
            resolve_sender(&content, &device_b),
            Err(CredentialError::SignatureInvalid)
        ));
    }

    #[test]
    fn rejects_missing_domain_short_and_bad_version() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();
        let device = Ed25519SigningKey::generate().verifying_key();
        let endorsement =
            endorse_local_identity::<Infallible>(
                &account_pub,
                &device,
                |m| Ok(account_key.sign(m)),
            )
            .unwrap();
        let content = encode_credential(&account_pub, &endorsement);

        // Strip the domain prefix.
        assert!(matches!(
            resolve_sender(&content[CREDENTIAL_DOMAIN.len()..], &device),
            Err(CredentialError::Domain)
        ));
        // Domain present but body truncated.
        let short = &content[..CREDENTIAL_DOMAIN.len() + 4];
        assert!(matches!(
            resolve_sender(short, &device),
            Err(CredentialError::Short)
        ));
        // Wrong version byte (first byte after the domain prefix).
        let mut bad_version = content.clone();
        bad_version[CREDENTIAL_DOMAIN.len()] = 99;
        assert!(matches!(
            resolve_sender(&bad_version, &device),
            Err(CredentialError::Version(99))
        ));
    }
}
