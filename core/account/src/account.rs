//! Test-only account and account-service implementations: in-memory
//! transport, production contract. The publish gate (signature, validity,
//! strict extension) is enforced exactly as a real service would.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};

use crate::{
    AccountAddr, AccountEntry, AccountError, AccountLog, AccountRegistry, EntryData,
    SignedAccountLog, verify_extension, verify_log,
};

/// Logs "published" by accounts, keyed by address.
type SharedLogs = Arc<Mutex<HashMap<AccountAddr, SignedAccountLog>>>;

/// In-memory account service: the shared backend for a fleet of test
/// accounts, and the registry that answers questions about them.
#[derive(Clone, Debug, Default)]
pub struct TestAccountService {
    logs: SharedLogs,
}

impl TestAccountService {
    pub fn new() -> Self {
        Self::default()
    }

    /// A new account publishing to this service's shared backend.
    pub fn account(&self) -> TestLogosAccount {
        TestLogosAccount::with_service(self.clone())
    }

    /// The publish gate a real service runs: signature under the claimed
    /// address, strict extension of whatever is already stored.
    fn publish(&self, addr: &AccountAddr, log: SignedAccountLog) -> Result<(), AccountError> {
        verify_log(addr, &log)?;
        let mut logs = self.logs.lock().expect("poisoned");
        if let Some(previous) = logs.get(addr) {
            verify_extension(&previous.payload, &log.payload)?;
        }
        logs.insert(addr.clone(), log);
        Ok(())
    }
}

impl AccountRegistry for TestAccountService {
    type Error = AccountError;

    fn associated_ed25519_keys(
        &self,
        addr: &AccountAddr,
    ) -> Result<Option<Vec<Ed25519VerifyingKey>>, Self::Error> {
        let logs = self.logs.lock().expect("poisoned");
        let Some(signed) = logs.get(addr) else {
            return Ok(None);
        };
        let log = verify_log(addr, signed)?;
        log.live_entries()
            .iter()
            .filter_map(|data| match data {
                EntryData::Ed25519Key(bytes) => Some(
                    // A signed log endorsing a non-key is the account's error,
                    // not a lookup miss — surface it rather than skip it.
                    Ed25519VerifyingKey::from_bytes(bytes)
                        .map_err(|_| AccountError::Generic("endorsed key is invalid".into())),
                ),
                EntryData::Text(_) => None,
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some)
    }
}

/// A test-focused account: holds its signing key and working log, publishes
/// through a [`TestAccountService`]. Not persisted; not for production.
pub struct TestLogosAccount {
    signing_key: Ed25519SigningKey,
    addr: AccountAddr,
    log: AccountLog,
    service: TestAccountService,
}

impl TestLogosAccount {
    /// An account with its own private backend.
    pub fn new() -> Self {
        TestAccountService::new().account()
    }

    fn with_service(service: TestAccountService) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&signing_key.verifying_key());
        Self {
            signing_key,
            addr,
            log: AccountLog::new(vec![]).expect("empty log is valid"),
            service,
        }
    }
}

impl Default for TestLogosAccount {
    fn default() -> Self {
        Self::new()
    }
}

// Inherent for now — the write-side trait (AccountProvider) is parked in
// lib.rs; these become its impl when it lands.
impl TestLogosAccount {
    pub fn address(&self) -> &AccountAddr {
        &self.addr
    }

    pub fn associate_ed25519_signer(
        &mut self,
        key: &Ed25519VerifyingKey,
    ) -> Result<(), AccountError> {
        let device = key.as_ref().try_into().expect("ed25519 keys are 32 bytes");
        let mut entries = self.log.entries().to_vec();
        entries.push(AccountEntry::Add(EntryData::Ed25519Key(device)));

        // Sign-side validation gate: never sign a log that does not replay.
        let log = AccountLog::new(entries)?;
        let payload = log.encode();
        let signed = SignedAccountLog {
            signature: self.signing_key.sign(payload.as_bytes()),
            payload,
        };
        self.service.publish(&self.addr, signed)?;
        self.log = log;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> Ed25519VerifyingKey {
        Ed25519SigningKey::generate().verifying_key()
    }

    /// associate → the shared service resolves the key for that account.
    #[test]
    fn associated_signer_is_resolvable() {
        let srv = TestAccountService::new();
        let mut account = srv.account();
        let dev = device();

        account.associate_ed25519_signer(&dev).unwrap();

        assert!(srv.is_ed25519_associated(&dev, account.address()).unwrap());
        assert!(
            !srv.is_ed25519_associated(&device(), account.address())
                .unwrap()
        );
    }

    /// An account that never published is unknown, not empty.
    #[test]
    fn unpublished_account_is_unknown() {
        let srv = TestAccountService::new();
        let account = srv.account();
        assert!(
            srv.associated_ed25519_keys(account.address())
                .unwrap()
                .is_none()
        );
    }

    /// Each associate extends the log; the registry sees the full key set.
    #[test]
    fn associations_accumulate() {
        let srv = TestAccountService::new();
        let mut account = srv.account();
        let (a, b) = (device(), device());

        account.associate_ed25519_signer(&a).unwrap();
        account.associate_ed25519_signer(&b).unwrap();

        let keys = srv
            .associated_ed25519_keys(account.address())
            .unwrap()
            .unwrap();
        assert_eq!(keys, vec![a, b]);
    }

    /// The publish gate refuses a log signed by anyone but the account.
    #[test]
    fn publish_rejects_wrong_signer() {
        let srv = TestAccountService::new();
        let account = srv.account();
        let imposter = Ed25519SigningKey::generate();

        let payload = AccountLog::new(vec![]).unwrap().encode();
        let forged = SignedAccountLog {
            signature: imposter.sign(payload.as_bytes()),
            payload,
        };
        assert!(srv.publish(account.address(), forged).is_err());
    }
}
