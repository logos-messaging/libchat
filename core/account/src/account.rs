//! Test-only account and account-service implementations: in-memory
//! transport, production contract. The publish gate (signature, validity,
//! strict extension) is enforced exactly as a real service would.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};

use crate::{
    AccountAddr, AccountEntry, AccountError, AccountLog, AccountLogStore, AccountRegistry,
    EntryData, SignedAccountLog, verify_extension, verify_log,
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
}

/// The publish gate a real service runs: signature under the claimed address,
/// strict extension of whatever is already stored.
impl AccountLogStore for TestAccountService {
    type Error = AccountError;

    fn publish_log(
        &mut self,
        addr: &AccountAddr,
        log: SignedAccountLog,
    ) -> Result<(), Self::Error> {
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

    fn endorsed_ed25519_keys(
        &self,
        addr: &AccountAddr,
    ) -> Result<Option<Vec<Ed25519VerifyingKey>>, Self::Error> {
        let logs = self.logs.lock().expect("poisoned");
        let Some(signed) = logs.get(addr) else {
            return Ok(None);
        };
        Ok(Some(verify_log(addr, signed)?.endorsed_ed25519_keys()?))
    }
}

/// A test-focused account: its signing key, its working log, and the
/// [`AccountLogStore`] it publishes to. Every change goes to that store, so the
/// log this account extends and the log readers resolve are the same log.
///
/// Nothing is persisted: an account lives and dies with the process, so its
/// endorsements cannot be extended by a later run. Not for production.
pub struct TestLogosAccount<S> {
    signing_key: Ed25519SigningKey,
    addr: AccountAddr,
    log: AccountLog,
    store: S,
}

impl<S: AccountLogStore> TestLogosAccount<S> {
    /// A brand-new account publishing to `store`. Its key is freshly minted, so
    /// there is nothing published to read back.
    pub fn new(store: S) -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let addr = AccountAddr::from(&signing_key.verifying_key());
        Self {
            signing_key,
            addr,
            log: AccountLog::new(vec![]).expect("empty log is valid"),
            store,
        }
    }

    pub fn address(&self) -> &AccountAddr {
        &self.addr
    }

    /// Endorse `key` on this account: append it to the log, sign the log
    /// whole, and publish it — where readers resolve this account.
    pub fn endorse_ed25519_signer(
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
        self.store
            .publish_log(&self.addr, signed)
            .map_err(|e| AccountError::Generic(e.to_string()))?;
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

    /// endorse → the service it published to resolves the key for that account.
    #[test]
    fn endorsed_signer_is_resolvable() {
        let srv = TestAccountService::new();
        let mut account = TestLogosAccount::new(srv.clone());
        let dev = device();

        account.endorse_ed25519_signer(&dev).unwrap();

        assert!(srv.is_ed25519_endorsed(&dev, account.address()).unwrap());
        assert!(
            !srv.is_ed25519_endorsed(&device(), account.address())
                .unwrap()
        );
    }

    /// An account that never published is unknown, not empty.
    #[test]
    fn unpublished_account_is_unknown() {
        let srv = TestAccountService::new();
        let account = TestLogosAccount::new(srv.clone());
        assert!(
            srv.endorsed_ed25519_keys(account.address())
                .unwrap()
                .is_none()
        );
    }

    /// Each endorsement extends the log; the registry sees the full key set.
    #[test]
    fn endorsements_accumulate() {
        let srv = TestAccountService::new();
        let mut account = TestLogosAccount::new(srv.clone());
        let (a, b) = (device(), device());

        account.endorse_ed25519_signer(&a).unwrap();
        account.endorse_ed25519_signer(&b).unwrap();

        let keys = srv
            .endorsed_ed25519_keys(account.address())
            .unwrap()
            .unwrap();
        assert_eq!(keys, vec![a, b]);
    }

    /// The publish gate refuses a log signed by anyone but the account.
    #[test]
    fn publish_rejects_wrong_signer() {
        let mut srv = TestAccountService::new();
        let account = TestLogosAccount::new(srv.clone());
        let imposter = Ed25519SigningKey::generate();

        let payload = AccountLog::new(vec![]).unwrap().encode();
        let forged = SignedAccountLog {
            signature: imposter.sign(payload.as_bytes()),
            payload,
        };
        assert!(srv.publish_log(account.address(), forged).is_err());
    }
}
