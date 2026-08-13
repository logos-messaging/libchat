use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex},
};

use crypto::Ed25519VerifyingKey;
use libchat::{IdentityProvider, RegistrationService};
use logos_account::{AccountAddr, AccountLogStore, AccountRegistry, SignedAccountLog, verify_log};

/// A Contact Registry used for Tests.
/// This implementation stores what it is given and returns it when retrieved.
///
/// Like the real `keypackage-registry`, one object serves both roles: a
/// keypackage store ([`RegistrationService`]) keyed by `device_id`, and the
/// account log store ([`AccountLogStore`] / [`AccountRegistry`]) keyed by
/// account address.
#[derive(Clone, Default)]
pub struct EphemeralRegistry {
    key_packages: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    accounts: Arc<Mutex<HashMap<AccountAddr, SignedAccountLog>>>,
}

impl EphemeralRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Debug for EphemeralRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registry = self.key_packages.lock().unwrap();
        let truncated: Vec<(&String, String)> = registry
            .iter()
            .map(|(k, v)| {
                let hex = if v.len() <= 8 {
                    hex::encode(v)
                } else {
                    format!(
                        "{}..{}",
                        hex::encode(&v[..4]),
                        hex::encode(&v[v.len() - 4..])
                    )
                };
                (k, hex)
            })
            .collect();
        f.debug_struct("EphemeralRegistry")
            .field("registry", &truncated)
            .finish()
    }
}

impl RegistrationService for EphemeralRegistry {
    type Error = String;

    fn register(
        &mut self,
        identity: &dyn IdentityProvider,
        key_bundle: Vec<u8>,
    ) -> Result<(), <Self as RegistrationService>::Error> {
        // Keyed by device id — the hex of the signer's verifying key — exactly
        // like the HTTP registry, so tests exercise the deployed keying.
        self.key_packages
            .lock()
            .unwrap()
            .insert(hex::encode(identity.public_key().as_ref()), key_bundle);
        Ok(())
    }

    fn retrieve(
        &self,
        device_id: &str,
    ) -> Result<Option<Vec<u8>>, <Self as RegistrationService>::Error> {
        Ok(self.key_packages.lock().unwrap().get(device_id).cloned())
    }
}

/// Stores whatever it is handed, like the untrusted service it stands in for.
impl AccountLogStore for EphemeralRegistry {
    type Error = String;

    fn publish_log(
        &mut self,
        addr: &AccountAddr,
        log: SignedAccountLog,
    ) -> Result<(), <Self as AccountLogStore>::Error> {
        self.accounts.lock().unwrap().insert(addr.clone(), log);
        Ok(())
    }
}

/// Verifies each log on read exactly as the HTTP client does, so callers
/// exercise the same trust path without a server.
impl AccountRegistry for EphemeralRegistry {
    type Error = String;

    fn endorsed_ed25519_keys(
        &self,
        addr: &AccountAddr,
    ) -> Result<Option<Vec<Ed25519VerifyingKey>>, <Self as AccountRegistry>::Error> {
        let Some(signed) = self.accounts.lock().unwrap().get(addr).cloned() else {
            return Ok(None);
        };
        let log = verify_log(addr, &signed).map_err(|e| e.to_string())?;
        log.endorsed_ed25519_keys()
            .map(Some)
            .map_err(|e| e.to_string())
    }
}
