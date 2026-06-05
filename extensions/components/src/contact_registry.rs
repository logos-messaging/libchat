use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex},
};

use libchat::{
    AccountDirectory, AccountId, DeviceSet, IdentityProvider, RegistrationService,
    SignedDeviceBundle, verify_bundle,
};

pub mod http;

/// A Contact Registry used for Tests.
/// This implementation stores bundle bytes and then returns them when
/// retrieved
///

#[derive(Clone)]
pub struct EphemeralRegistry {
    registry: Arc<Mutex<HashMap<String, Vec<u8>>>>,
}

impl EphemeralRegistry {
    pub fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Default for EphemeralRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for EphemeralRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let registry = self.registry.lock().unwrap();
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
    ) -> Result<(), Self::Error> {
        self.registry
            .lock()
            .unwrap()
            .insert(identity.account_id().to_string(), key_bundle);
        Ok(())
    }

    fn retrieve(&self, device_id: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.registry.lock().unwrap().get(device_id).cloned())
    }
}

/// An in-memory [`AccountDirectory`] for tests — the account-bundle analogue of
/// [`EphemeralRegistry`]. Stores one signed bundle per account and verifies it
/// on `fetch`, exactly as the HTTP client does, so callers exercise the same
/// trust path without a running server.
#[derive(Clone, Default)]
pub struct EphemeralAccountDirectory {
    bundles: Arc<Mutex<HashMap<String, SignedDeviceBundle>>>,
}

impl EphemeralAccountDirectory {
    pub fn new() -> Self {
        Self::default()
    }
}

impl Debug for EphemeralAccountDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bundles = self.bundles.lock().unwrap();
        f.debug_struct("EphemeralAccountDirectory")
            .field("accounts", &bundles.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl AccountDirectory for EphemeralAccountDirectory {
    type Error = String;

    fn publish(&mut self, bundle: &SignedDeviceBundle) -> Result<(), Self::Error> {
        self.bundles
            .lock()
            .unwrap()
            .insert(bundle.account_id.to_string(), bundle.clone());
        Ok(())
    }

    fn fetch(&self, account: &AccountId) -> Result<Option<DeviceSet>, Self::Error> {
        let Some(bundle) = self.bundles.lock().unwrap().get(account.as_str()).cloned() else {
            return Ok(None);
        };
        verify_bundle(account, &bundle)
            .map(Some)
            .map_err(|e| e.to_string())
    }
}
