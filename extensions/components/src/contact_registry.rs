use std::{
    collections::HashMap,
    fmt::Debug,
    sync::{Arc, Mutex},
};

use libchat::RegistrationService;

/// A Contact Registry used for Tests.
/// This implementation stores bundle bytes and then returns them when
/// retreived
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

    fn register(&mut self, identity: String, key_bundle: Vec<u8>) -> Result<(), Self::Error> {
        self.registry.lock().unwrap().insert(identity, key_bundle);
        Ok(())
    }

    fn retreive(&self, identity: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.registry.lock().unwrap().get(identity).cloned())
    }
}
