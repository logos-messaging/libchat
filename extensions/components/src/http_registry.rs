use std::fmt::Debug;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use libchat::{AccountId, IdentityProvider, RegistrationService};
use serde::{Deserialize, Serialize};

/// HTTP client for the testnet KeyPackage Registry service.
///
/// Throwaway transport for issue #110 — replaced by λLEZ in v0.3.
///
/// Submissions are not signed. The schema accommodates multiple devices per
/// `account_id`, but Scope A (one device per account) is what the chat layer
/// supports today; `retrieve` returns the latest device's keypackage.
#[derive(Clone)]
pub struct HttpRegistry {
    base_url: String,
    http: reqwest::blocking::Client,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpRegistryError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned status {0}: {1}")]
    Server(u16, String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("clock before unix epoch")]
    Clock,
}

#[derive(Debug, Serialize)]
struct SubmitRequest<'a> {
    account_id: &'a str,
    device_pubkey: String,
    key_package: String,
    timestamp_ms: u64,
}

#[derive(Debug, Deserialize)]
struct FetchResponse {
    key_package: String,
    #[allow(dead_code)]
    timestamp_ms: u64,
    #[allow(dead_code)]
    device_pubkey: String,
}

impl HttpRegistry {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_timeout(base_url, Duration::from_secs(10))
    }

    pub fn with_timeout(base_url: impl Into<String>, timeout: Duration) -> Self {
        let http = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .build()
            .expect("reqwest client builder is infallible with these options");
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }
}

impl Debug for HttpRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRegistry")
            .field("base_url", &self.base_url)
            .finish()
    }
}

impl RegistrationService for HttpRegistry {
    type Error = HttpRegistryError;

    fn register(
        &mut self,
        identity: &dyn IdentityProvider,
        key_bundle: Vec<u8>,
    ) -> Result<(), Self::Error> {
        let account_id = identity.account_id().as_str();
        let device_pubkey: &[u8] = identity.public_key().as_ref();
        if device_pubkey.len() != 32 {
            return Err(HttpRegistryError::Decode(
                "public_key not 32 bytes".into(),
            ));
        }

        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HttpRegistryError::Clock)?
            .as_millis() as u64;

        let req = SubmitRequest {
            account_id,
            device_pubkey: BASE64.encode(device_pubkey),
            key_package: BASE64.encode(&key_bundle),
            timestamp_ms,
        };

        let url = format!("{}/v0/keypackage", self.base_url);
        let resp = self.http.post(&url).json(&req).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(HttpRegistryError::Server(status, body));
        }
        Ok(())
    }

    fn retrieve(&self, identity: &AccountId) -> Result<Option<Vec<u8>>, Self::Error> {
        let url = format!("{}/v0/keypackage/{}", self.base_url, identity.as_str());
        let resp = self.http.get(&url).send()?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(HttpRegistryError::Server(status, body));
        }
        let body: FetchResponse = resp.json()?;
        let bytes = BASE64
            .decode(body.key_package)
            .map_err(|e| HttpRegistryError::Decode(e.to_string()))?;
        Ok(Some(bytes))
    }
}
