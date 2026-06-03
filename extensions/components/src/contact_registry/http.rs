use std::fmt::Debug;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use libchat::{IdentityProvider, RegistrationService};
use serde::{Deserialize, Serialize};

/// HTTP client for the testnet KeyPackage Registry service.
///
/// Throwaway transport for issue #110 — replaced by λLEZ in v0.3.
///
/// Bundles are self-signed by the device key. The server stores blindly; this
/// client verifies the signature on retrieve. Without the signature, a
/// republished bundle under a different `account_id` would be undetectable
/// pre-λLEZ — the signed payload commits to `account_id`, so the verifier
/// catches the mismatch.
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
    #[error("signature verification failed")]
    SignatureInvalid,
}

#[derive(Debug, Serialize)]
struct SubmitRequest {
    device_id: String,
    key_package: String,
    timestamp_ms: u64,
    signature: String,
}

#[derive(Debug, Deserialize)]
struct FetchResponse {
    key_package: String,
    timestamp_ms: u64,
    signature: String,
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
        // `device_id` is the hex-encoded ed25519 verifying key. Signing the
        // bundle with the matching key is proof-of-possession: only the holder
        // of this device key can publish under this `device_id`.
        let device_id = hex::encode(identity.public_key().as_ref());
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HttpRegistryError::Clock)?
            .as_millis() as u64;

        let message = signed_message(&device_id, &key_bundle, timestamp_ms);
        let signature = identity.sign(&message);

        let req = SubmitRequest {
            device_id,
            key_package: BASE64.encode(&key_bundle),
            timestamp_ms,
            signature: BASE64.encode(signature.as_ref()),
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

    fn retrieve(&self, device_id: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        let url = format!("{}/v0/keypackage/{}", self.base_url, device_id);
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

        // `device_id` is the hex-encoded ed25519 verifying key; recover the key
        // from it so the signature can be checked against the id alone.
        let device_pubkey_bytes =
            hex::decode(device_id).map_err(|e| HttpRegistryError::Decode(e.to_string()))?;
        let device_pubkey_arr: [u8; 32] = device_pubkey_bytes
            .as_slice()
            .try_into()
            .map_err(|_| HttpRegistryError::Decode("device_id not a 32-byte key".into()))?;
        let key_package = BASE64
            .decode(&body.key_package)
            .map_err(|e| HttpRegistryError::Decode(e.to_string()))?;
        let signature_bytes = BASE64
            .decode(&body.signature)
            .map_err(|e| HttpRegistryError::Decode(e.to_string()))?;
        let signature_arr: [u8; 64] = signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| HttpRegistryError::Decode("signature not 64 bytes".into()))?;

        let verifying_key = Ed25519VerifyingKey::from_bytes(&device_pubkey_arr)
            .map_err(|_| HttpRegistryError::Decode("device_id not a valid ed25519 vk".into()))?;
        let signature = Ed25519Signature::from(signature_arr);
        let message = signed_message(device_id, &key_package, body.timestamp_ms);
        verifying_key
            .verify(&message, &signature)
            .map_err(|_| HttpRegistryError::SignatureInvalid)?;

        Ok(Some(key_package))
    }
}

/// Canonical signing payload: `device_id || key_package || timestamp_ms_le`.
///
/// `device_id` is the hex-encoded ed25519 verifying key, so the signature is
/// proof-of-possession of the device key: only the holder of that key can
/// produce a bundle that verifies under it. Signer and verifier must build this
/// byte-for-byte identically. `timestamp_ms` is little-endian.
fn signed_message(device_id: &str, key_package: &[u8], timestamp_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(device_id.len() + key_package.len() + 8);
    out.extend_from_slice(device_id.as_bytes());
    out.extend_from_slice(key_package);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;

    /// Tampering with the key_package after signing breaks verification.
    #[test]
    fn signature_binds_key_package() {
        let signing = Ed25519SigningKey::generate();
        let verifying = signing.verifying_key();
        let device_id = hex::encode(verifying.as_ref());
        let timestamp_ms = 1_700_000_000_000u64;

        let original = b"original-keypackage".to_vec();
        let tampered = b"tampered-keypackage".to_vec();

        let msg = signed_message(&device_id, &original, timestamp_ms);
        let signature = signing.sign(&msg);

        let tampered_msg = signed_message(&device_id, &tampered, timestamp_ms);
        verifying
            .verify(&tampered_msg, &signature)
            .expect_err("signature must not verify against a different key_package");
    }

    /// End-to-end of the register/retrieve crypto wiring: the key recovered by
    /// hex-decoding the device_id verifies a signature produced at register
    /// time, exactly as `retrieve` does on the wire.
    #[test]
    fn sign_then_verify_via_device_id() {
        let signing = Ed25519SigningKey::generate();
        let verifying = signing.verifying_key();
        let key_package = b"fake-mls-keypackage-bytes".to_vec();
        let timestamp_ms = 1_700_000_000_000u64;

        // register side: sign over the canonical payload.
        let device_id = hex::encode(verifying.as_ref());
        let signature = signing.sign(&signed_message(&device_id, &key_package, timestamp_ms));

        // retrieve side: recover the key from device_id alone and verify.
        let recovered = hex::decode(&device_id).unwrap();
        let recovered_arr: [u8; 32] = recovered.as_slice().try_into().unwrap();
        let recovered_key = Ed25519VerifyingKey::from_bytes(&recovered_arr).unwrap();
        recovered_key
            .verify(
                &signed_message(&device_id, &key_package, timestamp_ms),
                &signature,
            )
            .expect("recovered key must verify the register-time signature");
    }
}
