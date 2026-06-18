use std::fmt::Debug;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto::{Ed25519Signature, Ed25519VerifyingKey};
use libchat::{
    AccountService, BundleError, DeviceSet, IdentityProvider, RegistrationService,
    SignedDeviceBundle, verify_bundle,
};
use serde::{Deserialize, Serialize};

/// HTTP client for the testnet KeyPackage Registry service.
///
/// Throwaway transport for issue #110 — replaced by λLEZ in v0.3.
///
/// The wire carries `device_id` (the hex device verifying key), an opaque
/// `payload` blob, and its `signature`. The signed bytes and the transmitted
/// `payload` bytes are identical, so every verifier checks the signature over
/// exactly what it received — no field-by-field reconstruction to keep in sync.
/// The `payload` is opaque to the server: it verifies `signature` over `payload`
/// with `device_id`'s key (proof-of-possession — only the holder of that key can
/// publish under `device_id`) without decoding the payload.
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
    #[error("bundle: {0}")]
    Bundle(#[from] BundleError),
}

#[derive(Debug, Serialize)]
struct SubmitRequest {
    /// hex of the 32-byte device verifying key — the verification + storage key.
    device_id: String,
    /// base64 of the canonical signed payload (see [`encode_payload`]).
    payload: String,
    /// base64 of the 64-byte Ed25519 signature over `payload`.
    signature: String,
}

#[derive(Debug, Deserialize)]
struct FetchResponse {
    payload: String,
    signature: String,
}

#[derive(Debug, Serialize)]
struct SubmitAccountRequest {
    /// hex of the 32-byte account verifying key — verification + storage key.
    account_pub: String,
    /// base64 of the canonical signed device-list payload.
    payload: String,
    /// base64 of the 64-byte account signature over `payload`.
    signature: String,
}

#[derive(Debug, Deserialize)]
struct FetchAccountResponse {
    payload: String,
    signature: String,
    #[allow(dead_code)] // server's prune clock; freshness is taken from the bundle's lamport
    updated_at: i64,
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
    ) -> Result<(), HttpRegistryError> {
        let device_id = hex::encode(identity.public_key().as_ref());
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| HttpRegistryError::Clock)?
            .as_millis() as u64;

        // Sign exactly the bytes that go on the wire.
        let payload = encode_payload(timestamp_ms, &key_bundle);
        let signature = identity.sign(&payload);

        let req = SubmitRequest {
            device_id,
            payload: BASE64.encode(&payload),
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

    fn retrieve(&self, device_id: &str) -> Result<Option<Vec<u8>>, HttpRegistryError> {
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

        let payload = BASE64
            .decode(&body.payload)
            .map_err(|e| HttpRegistryError::Decode(e.to_string()))?;
        let signature_arr: [u8; 64] = BASE64
            .decode(&body.signature)
            .map_err(|e| HttpRegistryError::Decode(e.to_string()))?
            .as_slice()
            .try_into()
            .map_err(|_| HttpRegistryError::Decode("signature not 64 bytes".into()))?;

        // Verify over the received payload bytes, using the key we asked for
        // (`device_id`). A bundle the requested device didn't sign won't verify.
        let device_pubkey: [u8; 32] = hex::decode(device_id)
            .map_err(|e| HttpRegistryError::Decode(e.to_string()))?
            .as_slice()
            .try_into()
            .map_err(|_| HttpRegistryError::Decode("device_id not a 32-byte key".into()))?;
        let verifying_key = Ed25519VerifyingKey::from_bytes(&device_pubkey)
            .map_err(|_| HttpRegistryError::Decode("device_id not a valid ed25519 vk".into()))?;
        verifying_key
            .verify(&payload, &Ed25519Signature::from(signature_arr))
            .map_err(|_| HttpRegistryError::SignatureInvalid)?;

        let (_timestamp_ms, key_package) = decode_payload(&payload)
            .ok_or_else(|| HttpRegistryError::Decode("short payload".into()))?;

        Ok(Some(key_package.to_vec()))
    }
}

impl AccountService for HttpRegistry {
    type Error = HttpRegistryError;

    fn publish(&mut self, bundle: &SignedDeviceBundle) -> Result<(), Self::Error> {
        let req = SubmitAccountRequest {
            account_pub: hex::encode(bundle.account_pub.as_ref()),
            payload: BASE64.encode(&bundle.payload),
            signature: BASE64.encode(bundle.signature.as_ref()),
        };

        let url = format!("{}/v0/account", self.base_url);
        let resp = self.http.post(&url).json(&req).send()?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(HttpRegistryError::Server(status, body));
        }
        Ok(())
    }

    fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error> {
        let url = format!(
            "{}/v0/account/{}",
            self.base_url,
            hex::encode(account.as_ref())
        );
        let resp = self.http.get(&url).send()?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().unwrap_or_default();
            return Err(HttpRegistryError::Server(status, body));
        }
        let body: FetchAccountResponse = resp.json()?;

        let payload = BASE64
            .decode(&body.payload)
            .map_err(|e| HttpRegistryError::Decode(e.to_string()))?;
        let signature_arr: [u8; 64] = BASE64
            .decode(&body.signature)
            .map_err(|e| HttpRegistryError::Decode(e.to_string()))?
            .as_slice()
            .try_into()
            .map_err(|_| HttpRegistryError::Decode("signature not 64 bytes".into()))?;

        // The directory service is untrusted: verify the account signature over
        // the exact received bytes, and that the bundle is bound to the account
        // we asked for, before handing back any device keys.
        let bundle = SignedDeviceBundle {
            account_pub: account.clone(),
            payload,
            signature: Ed25519Signature::from(signature_arr),
        };
        let device_set = verify_bundle(account, &bundle)?;
        Ok(Some(device_set))
    }
}

/// Canonical binary payload — the bytes that are both signed and transmitted
/// verbatim. Opaque to the server; decoded only by consumers:
///
/// ```text
/// timestamp_ms : u64 little-endian (8 bytes)
/// key_package  : remaining bytes (variable, last → no length prefix needed)
/// ```
///
/// The fixed-width field first with the one variable field last makes every
/// byte string parse exactly one way — no delimiter, no ambiguity, even though
/// `key_package` is arbitrary bytes. The device verifying key is carried
/// alongside as `device_id`, not embedded here.
fn encode_payload(timestamp_ms: u64, key_package: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + key_package.len());
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out.extend_from_slice(key_package);
    out
}

/// Inverse of [`encode_payload`]. Returns `None` if the payload is shorter than
/// the fixed header (`8`).
fn decode_payload(payload: &[u8]) -> Option<(u64, &[u8])> {
    if payload.len() < 8 {
        return None;
    }
    let timestamp_ms = u64::from_le_bytes(payload[..8].try_into().ok()?);
    Some((timestamp_ms, &payload[8..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;

    /// `encode_payload` / `decode_payload` round-trip, including a key_package
    /// containing bytes that a delimiter scheme would choke on (`:`, `|`, NUL).
    #[test]
    fn payload_roundtrips_with_arbitrary_bytes() {
        let ts = 1_700_000_000_000u64;
        let key_package = b"mls:bytes|with\x00delimiters".to_vec();

        let payload = encode_payload(ts, &key_package);
        let (got_ts, got_kp) = decode_payload(&payload).unwrap();
        assert_eq!(got_ts, ts);
        assert_eq!(got_kp, key_package.as_slice());
    }

    #[test]
    fn decode_rejects_short_payload() {
        assert!(decode_payload(&[0u8; 7]).is_none());
    }

    /// Tampering with any byte of the payload breaks verification.
    #[test]
    fn signature_binds_payload() {
        let signing = Ed25519SigningKey::generate();
        let verifying = signing.verifying_key();

        let payload = encode_payload(1_700_000_000_000, b"original-keypackage");
        let signature = signing.sign(&payload);

        let tampered = encode_payload(1_700_000_000_000, b"tampered-keypackage");
        verifying
            .verify(&tampered, &signature)
            .expect_err("signature must not verify against a different payload");
    }

    /// End-to-end of the wire crypto: verify over the received payload bytes
    /// using the key recovered from device_id, exactly as `retrieve` does.
    #[test]
    fn sign_then_verify_over_payload() {
        let signing = Ed25519SigningKey::generate();
        let pubkey: [u8; 32] = signing.verifying_key().as_ref().try_into().unwrap();
        let payload = encode_payload(1_700_000_000_000, b"fake-mls-keypackage-bytes");
        let signature = signing.sign(&payload);

        // retrieve side: recover key from device_id (hex of pubkey), verify payload.
        let device_id = hex::encode(pubkey);
        let recovered: [u8; 32] = hex::decode(&device_id)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap();
        Ed25519VerifyingKey::from_bytes(&recovered)
            .unwrap()
            .verify(&payload, &signature)
            .expect("recovered key must verify the register-time signature");
    }
}
