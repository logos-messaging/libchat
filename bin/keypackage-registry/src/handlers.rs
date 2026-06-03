use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::store::{Store, StoredBundle};

/// Canonical signing payload — must stay byte-for-byte in sync with the client's
/// `signed_message` (`extensions/components/src/contact_registry/http.rs`):
/// `device_id || key_package || timestamp_ms_le`.
fn signed_message(device_id: &str, key_package: &[u8], timestamp_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(device_id.len() + key_package.len() + 8);
    out.extend_from_slice(device_id.as_bytes());
    out.extend_from_slice(key_package);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out
}

#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
    /// Hex-encoded 32-byte Ed25519 verifying key for the submitting device.
    /// This is the storage/lookup key.
    pub device_id: String,
    /// Base64-encoded MLS KeyPackage bytes.
    pub key_package: String,
    pub timestamp_ms: u64,
    /// Base64-encoded 64-byte Ed25519 signature by the device key over
    /// `device_id || key_package || timestamp_ms_le`. Verifying it under the key
    /// recovered from `device_id` is proof-of-possession: only the holder of the
    /// device key can publish under this `device_id`.
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    pub key_package: String,
    pub timestamp_ms: u64,
    /// Base64-encoded signature; consumers must verify before trusting.
    pub signature: String,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/v0/keypackage", post(submit))
        .route("/v0/keypackage/:device_id", get(fetch))
        .with_state(store)
}

async fn submit(
    State(store): State<Arc<Store>>,
    Json(req): Json<SubmitRequest>,
) -> Result<StatusCode, ApiError> {
    // Verify proof-of-possession before persisting: `device_id` is the
    // verifying key, so a valid signature means the submitter holds that key.
    // This rejects junk early (DoS mitigation). Consumers still verify on
    // retrieve — the server is not a trusted authority.
    let device_pubkey: [u8; 32] = hex::decode(&req.device_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::bad("device_id: must be hex of a 32-byte key"))?;
    let key_package = BASE64
        .decode(&req.key_package)
        .map_err(|_| ApiError::bad("key_package: not valid base64"))?;
    let signature: [u8; 64] = BASE64
        .decode(&req.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::bad("signature: must be base64 of 64 bytes"))?;

    let verifying_key = VerifyingKey::from_bytes(&device_pubkey)
        .map_err(|_| ApiError::bad("device_id: not a valid ed25519 key"))?;
    let message = signed_message(&req.device_id, &key_package, req.timestamp_ms);
    verifying_key
        .verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| ApiError::bad("signature: verification failed"))?;

    store
        .insert(
            &req.device_id,
            &StoredBundle {
                key_package,
                timestamp_ms: req.timestamp_ms,
                signature: signature.to_vec(),
            },
        )
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch(
    State(store): State<Arc<Store>>,
    Path(device_id): Path<String>,
) -> Result<Json<FetchResponse>, ApiError> {
    let Some(bundle) = store.latest(&device_id).map_err(ApiError::internal)? else {
        return Err(ApiError::not_found("no keypackage for device"));
    };
    Ok(Json(FetchResponse {
        key_package: BASE64.encode(&bundle.key_package),
        timestamp_ms: bundle.timestamp_ms,
        signature: BASE64.encode(&bundle.signature),
    }))
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
    fn internal<E: std::fmt::Display>(err: E) -> Self {
        tracing::error!("internal: {err}");
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "internal error".into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}
