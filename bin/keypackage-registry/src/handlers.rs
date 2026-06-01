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

#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
    /// Base64-encoded 32-byte Ed25519 public key. The server derives
    /// `account_id = hex(pubkey)` and uses it as the storage key.
    pub pubkey: String,
    /// Base64-encoded MLS KeyPackage bytes.
    pub key_package: String,
    pub timestamp_ms: u64,
    /// Base64-encoded 64-byte Ed25519 signature over
    /// `pubkey || key_package || timestamp_ms_le`.
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    pub key_package: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/v0/keypackage", post(submit))
        .route("/v0/keypackage/:account_id", get(fetch))
        .with_state(store)
}

async fn submit(
    State(store): State<Arc<Store>>,
    Json(req): Json<SubmitRequest>,
) -> Result<StatusCode, ApiError> {
    let pubkey_bytes = BASE64
        .decode(&req.pubkey)
        .map_err(|_| ApiError::bad("pubkey: not valid base64"))?;
    let pubkey_arr: [u8; 32] = pubkey_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::bad("pubkey: must be 32 bytes"))?;

    // account_id is derived from pubkey, not supplied: ties identity to the
    // key so submissions can be verified locally without an external resolver.
    let account_id = hex::encode(pubkey_arr);

    let key_package = BASE64
        .decode(&req.key_package)
        .map_err(|_| ApiError::bad("key_package: not valid base64"))?;
    let signature_bytes = BASE64
        .decode(&req.signature)
        .map_err(|_| ApiError::bad("signature: not valid base64"))?;
    let signature_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ApiError::bad("signature: must be 64 bytes"))?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_arr)
        .map_err(|_| ApiError::bad("pubkey: not a valid ed25519 verifying key"))?;
    let signature = Signature::from_bytes(&signature_arr);

    let message = signed_message(&pubkey_arr, &key_package, req.timestamp_ms);
    verifying_key
        .verify_strict(&message, &signature)
        .map_err(|_| ApiError::bad("signature verification failed"))?;

    store
        .insert(
            &account_id,
            &StoredBundle {
                key_package,
                timestamp_ms: req.timestamp_ms,
            },
        )
        .map_err(ApiError::internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch(
    State(store): State<Arc<Store>>,
    Path(account_id): Path<String>,
) -> Result<Json<FetchResponse>, ApiError> {
    let Some(bundle) = store.latest(&account_id).map_err(ApiError::internal)? else {
        return Err(ApiError::not_found("no keypackage for account"));
    };
    Ok(Json(FetchResponse {
        key_package: BASE64.encode(&bundle.key_package),
        timestamp_ms: bundle.timestamp_ms,
    }))
}

/// Canonical signing payload. Clients and server must agree byte-for-byte.
/// `timestamp_ms` is little-endian to match the client signer.
pub fn signed_message(pubkey: &[u8; 32], key_package: &[u8], timestamp_ms: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + key_package.len() + 8);
    out.extend_from_slice(pubkey);
    out.extend_from_slice(key_package);
    out.extend_from_slice(&timestamp_ms.to_le_bytes());
    out
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
