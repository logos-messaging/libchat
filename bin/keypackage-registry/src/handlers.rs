use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::store::{Store, StoredBundle};

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
    // Server stores blindly — no signature verification here. Consumers
    // recover the key from `device_id` and verify on retrieve. This mirrors
    // the λLEZ design ("dumb storage, clients verify") for forward
    // compatibility.
    let device_pubkey =
        hex::decode(&req.device_id).map_err(|_| ApiError::bad("device_id: not valid hex"))?;
    if device_pubkey.len() != 32 {
        return Err(ApiError::bad("device_id: must be a 32-byte key"));
    }
    let key_package = BASE64
        .decode(&req.key_package)
        .map_err(|_| ApiError::bad("key_package: not valid base64"))?;
    let signature = BASE64
        .decode(&req.signature)
        .map_err(|_| ApiError::bad("signature: not valid base64"))?;
    if signature.len() != 64 {
        return Err(ApiError::bad("signature: must be 64 bytes"));
    }

    store
        .insert(
            &req.device_id,
            &StoredBundle {
                key_package,
                timestamp_ms: req.timestamp_ms,
                signature,
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
