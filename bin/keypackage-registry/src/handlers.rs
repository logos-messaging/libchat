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
    /// User-chosen identity label. An account may span multiple devices,
    /// each with its own `device_pubkey`. Not derived from any key.
    pub account_id: String,
    /// Base64-encoded 32-byte Ed25519 verifying key for the submitting device.
    pub device_pubkey: String,
    /// Base64-encoded MLS KeyPackage bytes.
    pub key_package: String,
    pub timestamp_ms: u64,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    pub key_package: String,
    pub timestamp_ms: u64,
    /// Base64-encoded device pubkey of the returned bundle.
    pub device_pubkey: String,
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
    // No signature check — λLEZ-class identity authorization will land in
    // v0.3. For testnet we trust submissions; the chat layer will MLS-validate
    // the keypackage when it actually uses it.
    let device_pubkey = BASE64
        .decode(&req.device_pubkey)
        .map_err(|_| ApiError::bad("device_pubkey: not valid base64"))?;
    if device_pubkey.len() != 32 {
        return Err(ApiError::bad("device_pubkey: must be 32 bytes"));
    }
    let key_package = BASE64
        .decode(&req.key_package)
        .map_err(|_| ApiError::bad("key_package: not valid base64"))?;

    store
        .insert(
            &req.account_id,
            &StoredBundle {
                device_pubkey,
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
        device_pubkey: BASE64.encode(&bundle.device_pubkey),
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
