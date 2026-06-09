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

use crate::store::{Store, StoredAccountBundle, StoredKeyPackageBundle};

#[derive(Debug, Deserialize)]
pub struct SubmitRequest {
    /// Hex of the 32-byte Ed25519 device verifying key. Used to verify the
    /// signature and as the storage/lookup key. `payload` stays opaque.
    pub device_id: String,
    /// base64 of the signed payload. Opaque to the server — it never decodes it.
    pub payload: String,
    /// base64 of the 64-byte Ed25519 signature over `payload`. Verifying it
    /// under `device_id`'s key is proof-of-possession: only the holder of that
    /// key can publish under this `device_id`.
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct FetchResponse {
    /// base64 of the stored payload; consumers verify `signature` over it.
    pub payload: String,
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
        .route("/v0/account", post(submit_account))
        .route("/v0/account/:account_id", get(fetch_account))
        .with_state(store)
}

async fn submit(
    State(store): State<Arc<Store>>,
    Json(req): Json<SubmitRequest>,
) -> Result<StatusCode, ApiError> {
    // Verify proof-of-possession before persisting. `payload` is opaque — the
    // server only checks that `signature` over the received payload bytes is
    // valid under `device_id`'s key. A valid signature means the submitter holds
    // that key. This rejects junk early (DoS mitigation); consumers still verify
    // on retrieve, the server is not a trusted authority.
    let device_pubkey: [u8; 32] = hex::decode(&req.device_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::bad("device_id: must be hex of a 32-byte key"))?;
    let payload = BASE64
        .decode(&req.payload)
        .map_err(|_| ApiError::bad("payload: not valid base64"))?;
    let signature: [u8; 64] = BASE64
        .decode(&req.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::bad("signature: must be base64 of 64 bytes"))?;

    let verifying_key = VerifyingKey::from_bytes(&device_pubkey)
        .map_err(|_| ApiError::bad("device_id: not a valid ed25519 key"))?;
    verifying_key
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| ApiError::bad("signature: verification failed"))?;

    store
        .insert(
            &req.device_id,
            &StoredKeyPackageBundle {
                payload,
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
        payload: BASE64.encode(&bundle.payload),
        signature: BASE64.encode(&bundle.signature),
    }))
}

/// Request body for publishing a signed device-list bundle under an account.
///
/// The `payload` is intentionally opaque to the server. Clients are expected
/// to encode a lamport-timestamped list of device (LocalIdentity) Ed25519
/// public keys inside it so that consumers can detect stale bundles. The server
/// only verifies that `signature` is a valid Ed25519 signature over `payload`
/// made by the key identified by `account_id`.
#[derive(Debug, Deserialize)]
pub struct SubmitAccountRequest {
    /// Hex of the 32-byte Ed25519 account (AccountAddress) verifying key.
    /// Acts as both the storage key and the verification key.
    pub account_id: String,
    /// base64 of the opaque signed payload (lamport-ts + device pubkeys, etc.).
    pub payload: String,
    /// base64 of the 64-byte Ed25519 signature over `payload` made by the
    /// account key. Proof-of-possession: only the account holder can publish.
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct FetchAccountResponse {
    /// base64 of the stored payload.
    pub payload: String,
    /// base64 of the 64-byte Ed25519 signature.
    pub signature: String,
    /// Unix timestamp (ms) of the last successful upsert.
    pub updated_at: i64,
}

/// `POST /v0/account` — upsert a signed device-list bundle for an account.
///
/// The server verifies the Ed25519 signature and then stores exactly one blob
/// per `account_id`, replacing any previous value. Clients should re-publish
/// whenever they add or rotate LocalIdentities.
async fn submit_account(
    State(store): State<Arc<Store>>,
    Json(req): Json<SubmitAccountRequest>,
) -> Result<StatusCode, ApiError> {
    let account_pubkey: [u8; 32] = hex::decode(&req.account_id)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::bad("account_id: must be hex of a 32-byte key"))?;
    let payload = BASE64
        .decode(&req.payload)
        .map_err(|_| ApiError::bad("payload: not valid base64"))?;
    let signature: [u8; 64] = BASE64
        .decode(&req.signature)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| ApiError::bad("signature: must be base64 of 64 bytes"))?;

    let verifying_key = VerifyingKey::from_bytes(&account_pubkey)
        .map_err(|_| ApiError::bad("account_id: not a valid ed25519 key"))?;
    verifying_key
        .verify_strict(&payload, &Signature::from_bytes(&signature))
        .map_err(|_| ApiError::bad("signature: verification failed"))?;

    // Read the bundle's lamport so the store can reject replays. Safe to trust:
    // the signature over `payload` was just verified, so the lamport can't be
    // forged without the account key.
    let lamport = crate::store::payload_lamport(&payload)
        .ok_or_else(|| ApiError::bad("payload: too short to contain a lamport header"))?;

    let applied = store
        .upsert_account(
            &req.account_id,
            lamport,
            &StoredAccountBundle {
                payload,
                signature: signature.to_vec(),
                updated_at: 0, // filled in by store
            },
        )
        .map_err(ApiError::internal)?;
    if !applied {
        return Err(ApiError::conflict(
            "stale bundle: lamport is not newer than the stored one",
        ));
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `GET /v0/account/:account_id` — fetch the device-list bundle for an account.
///
/// Returns the latest published bundle so consumers can verify the
/// account signature and decode the list of LocalIdentity keys themselves.
async fn fetch_account(
    State(store): State<Arc<Store>>,
    Path(account_id): Path<String>,
) -> Result<Json<FetchAccountResponse>, ApiError> {
    let Some(bundle) = store.get_account(&account_id).map_err(ApiError::internal)? else {
        return Err(ApiError::not_found("no account bundle for account_id"));
    };
    Ok(Json(FetchAccountResponse {
        payload: BASE64.encode(&bundle.payload),
        signature: BASE64.encode(&bundle.signature),
        updated_at: bundle.updated_at,
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
    fn conflict(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
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
