use safer_ffi::prelude::*;

// Must only contain negative values, values cannot be changed once set.
#[repr(i32)]
pub enum ErrorCode {
    None = 0,
    BadPtr = -1,
    BadConvoId = -2,
    BadIntro = -3,
    NotImplemented = -4,
    BufferExceeded = -5,
    UnknownError = -6,
}

use crate::context::{Context, Introduction};

/// Opaque wrapper for Context
#[derive_ReprC]
#[repr(opaque)]
pub struct ContextHandle(pub(crate) Context);

/// Creates a new libchat Ctx
///
/// # Returns
/// Opaque handle to the store. Must be freed with destroy_context()
#[ffi_export]
pub fn create_context() -> repr_c::Box<ContextHandle> {
    Box::new(ContextHandle(Context::new())).into()
}

/// Destroys a conversation store and frees its memory
///
/// # Safety
/// - handle must be a valid pointer from conversation_store_create()
/// - handle must not be used after this call
/// - handle must not be freed twice
#[ffi_export]
pub fn destroy_context(ctx: repr_c::Box<ContextHandle>) {
    drop(ctx);
}

/// Creates an intro bundle for sharing with other users
///
/// # Returns
/// Returns the number of bytes written to bundle_out
/// Check error_code field: 0 means success, negative values indicate errors (see ErrorCode).
#[ffi_export]
pub fn create_intro_bundle(ctx: &mut ContextHandle, mut bundle_out: c_slice::Mut<'_, u8>) -> i32 {
    let Ok(bundle) = ctx.0.create_intro_bundle() else {
        return ErrorCode::UnknownError as i32;
    };

    // Check buffer is large enough
    if bundle_out.len() < bundle.len() {
        return ErrorCode::BufferExceeded as i32;
    }

    bundle_out[..bundle.len()].copy_from_slice(&bundle);
    bundle.len() as i32
}

/// Creates a new private conversation
///
/// # Returns
/// Returns a struct with payloads that must be sent, the conversation_id that was created.
/// The NewConvoResult must be freed.
#[ffi_export]
pub fn create_new_private_convo(
    ctx: &mut ContextHandle,
    bundle: c_slice::Ref<'_, u8>,
    content: c_slice::Ref<'_, u8>,
) -> NewConvoResult {
    // Convert input bundle to Introduction
    let Ok(intro) = Introduction::try_from(bundle.as_slice()) else {
        return NewConvoResult {
            error_code: ErrorCode::BadIntro as i32,
            convo_id: "".into(),
            payloads: Vec::new().into(),
        };
    };

    // Convert input content to String
    let msg = String::from_utf8_lossy(&content).into_owned();

    // Create conversation
    let (convo_id, payloads) = ctx.0.create_private_convo(&intro, msg);

    // Convert payloads to FFI-compatible vector
    let ffi_payloads: Vec<Payload> = payloads
        .into_iter()
        .map(|p| Payload {
            address: p.delivery_address.into(),
            data: p.data.into(),
        })
        .collect();

    NewConvoResult {
        error_code: 0,
        convo_id: convo_id.to_string().into(),
        payloads: ffi_payloads.into(),
    }
}

/// Sends content to an existing conversation
///
/// # Returns
/// Returns a PayloadResult with payloads that must be delivered to participants.
/// Check error_code field: 0 means success, negative values indicate errors (see ErrorCode).
#[ffi_export]
pub fn send_content(
    ctx: &mut ContextHandle,
    convo_id: repr_c::String,
    content: c_slice::Ref<'_, u8>,
) -> PayloadResult {
    let payloads = match ctx.0.send_content(&convo_id, &content) {
        Ok(p) => p,
        Err(_) => {
            return PayloadResult {
                error_code: ErrorCode::UnknownError as i32,
                payloads: safer_ffi::Vec::EMPTY,
            };
        }
    };

    let ffi_payloads: Vec<Payload> = payloads
        .into_iter()
        .map(|p| Payload {
            address: p.delivery_address.into(),
            data: p.data.into(),
        })
        .collect();

    PayloadResult {
        error_code: 0,
        payloads: ffi_payloads.into(),
    }
}

/// Handles an incoming payload and writes content to caller-provided buffers
///
/// # Returns
/// Returns the number of bytes written to data_out on success (>= 0).
/// Returns negative error code on failure (see ErrorCode).
/// conversation_id_out_len is set to the number of bytes written to conversation_id_out.
#[ffi_export]
pub fn handle_payload(
    ctx: &mut ContextHandle,
    payload: c_slice::Ref<'_, u8>,
    mut conversation_id_out: c_slice::Mut<'_, u8>,
    conversation_id_out_len: Out<'_, u32>,
    mut content_out: c_slice::Mut<'_, u8>,
) -> i32 {
    match ctx.0.handle_payload(&payload) {
        Some(content) => {
            let convo_id_bytes = content.conversation_id.as_bytes();

            if conversation_id_out.len() < convo_id_bytes.len() {
                return ErrorCode::BufferExceeded as i32;
            }

            if content_out.len() < content.data.len() {
                return ErrorCode::BufferExceeded as i32;
            }

            conversation_id_out[..convo_id_bytes.len()].copy_from_slice(convo_id_bytes);
            conversation_id_out_len.write(convo_id_bytes.len() as u32);
            content_out[..content.data.len()].copy_from_slice(&content.data);

            content.data.len() as i32
        }
        None => 0,
    }
}

// ============================================================================
// safer_ffi implementation
// ===============================================================================================================================

/// Payload structure for FFI
#[derive(Debug)]
#[derive_ReprC]
#[repr(C)]
pub struct Payload {
    pub address: repr_c::String,
    pub data: repr_c::Vec<u8>,
}

/// Result structure for create_intro_bundle_safe
/// error_code is 0 on success, negative on error (see ErrorCode)
#[derive_ReprC]
#[repr(C)]
pub struct PayloadResult {
    pub error_code: i32,
    pub payloads: repr_c::Vec<Payload>,
}

/// Free the result from create_intro_bundle_safe
#[ffi_export]
pub fn destroy_payload_result(result: PayloadResult) {
    drop(result);
}

/// Result structure for create_new_private_convo_safe
/// error_code is 0 on success, negative on error (see ErrorCode)
#[derive_ReprC]
#[repr(C)]
pub struct NewConvoResult {
    pub error_code: i32,
    pub convo_id: repr_c::String,
    pub payloads: repr_c::Vec<Payload>,
}

/// Free the result from create_new_private_convo_safe
#[ffi_export]
pub fn destroy_convo_result(result: NewConvoResult) {
    drop(result);
}
