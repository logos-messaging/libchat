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
    let s = String::from_utf8_lossy(&bundle).to_string();
    let Ok(intro) = Introduction::try_from(s) else {
        return NewConvoResult {
            error_code: ErrorCode::BadIntro as i32,
            convo_id: 0,
            payloads: Vec::new().into(),
        };
    };

    // Convert input content to String
    let msg = String::from_utf8_lossy(&content).into_owned();

    // Create conversation
    let (convo_handle, payloads) = ctx.0.create_private_convo(&intro, msg);

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
        convo_id: convo_handle,
        payloads: ffi_payloads.into(),
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
    pub convo_id: u32,
    pub payloads: repr_c::Vec<Payload>,
}

/// Free the result from create_new_private_convo_safe
#[ffi_export]
pub fn destroy_convo_result(result: NewConvoResult) {
    drop(result);
}
