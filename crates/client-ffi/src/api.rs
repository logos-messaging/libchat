use safer_ffi::prelude::*;
use std::sync::Arc;

use crate::delivery::{CDelivery, DeliverFn};
use client::{ChatClient, ClientError};

// ---------------------------------------------------------------------------
// Opaque client handle
// ---------------------------------------------------------------------------

#[derive_ReprC]
#[repr(opaque)]
pub struct ClientHandle(pub(crate) ChatClient<CDelivery>);

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

#[derive_ReprC]
#[repr(i32)]
pub enum ErrorCode {
    None = 0,
    BadUtf8 = -1,
    BadIntro = -2,
    DeliveryFail = -3,
    UnknownError = -4,
}

// ---------------------------------------------------------------------------
// Result types (opaque, heap-allocated via repr_c::Box)
// ---------------------------------------------------------------------------

#[derive_ReprC]
#[repr(opaque)]
pub struct CreateIntroResult {
    error_code: i32,
    data: Option<Vec<u8>>,
}

#[derive_ReprC]
#[repr(opaque)]
pub struct CreateConvoResult {
    error_code: i32,
    convo_id: Option<String>,
}

#[derive_ReprC]
#[repr(opaque)]
pub struct PushInboundResult {
    error_code: i32,
    has_content: bool,
    is_new_convo: bool,
    convo_id: Option<String>,
    content: Option<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Create an ephemeral in-memory client. Returns NULL if `callback` is None or
/// `name` is not valid UTF-8. Free with `client_destroy`.
#[ffi_export]
fn client_create(
    name: c_slice::Ref<'_, u8>,
    callback: DeliverFn,
) -> Option<repr_c::Box<ClientHandle>> {
    let name_str = match std::str::from_utf8(name.as_slice()) {
        Ok(s) => s,
        Err(_) => return None,
    };
    callback?;
    let delivery = CDelivery { callback };
    Some(Box::new(ClientHandle(ChatClient::new(name_str, delivery))).into())
}

/// Free a client handle. Must not be used after this call.
#[ffi_export]
fn client_destroy(handle: repr_c::Box<ClientHandle>) {
    drop(handle)
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/// Return the installation name as an owned byte slice.
/// Free with `client_installation_name_free`.
#[ffi_export]
fn client_installation_name(handle: &ClientHandle) -> c_slice::Box<u8> {
    handle
        .0
        .installation_name()
        .as_bytes()
        .to_vec()
        .into_boxed_slice()
        .into()
}

#[ffi_export]
fn client_installation_name_free(name: c_slice::Box<u8>) {
    drop(name)
}

// ---------------------------------------------------------------------------
// Intro bundle
// ---------------------------------------------------------------------------

/// Produce a serialised introduction bundle for out-of-band sharing.
/// Free with `create_intro_result_free`.
#[ffi_export]
fn client_create_intro_bundle(handle: &mut ClientHandle) -> repr_c::Box<CreateIntroResult> {
    let result = match handle.0.create_intro_bundle() {
        Ok(bytes) => CreateIntroResult {
            error_code: ErrorCode::None as i32,
            data: Some(bytes),
        },
        Err(_) => CreateIntroResult {
            error_code: ErrorCode::UnknownError as i32,
            data: None,
        },
    };
    Box::new(result).into()
}

#[ffi_export]
fn create_intro_result_error_code(r: &CreateIntroResult) -> i32 {
    r.error_code
}

/// Returns an empty slice when error_code != 0.
/// The slice is valid only while `r` is alive.
#[ffi_export]
fn create_intro_result_bytes(r: &CreateIntroResult) -> c_slice::Ref<'_, u8> {
    r.data.as_deref().unwrap_or(&[]).into()
}

#[ffi_export]
fn create_intro_result_free(r: repr_c::Box<CreateIntroResult>) {
    drop(r)
}

// ---------------------------------------------------------------------------
// Create conversation
// ---------------------------------------------------------------------------

/// Parse an intro bundle and initiate a private conversation.
/// Outbound envelopes are dispatched through the delivery callback.
/// Free with `create_convo_result_free`.
#[ffi_export]
fn client_create_conversation(
    handle: &mut ClientHandle,
    bundle: c_slice::Ref<'_, u8>,
    content: c_slice::Ref<'_, u8>,
) -> repr_c::Box<CreateConvoResult> {
    let result = match handle
        .0
        .create_conversation(bundle.as_slice(), content.as_slice())
    {
        Ok(convo_id) => CreateConvoResult {
            error_code: ErrorCode::None as i32,
            convo_id: Some(convo_id.to_string()),
        },
        Err(ClientError::Chat(_)) => CreateConvoResult {
            error_code: ErrorCode::BadIntro as i32,
            convo_id: None,
        },
        Err(ClientError::Delivery(_)) => CreateConvoResult {
            error_code: ErrorCode::DeliveryFail as i32,
            convo_id: None,
        },
    };
    Box::new(result).into()
}

#[ffi_export]
fn create_convo_result_error_code(r: &CreateConvoResult) -> i32 {
    r.error_code
}

/// Returns an empty slice when error_code != 0.
/// The slice is valid only while `r` is alive.
#[ffi_export]
fn create_convo_result_id(r: &CreateConvoResult) -> c_slice::Ref<'_, u8> {
    r.convo_id.as_deref().unwrap_or("").as_bytes().into()
}

#[ffi_export]
fn create_convo_result_free(r: repr_c::Box<CreateConvoResult>) {
    drop(r)
}

// ---------------------------------------------------------------------------
// Send message
// ---------------------------------------------------------------------------

/// Encrypt `content` and dispatch outbound envelopes. Returns an `ErrorCode`.
#[ffi_export]
fn client_send_message(
    handle: &mut ClientHandle,
    convo_id: c_slice::Ref<'_, u8>,
    content: c_slice::Ref<'_, u8>,
) -> ErrorCode {
    let id_str = match std::str::from_utf8(convo_id.as_slice()) {
        Ok(s) => s,
        Err(_) => return ErrorCode::BadUtf8,
    };
    let convo_id_owned: client::ConversationIdOwned = Arc::from(id_str);
    match handle.0.send_message(&convo_id_owned, content.as_slice()) {
        Ok(()) => ErrorCode::None,
        Err(ClientError::Delivery(_)) => ErrorCode::DeliveryFail,
        Err(_) => ErrorCode::UnknownError,
    }
}

// ---------------------------------------------------------------------------
// Push inbound
// ---------------------------------------------------------------------------

/// Decrypt an inbound payload. `has_content` is false for protocol frames.
/// Free with `push_inbound_result_free`.
#[ffi_export]
fn client_receive(
    handle: &mut ClientHandle,
    payload: c_slice::Ref<'_, u8>,
) -> repr_c::Box<PushInboundResult> {
    let result = match handle.0.receive(payload.as_slice()) {
        Ok(Some(cd)) => PushInboundResult {
            error_code: ErrorCode::None as i32,
            has_content: true,
            is_new_convo: cd.is_new_convo,
            convo_id: Some(cd.conversation_id),
            content: Some(cd.data),
        },
        Ok(None) => PushInboundResult {
            error_code: ErrorCode::None as i32,
            has_content: false,
            is_new_convo: false,
            convo_id: None,
            content: None,
        },
        Err(_) => PushInboundResult {
            error_code: ErrorCode::UnknownError as i32,
            has_content: false,
            is_new_convo: false,
            convo_id: None,
            content: None,
        },
    };
    Box::new(result).into()
}

#[ffi_export]
fn push_inbound_result_error_code(r: &PushInboundResult) -> i32 {
    r.error_code
}

#[ffi_export]
fn push_inbound_result_has_content(r: &PushInboundResult) -> bool {
    r.has_content
}

#[ffi_export]
fn push_inbound_result_is_new_convo(r: &PushInboundResult) -> bool {
    r.is_new_convo
}

/// Returns an empty slice when has_content is false.
/// The slice is valid only while `r` is alive.
#[ffi_export]
fn push_inbound_result_convo_id(r: &PushInboundResult) -> c_slice::Ref<'_, u8> {
    r.convo_id.as_deref().unwrap_or("").as_bytes().into()
}

/// Returns an empty slice when has_content is false.
/// The slice is valid only while `r` is alive.
#[ffi_export]
fn push_inbound_result_content(r: &PushInboundResult) -> c_slice::Ref<'_, u8> {
    r.content.as_deref().unwrap_or(&[]).into()
}

#[ffi_export]
fn push_inbound_result_free(r: repr_c::Box<PushInboundResult>) {
    drop(r)
}
