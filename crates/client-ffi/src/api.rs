use safer_ffi::prelude::*;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use crate::delivery::{CDelivery, DeliverFn};
use logos_chat::{ChatClient, ClientError, Event};

// ---------------------------------------------------------------------------
// Opaque client handle
// ---------------------------------------------------------------------------

#[derive_ReprC]
#[repr(opaque)]
pub struct ClientHandle {
    client: ChatClient<CDelivery>,
    push_tx: mpsc::Sender<Vec<u8>>,
    event_rx: Mutex<mpsc::Receiver<Event>>,
}

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
pub struct EventList {
    error_code: i32,
    events: Vec<Event>,
}

#[derive_ReprC]
#[repr(i32)]
pub enum EventTag {
    /// A new conversation was started (responder side).
    ConversationStarted = 0,
    /// User content was received on an existing conversation.
    MessageReceived = 1,
    /// Delivery of a previously-sent envelope failed.
    DeliveryFailed = 2,
    /// Returned when the index is out of bounds or the variant is unknown to
    /// this binary (e.g. a new `Event` variant from a newer library version).
    Unknown = -1,
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

/// Create an ephemeral in-memory client. Returns NULL if `callback` is None or
/// `name` is not valid UTF-8. Free with `client_destroy`.
///
/// Inbound bytes are fed via `client_push_inbound`; events are consumed via
/// `client_drain_events`.
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
    let (delivery, push_tx) = CDelivery::new(callback);
    let (client, event_rx) = ChatClient::new(name_str, delivery);
    Some(
        Box::new(ClientHandle {
            client,
            push_tx,
            event_rx: Mutex::new(event_rx),
        })
        .into(),
    )
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
        .client
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
    let result = match handle.client.create_intro_bundle() {
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
        .client
        .create_conversation(bundle.as_slice(), content.as_slice())
    {
        Ok((convo_id, events)) => {
            let error_code = if events.iter().any(Event::is_delivery_failure) {
                ErrorCode::DeliveryFail as i32
            } else {
                ErrorCode::None as i32
            };
            CreateConvoResult {
                error_code,
                convo_id: Some(convo_id.to_string()),
            }
        }
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
    let convo_id_owned: logos_chat::ConversationIdOwned = Arc::from(id_str);
    match handle
        .client
        .send_message(&convo_id_owned, content.as_slice())
    {
        Ok(events) if events.iter().any(Event::is_delivery_failure) => ErrorCode::DeliveryFail,
        Ok(_) => ErrorCode::None,
        Err(ClientError::Delivery(_)) => ErrorCode::DeliveryFail,
        Err(_) => ErrorCode::UnknownError,
    }
}

// ---------------------------------------------------------------------------
// Inbound + event drain
// ---------------------------------------------------------------------------

/// Queue an inbound payload for processing. Events surfaced from it are
/// observed via `client_drain_events`. Returns 0 on success, negative on
/// shutdown.
#[ffi_export]
fn client_push_inbound(handle: &mut ClientHandle, payload: c_slice::Ref<'_, u8>) -> i32 {
    match handle.push_tx.send(payload.as_slice().to_vec()) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// Wait up to `timeout_ms` for the next event and then drain everything else
/// that's currently buffered. Returns an `EventList` (possibly empty on
/// timeout). Free with `event_list_free`.
#[ffi_export]
fn client_drain_events(handle: &mut ClientHandle, timeout_ms: u64) -> repr_c::Box<EventList> {
    let rx = handle.event_rx.lock().unwrap();
    let timeout = Duration::from_millis(timeout_ms);
    let Ok(first) = rx.recv_timeout(timeout) else {
        return Box::new(EventList {
            error_code: ErrorCode::None as i32,
            events: Vec::new(),
        })
        .into();
    };
    let mut events = vec![first];
    // Brief settle window so events from the same payload arrive together
    // rather than across separate drain calls.
    std::thread::sleep(Duration::from_micros(500));
    while let Ok(e) = rx.try_recv() {
        events.push(e);
    }
    Box::new(EventList {
        error_code: ErrorCode::None as i32,
        events,
    })
    .into()
}

#[ffi_export]
fn event_list_error_code(r: &EventList) -> i32 {
    r.error_code
}

#[ffi_export]
fn event_list_len(r: &EventList) -> usize {
    r.events.len()
}

/// Returns the variant tag for the event at `idx`, or `EventTag::Unknown`
/// if `idx` is out of bounds.
#[ffi_export]
fn event_list_tag(r: &EventList, idx: usize) -> EventTag {
    match r.events.get(idx) {
        Some(Event::ConversationStarted { .. }) => EventTag::ConversationStarted,
        Some(Event::MessageReceived { .. }) => EventTag::MessageReceived,
        Some(Event::DeliveryFailed { .. }) => EventTag::DeliveryFailed,
        _ => EventTag::Unknown,
    }
}

/// Returns the conversation id (UTF-8 bytes) for the event at `idx`,
/// or an empty slice if `idx` is out of bounds.
/// The slice is valid only while `r` is alive.
#[ffi_export]
fn event_list_conversation_id(r: &EventList, idx: usize) -> c_slice::Ref<'_, u8> {
    let bytes: &[u8] = match r.events.get(idx) {
        Some(
            Event::ConversationStarted {
                conversation_id, ..
            }
            | Event::MessageReceived {
                conversation_id, ..
            }
            | Event::DeliveryFailed {
                conversation_id, ..
            },
        ) => conversation_id.as_bytes(),
        _ => &[],
    };
    bytes.into()
}

/// Returns the message bytes for a `MessageReceived` event at `idx`.
/// Returns an empty slice for any other variant or out-of-bounds index.
/// The slice is valid only while `r` is alive.
#[ffi_export]
fn event_list_message_data(r: &EventList, idx: usize) -> c_slice::Ref<'_, u8> {
    let bytes: &[u8] = match r.events.get(idx) {
        Some(Event::MessageReceived { data, .. }) => data.as_slice(),
        _ => &[],
    };
    bytes.into()
}

#[ffi_export]
fn event_list_free(r: repr_c::Box<EventList>) {
    drop(r)
}
