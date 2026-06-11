use safer_ffi::prelude::*;

use crossbeam_channel::{Receiver, Sender};

use crate::delivery::{CDelivery, DeliverFn};
use libchat::ChatError;
use logos_chat::{ChatClient, ClientError, ConversationClass, Event};

// ---------------------------------------------------------------------------
// Opaque client handle
// ---------------------------------------------------------------------------

#[derive_ReprC]
#[repr(opaque)]
pub struct ClientHandle {
    client: ChatClient<CDelivery>,
    events: Receiver<Event>,
    inbound: Sender<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

#[derive_ReprC]
#[repr(i32)]
pub enum ErrorCode {
    None = 0,
    BadUtf8 = -1,
    /// Failure parsing or processing an introduction bundle.
    BadIntro = -2,
    DeliveryFail = -3,
    UnknownError = -4,
    /// Failure decoding, decrypting, or processing an inbound payload.
    BadPayload = -5,
}

// ---------------------------------------------------------------------------
// Event taxonomy (C-side view of Event)
// ---------------------------------------------------------------------------

#[derive_ReprC]
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum EventKind {
    /// Sentinel returned by `event_list_kind_at` for out-of-bounds indices.
    /// Never the kind of a real event row.
    Invalid = -1,
    ConversationStarted = 0,
    MessageReceived = 1,
}

#[derive_ReprC]
#[repr(i32)]
#[derive(Clone, Copy)]
pub enum FfiConversationClass {
    /// Sentinel for accessor calls that don't apply to the queried row
    /// (out-of-bounds, or a non-`ConversationStarted` event).
    Invalid = -1,
    Private = 0,
    Group = 1,
}

impl From<ConversationClass> for FfiConversationClass {
    fn from(c: ConversationClass) -> Self {
        match c {
            ConversationClass::Private => FfiConversationClass::Private,
            ConversationClass::Group => FfiConversationClass::Group,
        }
    }
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

/// An ordered list of events with a status code. Inspect `error_code` (zero
/// on success) before iterating with `event_list_len` and the indexed
/// accessors.
#[derive_ReprC]
#[repr(opaque)]
pub struct EventList {
    error_code: i32,
    events: Vec<EventRow>,
}

enum EventRow {
    ConversationStarted {
        convo_id: String,
        class: FfiConversationClass,
    },
    MessageReceived {
        convo_id: String,
        content: Vec<u8>,
    },
}

impl EventRow {
    /// Translate an [`Event`] into the FFI row shape, or `None` for variants
    /// without an FFI representation.
    fn from_event(event: Event) -> Option<Self> {
        match event {
            Event::ConversationStarted {
                convo_id, class, ..
            } => Some(EventRow::ConversationStarted {
                convo_id: convo_id.to_string(),
                class: class.into(),
            }),
            Event::MessageReceived {
                convo_id, content, ..
            } => Some(EventRow::MessageReceived {
                convo_id: convo_id.to_string(),
                content,
            }),
            _ => None,
        }
    }

    fn convo_id(&self) -> &str {
        match self {
            EventRow::ConversationStarted { convo_id, .. }
            | EventRow::MessageReceived { convo_id, .. } => convo_id,
        }
    }

    fn content(&self) -> &[u8] {
        match self {
            EventRow::MessageReceived { content, .. } => content,
            _ => &[],
        }
    }
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
    let (inbound_tx, inbound_rx) = crossbeam_channel::unbounded();
    let delivery = CDelivery::new(callback, inbound_rx);
    let (client, events) = ChatClient::new(name_str, delivery);
    Some(
        Box::new(ClientHandle {
            client,
            events,
            inbound: inbound_tx,
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
        Ok(convo_id) => CreateConvoResult {
            error_code: ErrorCode::None as i32,
            convo_id: Some(convo_id),
        },
        Err(ClientError::Chat(ChatError::Delivery(_))) => CreateConvoResult {
            error_code: ErrorCode::DeliveryFail as i32,
            convo_id: None,
        },
        Err(ClientError::Chat(_)) => CreateConvoResult {
            error_code: ErrorCode::BadIntro as i32,
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
    match handle.client.send_message(id_str, content.as_slice()) {
        Ok(()) => ErrorCode::None,
        Err(ClientError::Chat(ChatError::Delivery(_))) => ErrorCode::DeliveryFail,
        Err(_) => ErrorCode::UnknownError,
    }
}

// ---------------------------------------------------------------------------
// Inbound (push wire payloads in, drain events out)
// ---------------------------------------------------------------------------

/// Feed an inbound payload (read off the wire by the host) to the client's
/// worker, which decrypts it and produces events for `client_poll_events`.
#[ffi_export]
fn client_push_inbound(handle: &ClientHandle, payload: c_slice::Ref<'_, u8>) {
    // Disconnected only if the worker has stopped; nothing to do then.
    let _ = handle.inbound.send(payload.as_slice().to_vec());
}

/// Drain every event the worker has produced since the last call. The list may
/// be empty. Free with `event_list_free`.
#[ffi_export]
fn client_poll_events(handle: &ClientHandle) -> repr_c::Box<EventList> {
    let events = handle
        .events
        .try_iter()
        .filter_map(EventRow::from_event)
        .collect();
    Box::new(EventList {
        error_code: ErrorCode::None as i32,
        events,
    })
    .into()
}

/// Block until the worker produces an event or `timeout_ms` elapses, then drain
/// everything available. Parks on the channel (no busy-wait); an empty list
/// means timeout or a stopped worker. Free with `event_list_free`.
#[ffi_export]
fn client_wait_events(handle: &ClientHandle, timeout_ms: u64) -> repr_c::Box<EventList> {
    let timeout = std::time::Duration::from_millis(timeout_ms);
    let mut events = Vec::new();
    if let Ok(first) = handle.events.recv_timeout(timeout) {
        events.extend(EventRow::from_event(first));
        events.extend(handle.events.try_iter().filter_map(EventRow::from_event));
    }
    Box::new(EventList {
        error_code: ErrorCode::None as i32,
        events,
    })
    .into()
}

#[ffi_export]
fn event_list_error_code(list: &EventList) -> i32 {
    list.error_code
}

#[ffi_export]
fn event_list_len(list: &EventList) -> usize {
    list.events.len()
}

/// Returns `EventKind::Invalid` for out-of-bounds indices.
#[ffi_export]
fn event_list_kind_at(list: &EventList, idx: usize) -> EventKind {
    match list.events.get(idx) {
        Some(EventRow::ConversationStarted { .. }) => EventKind::ConversationStarted,
        Some(EventRow::MessageReceived { .. }) => EventKind::MessageReceived,
        None => EventKind::Invalid,
    }
}

/// Returns an empty slice for out-of-bounds indices.
/// The slice is valid only while `list` is alive.
#[ffi_export]
fn event_list_convo_id_at(list: &EventList, idx: usize) -> c_slice::Ref<'_, u8> {
    list.events
        .get(idx)
        .map(|r| r.convo_id().as_bytes())
        .unwrap_or(&[])
        .into()
}

/// Returns an empty slice for non-`MessageReceived` events or out-of-bounds.
/// The slice is valid only while `list` is alive.
#[ffi_export]
fn event_list_content_at(list: &EventList, idx: usize) -> c_slice::Ref<'_, u8> {
    list.events
        .get(idx)
        .map(EventRow::content)
        .unwrap_or(&[])
        .into()
}

/// Returns `FfiConversationClass::Invalid` for non-`ConversationStarted`
/// events or out-of-bounds.
#[ffi_export]
fn event_list_conversation_class_at(list: &EventList, idx: usize) -> FfiConversationClass {
    match list.events.get(idx) {
        Some(EventRow::ConversationStarted { class, .. }) => *class,
        _ => FfiConversationClass::Invalid,
    }
}

#[ffi_export]
fn event_list_free(list: repr_c::Box<EventList>) {
    drop(list)
}
