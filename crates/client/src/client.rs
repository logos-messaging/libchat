use std::sync::Arc;
use std::thread::{self, JoinHandle};

use components::{EphemeralRegistry, ThreadedWakeupService, WakeupEvent};
use crossbeam_channel::{Receiver, Sender, select};
use libchat::{
    ChatError, ChatStorage, ConversationId, ConvoOutcome, Core, DeliveryService, InboxOutcome,
    Introduction, PayloadOutcome, RegistrationService, StorageConfig,
};
use logos_account::TestLogosAccount;
use parking_lot::Mutex;

use crate::errors::ClientError;
use crate::event::Event;

type ClientCore<T, R> = Core<(TestLogosAccount, T, R, ThreadedWakeupService, ChatStorage)>;

/// The transport as the client sees it: a [`DeliveryService`] for outbound
/// publishing plus the inbound payload stream the worker drains. One object owns
/// both directions of the boundary.
pub trait Transport: DeliveryService + Send + 'static {
    /// Hand over the inbound payload stream. Called once, at client construction,
    /// before the [`Core`] takes ownership of the service.
    fn inbound(&mut self) -> Receiver<Vec<u8>>;
}

/// High-level chat client.
///
/// Owns the synchronous [`Core`] behind an `Arc<Mutex<…>>` and a background
/// worker that consumes inbound payloads off the transport's channel, drives
/// the core, and forwards observations as [`Event`]s. Construction returns the
/// handle together with the `Receiver<Event>` the application drains on its own
/// schedule.
///
/// Outbound calls (`send_message`, `create_conversation`, …) run on the
/// caller's thread: they briefly lock the core, invoke it, and return — no
/// message-passing round-trip. The `Arc`/`Mutex`/threads live entirely here;
/// the core never mentions threads.
pub struct ChatClient<T: DeliveryService, R: RegistrationService = EphemeralRegistry> {
    /// `parking_lot::Mutex` for its eventual fairness: an inbound burst can't
    /// starve caller operations of the lock.
    core: Arc<Mutex<ClientCore<T, R>>>,
    /// Dropped on `Drop` to wake the worker's `select!` and shut it down.
    shutdown: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

// ── Default-registry constructors ────────────────────────────────────────────

impl<T: Transport> ChatClient<T, EphemeralRegistry> {
    /// Create an in-memory, ephemeral client. Identity is lost on drop.
    pub fn new(name: impl Into<String>, mut transport: T) -> (Self, Receiver<Event>) {
        let inbound = transport.inbound();
        let ident = TestLogosAccount::new(name);
        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let core = Core::new_with_name(
            ident,
            transport,
            EphemeralRegistry::new(),
            wakeup_service,
            ChatStorage::in_memory(),
        )
        .unwrap();
        Self::spawn(core, inbound, wakeup_rx)
    }

    /// Open or create a persistent client backed by `StorageConfig`.
    ///
    /// If an identity already exists in storage it is loaded; otherwise a new
    /// one is created and saved.
    pub fn open(
        name: impl Into<String>,
        config: StorageConfig,
        mut transport: T,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let store = ChatStorage::new(config).map_err(ChatError::from)?;
        let inbound = transport.inbound();
        let ident = TestLogosAccount::new(name);
        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let core = Core::new_from_store(
            ident,
            transport,
            EphemeralRegistry::new(),
            wakeup_service,
            store,
        )?;
        Ok(Self::spawn(core, inbound, wakeup_rx))
    }
}

// ── Caller-supplied registry + shared methods ────────────────────────────────

impl<T, R> ChatClient<T, R>
where
    T: DeliveryService + Send + 'static,
    R: RegistrationService + Send + 'static,
{
    /// Open or create a persistent client with a caller-supplied registration
    /// service. Use this to swap in a network-backed registry (e.g. the
    /// testnet KeyPackage Registry) in place of the default in-memory store.
    ///
    /// Submits this account's KeyPackage to the registry as the last step of
    /// construction. The default in-memory `open` path skips this call, but
    /// when a real registry is wired in we want each session to publish so
    /// other clients can fetch it.
    pub fn open_with_registry(
        name: impl Into<String>,
        config: StorageConfig,
        mut transport: T,
        registry: R,
    ) -> Result<(Self, Receiver<Event>), ClientError>
    where
        T: Transport,
    {
        let store = ChatStorage::new(config).map_err(ChatError::from)?;
        let inbound = transport.inbound();
        let ident = TestLogosAccount::new(name);
        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let mut core = Core::new_from_store(ident, transport, registry, wakeup_service, store)?;
        core.register_keypackage()?;
        Ok(Self::spawn(core, inbound, wakeup_rx))
    }

    fn spawn(
        core: ClientCore<T, R>,
        inbound: Receiver<Vec<u8>>,
        wakeup_events: Receiver<WakeupEvent>,
    ) -> (Self, Receiver<Event>) {
        let core = Arc::new(Mutex::new(core));
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(0);

        let worker = thread::spawn({
            let core = Arc::clone(&core);
            move || worker_loop(core, inbound, wakeup_events, shutdown_rx, event_tx)
        });

        (
            Self {
                core,
                shutdown: Some(shutdown_tx),
                worker: Some(worker),
            },
            event_rx,
        )
    }

    /// Returns the installation name (identity label) of this client.
    pub fn installation_name(&self) -> String {
        self.core.lock().installation_name().to_string()
    }

    /// Produce a serialised introduction bundle for sharing out-of-band.
    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ClientError> {
        self.core.lock().create_intro_bundle().map_err(Into::into)
    }

    /// Parse intro bundle bytes and initiate a private conversation. Outbound
    /// envelopes are published by the core. Returns this side's conversation ID.
    pub fn create_conversation(
        &mut self,
        intro_bundle: &[u8],
        initial_content: &[u8],
    ) -> Result<ConversationId, ClientError> {
        let intro = Introduction::try_from(intro_bundle)?;
        self.core
            .lock()
            .create_private_convo(&intro, initial_content)
            .map_err(Into::into)
    }

    /// List all conversation IDs known to this client.
    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ClientError> {
        self.core.lock().list_conversations().map_err(Into::into)
    }

    /// Encrypt and send `content` to an existing conversation. The core
    /// publishes the outbound envelope.
    pub fn send_message(&mut self, convo_id: &str, content: &[u8]) -> Result<(), ClientError> {
        self.core
            .lock()
            .send_content(convo_id, content)
            .map_err(Into::into)
    }
}

impl<T: DeliveryService, R: RegistrationService> Drop for ChatClient<T, R> {
    fn drop(&mut self) {
        // Dropping the sender disconnects the worker's shutdown channel, waking
        // its `select!` so it can exit; then we join it.
        self.shutdown.take();
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

/// Background loop: block until an inbound payload or shutdown arrives, drive
/// the core on each payload, and forward events. No polling — `select!` parks
/// the thread until one of the channels is ready.
fn worker_loop<T, R>(
    core: Arc<Mutex<ClientCore<T, R>>>,
    inbound: Receiver<Vec<u8>>,
    wakeup_events: Receiver<WakeupEvent>,
    shutdown: Receiver<()>,
    event_tx: Sender<Event>,
) where
    T: DeliveryService + Send + 'static,
    R: RegistrationService + Send + 'static,
{
    loop {
        select! {
            recv(inbound) -> msg => {
                let Ok(bytes) = msg else {
                    return; // transport's sender dropped
                };
                let events = {
                    let mut core = core.lock();
                    match core.handle_payload(&bytes) {
                        Ok(outcome) => events_from_inbound(outcome),
                        Err(e) => {
                            tracing::warn!("inbound handle_payload failed: {e:?}");
                            vec![Event::InboundError {
                                message: e.to_string(),
                            }]
                        }
                    }
                };
                for event in events {
                    if event_tx.send(event).is_err() {
                        return; // application dropped the receiver
                    }
                }
            }
            recv(wakeup_events) -> msg => {
                let Ok(WakeupEvent { convo_id }) = msg else {
                    return; // wakeup service's sender dropped
                };
                if let Err(e) = core.lock().wakeup(&convo_id) {
                    tracing::warn!("wakeup failed: {e:?}");
                }
            }
            recv(shutdown) -> _ => return,
        }
    }
}

/// Walk a [`PayloadOutcome`] in causal order and emit one `Event` per
/// observation. For an `Inbox` outcome, [`Event::ConversationStarted`]
/// precedes the message event. The convo id is wrapped into `Arc<str>` once
/// per outcome and shared across the events it produces.
fn events_from_inbound(result: PayloadOutcome) -> Vec<Event> {
    match result {
        PayloadOutcome::Empty => Vec::new(),
        PayloadOutcome::Convo(co) => convo_events(co),
        PayloadOutcome::Inbox(io) => inbox_events(io),
    }
}

fn convo_events(outcome: ConvoOutcome) -> Vec<Event> {
    let ConvoOutcome { convo_id, content } = outcome;
    content
        .map(|c| Event::MessageReceived {
            convo_id: Arc::from(convo_id),
            content: c.bytes,
        })
        .into_iter()
        .collect()
}

fn inbox_events(outcome: InboxOutcome) -> Vec<Event> {
    let InboxOutcome {
        new_conversation,
        initial,
    } = outcome;
    let id: Arc<str> = Arc::from(new_conversation.convo_id);
    let mut events = Vec::with_capacity(2);
    events.push(Event::ConversationStarted {
        convo_id: Arc::clone(&id),
        class: new_conversation.class,
    });
    if let Some(c) = initial.and_then(|co| co.content) {
        events.push(Event::MessageReceived {
            convo_id: Arc::clone(&id),
            content: c.bytes,
        });
    }
    events
}
