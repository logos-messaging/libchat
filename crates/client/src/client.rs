use std::sync::Arc;

use libchat::{
    ChatError, ChatStorage, ConversationId, ConvoOutcome, Core, DeliveryService, InboxOutcome,
    Introduction, PayloadOutcome, RegistrationService, StorageConfig,
};

use components::EphemeralRegistry;
use logos_account::TestLogosAccount;

use crate::errors::ClientError;
use crate::event::Event;

pub struct ChatClient<D: DeliveryService, R: RegistrationService = EphemeralRegistry> {
    core: Core<(TestLogosAccount, D, R, ChatStorage)>,
}

// ── Default-registry constructors ────────────────────────────────────────────

impl<D: DeliveryService + 'static> ChatClient<D, EphemeralRegistry> {
    /// Create an in-memory, ephemeral client. Identity is lost on drop.
    pub fn new(name: impl Into<String>, delivery: D) -> Self {
        let registry = EphemeralRegistry::new();
        let store = ChatStorage::in_memory();
        let ident = TestLogosAccount::new(name);
        Self {
            core: Core::new_with_name(ident, delivery, registry, store).unwrap(),
        }
    }

    /// Open or create a persistent client backed by `StorageConfig`.
    ///
    /// If an identity already exists in storage it is loaded; otherwise a new
    /// one is created and saved.
    pub fn open(
        name: impl Into<String>,
        config: StorageConfig,
        delivery: D,
    ) -> Result<Self, ClientError> {
        let store = ChatStorage::new(config).map_err(ChatError::from)?;
        let registry = EphemeralRegistry::new();
        let ident = TestLogosAccount::new(name);
        let core = Core::new_from_store(ident, delivery, registry, store)?;
        Ok(Self { core })
    }
}

// ── Caller-supplied registry + shared methods ────────────────────────────────

impl<D, R> ChatClient<D, R>
where
    D: DeliveryService + 'static,
    R: RegistrationService + 'static,
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
        delivery: D,
        registry: R,
    ) -> Result<Self, ClientError> {
        let store = ChatStorage::new(config).map_err(ChatError::from)?;

        let ident = TestLogosAccount::new(name);
        let mut core = Core::new_from_store(ident, delivery, registry, store)?;
        core.register_keypackage()?;
        Ok(Self { core })
    }

    /// Returns the installation name (identity label) of this client.
    pub fn installation_name(&self) -> &str {
        self.core.installation_name()
    }

    /// Produce a serialised introduction bundle for sharing out-of-band.
    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ClientError> {
        self.core.create_intro_bundle().map_err(Into::into)
    }

    /// Parse intro bundle bytes and initiate a private conversation. Returns
    /// this side's conversation ID.
    pub fn create_conversation(
        &mut self,
        intro_bundle: &[u8],
        initial_content: &[u8],
    ) -> Result<ConversationId, ClientError> {
        let intro = Introduction::try_from(intro_bundle)?;
        self.core
            .create_private_convo(&intro, initial_content)
            .map_err(Into::into)
    }

    /// List all conversation IDs known to this client.
    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ClientError> {
        self.core.list_conversations().map_err(Into::into)
    }

    /// Encrypt and send `content` to an existing conversation.
    pub fn send_message(&mut self, convo_id: &str, content: &[u8]) -> Result<(), ClientError> {
        self.core
            .send_content(convo_id, content)
            .map_err(Into::into)
    }

    /// Decrypt an inbound payload. Returns the events the payload produced,
    /// in causal order. May be empty for protocol-only frames.
    pub fn receive(&mut self, payload: &[u8]) -> Result<Vec<Event>, ClientError> {
        let result = self.core.handle_payload(payload)?;
        Ok(events_from_inbound(result))
    }
}

/// Walk an [`PayloadOutcome`] in causal order and emit one `Event` per
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
