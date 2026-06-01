use std::sync::Arc;

use libchat::{
    AddressedEnvelope, ChatError, ChatStorage, Context, ConversationId, ConvoOutcome,
    DeliveryService, InboxOutcome, Introduction, PayloadOutcome, StorageConfig,
};

use components::EphemeralRegistry;

use crate::errors::ClientError;
use crate::event::Event;

pub struct ChatClient<D: DeliveryService> {
    ctx: Context<D, EphemeralRegistry, ChatStorage>,
}

impl<D: DeliveryService + 'static> ChatClient<D> {
    /// Create an in-memory, ephemeral client. Identity is lost on drop.
    pub fn new(name: impl Into<String>, delivery: D) -> Self {
        let registry = EphemeralRegistry::new();
        let store = ChatStorage::in_memory();
        Self {
            ctx: Context::new_with_name(name, delivery, registry, store).unwrap(),
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
    ) -> Result<Self, ClientError<D::Error>> {
        let store = ChatStorage::new(config).map_err(ChatError::from)?;
        let registry = EphemeralRegistry::new();
        let ctx = Context::new_from_store(name, delivery, registry, store)?;
        Ok(Self { ctx })
    }

    /// Returns the installation name (identity label) of this client.
    pub fn installation_name(&self) -> &str {
        self.ctx.installation_name()
    }

    /// Produce a serialised introduction bundle for sharing out-of-band.
    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ClientError<D::Error>> {
        self.ctx.create_intro_bundle().map_err(Into::into)
    }

    /// Parse intro bundle bytes, initiate a private conversation, and deliver
    /// all outbound envelopes. Returns this side's conversation ID.
    pub fn create_conversation(
        &mut self,
        intro_bundle: &[u8],
        initial_content: &[u8],
    ) -> Result<ConversationId, ClientError<D::Error>> {
        let intro = Introduction::try_from(intro_bundle)?;
        let (convo_id, envelopes) = self.ctx.create_private_convo(&intro, initial_content)?;
        self.dispatch_all(envelopes)?;
        Ok(convo_id)
    }

    /// List all conversation IDs known to this client.
    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ClientError<D::Error>> {
        self.ctx.list_conversations().map_err(Into::into)
    }

    /// Encrypt `content` and dispatch all outbound envelopes.
    pub fn send_message(
        &mut self,
        convo_id: &str,
        content: &[u8],
    ) -> Result<(), ClientError<D::Error>> {
        let envelopes = self.ctx.send_content(convo_id, content)?;
        self.dispatch_all(envelopes)
    }

    /// Decrypt an inbound payload. Returns the events the payload produced,
    /// in causal order. May be empty for protocol-only frames.
    pub fn receive(&mut self, payload: &[u8]) -> Result<Vec<Event>, ClientError<D::Error>> {
        let result = self.ctx.handle_payload(payload)?;
        Ok(events_from_inbound(result))
    }

    fn dispatch_all(
        &mut self,
        envelopes: Vec<AddressedEnvelope>,
    ) -> Result<(), ClientError<D::Error>> {
        for env in envelopes {
            let mut delivery = self.ctx.ds();
            delivery.publish(env).map_err(ClientError::Delivery)?;
        }
        Ok(())
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
