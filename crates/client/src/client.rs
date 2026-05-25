use libchat::{
    AddressedEnvelope, ChatError, ChatStorage, Context, ConversationIdOwned, ConversationKind,
    DeliveryService, InboundResult, Introduction, StorageConfig,
};

use components::EphemeralRegistry;

use crate::errors::ClientError;
use crate::event::{ConversationClass, Event};

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
    ) -> Result<ConversationIdOwned, ClientError<D::Error>> {
        let intro = Introduction::try_from(intro_bundle)?;
        let (convo_id, envelopes) = self.ctx.create_private_convo(&intro, initial_content)?;
        self.dispatch_all(envelopes)?;
        Ok(convo_id)
    }

    /// List all conversation IDs known to this client.
    pub fn list_conversations(&self) -> Result<Vec<ConversationIdOwned>, ClientError<D::Error>> {
        self.ctx.list_conversations().map_err(Into::into)
    }

    /// Encrypt `content` and dispatch all outbound envelopes.
    pub fn send_message(
        &mut self,
        convo_id: &ConversationIdOwned,
        content: &[u8],
    ) -> Result<(), ClientError<D::Error>> {
        let envelopes = self.ctx.send_content(convo_id.as_ref(), content)?;
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

/// Walk an [`InboundResult`] in causal order and emit one `Event` per
/// observation. The structural ordering of `InboundResult` (new conversation
/// before frame contents) determines the order of events here.
fn events_from_inbound(result: InboundResult) -> Vec<Event> {
    let mut events = Vec::with_capacity(
        usize::from(result.new_conversation.is_some()) + result.frame.messages.len(),
    );
    if let Some(nc) = result.new_conversation
        && let Some(class) = class_from_kind(&nc.kind)
    {
        events.push(Event::ConversationStarted {
            convo_id: nc.convo_id,
            class,
        });
    }
    for msg in result.frame.messages {
        events.push(Event::MessageReceived {
            convo_id: msg.convo_id,
            content: msg.content,
        });
    }
    events
}

/// Map a core [`ConversationKind`] to the coarse app-facing
/// [`ConversationClass`]. The exhaustive match means a new
/// `ConversationKind` variant becomes a compile error here, forcing a
/// deliberate mapping decision rather than silently misclassifying it.
/// `Unknown(_)` yields `None`: the client does not surface conversations
/// whose protocol kind cannot be safely classified for the application.
fn class_from_kind(kind: &ConversationKind) -> Option<ConversationClass> {
    match kind {
        ConversationKind::PrivateV1 => Some(ConversationClass::Private),
        ConversationKind::GroupV1 => Some(ConversationClass::Group),
        ConversationKind::Unknown(_) => None,
    }
}
