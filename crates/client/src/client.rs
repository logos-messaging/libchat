use libchat::{
    AddressedEnvelope, ChatError, ChatStorage, ContentData, Context, ConversationIdOwned, RegistrationService
    DeliveryService, Introduction, StorageConfig,
};

use crate::errors::ClientError;

pub struct ChatClient<D: DeliveryService> {
    ctx: Context<D, EphemeralChatStorage>,
    delivery: D,
}

impl<D: DeliveryService, RS: RegistrationService, > ChatClient<D> {
    /// Create an in-memory, ephemeral client. Identity is lost on drop.
    pub fn new(name: impl Into<String>, delivery: D) -> Self {
        let store = ChatStorage::in_memory();
        Self {
            ctx: Context::new_with_name(name, store),
            delivery,
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
        let ctx = Context::new_from_store(name, store)?;
        Ok(Self { ctx, delivery })
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

    /// Decrypt an inbound payload. Returns `Some(ContentData)` for user
    /// content, `None` for protocol frames.
    pub fn receive(
        &mut self,
        payload: &[u8],
    ) -> Result<Option<ContentData>, ClientError<D::Error>> {
        self.ctx.handle_payload(payload).map_err(Into::into)
    }

    fn dispatch_all(
        &mut self,
        envelopes: Vec<AddressedEnvelope>,
    ) -> Result<(), ClientError<D::Error>> {
        for env in envelopes {
            self.delivery.publish(env).map_err(ClientError::Delivery)?;
        }
        Ok(())
    }
}
