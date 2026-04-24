use std::cell::Ref;
use std::sync::Arc;
use std::{cell::RefCell, rc::Rc};

use crate::account::LogosAccount;
use crate::conversation::{Convo, GroupConvo, IdentityProvider};
use crate::ctx::ClientCtx;

use crate::{DeliveryService, RegistrationService};
use crate::{
    conversation::{Conversation, Id, PrivateV1Convo},
    errors::ChatError,
    inbox::Inbox,
    inbox_v2::InboxV2,
    proto::{EncryptedPayload, EnvelopeV1, Message},
    types::{AccountId, AddressedEnvelope, ContentData},
};
use crypto::{Identity, PublicKey};
use storage::{ChatStore, ConversationKind};

pub use crate::conversation::{ConversationId, ConversationIdOwned};
pub use crate::inbox::Introduction;

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context<DS: DeliveryService, RS: RegistrationService, CS: ChatStore> {
    identity: Rc<Identity>,
    client_ctx: ClientCtx<DS, RS, CS>,
    inbox: Inbox<CS>,
    pq_inbox: InboxV2,
    store: Rc<RefCell<CS>>,
}

impl<DS: DeliveryService, RS: RegistrationService, CS: ChatStore + 'static> Context<DS, RS, CS> {
    /// Opens or creates a Context with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created with the given name and saved.
    pub fn new_from_store(
        name: impl Into<String>,
        delivery: DS,
        contact_reg: RS,
        store: CS,
    ) -> Result<Self, ChatError> {
        let name = name.into();

        let store = Rc::new(RefCell::new(store));
        let mut ctx = ClientCtx::new(delivery, contact_reg, store.clone());

        // Load or create identity
        let identity = if let Some(identity) = store.borrow().load_identity()? {
            identity
        } else {
            let identity = Identity::new(&name);
            store.borrow_mut().save_identity(&identity)?;
            identity
        };

        let identity = Rc::new(identity);
        let inbox = Inbox::new(Rc::clone(&store), Rc::clone(&identity));

        let pq_inbox = InboxV2::new_with_account(LogosAccount::new_test(name));

        // Subscribe
        ctx.ds()
            .subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            identity: identity,
            client_ctx: ctx,
            inbox,
            pq_inbox,
            store,
        })
    }

    /// Creates a new in-memory Context (for testing).
    ///
    /// Uses in-memory SQLite database. Each call creates a new isolated database.
    pub fn new_with_name(
        name: impl Into<String>,
        delivery: DS,
        contact_reg: RS,
        chat_store: CS,
    ) -> Result<Self, ChatError> {
        let name = name.into();
        let identity = Identity::new(&name);

        let chat_store = Rc::new(RefCell::new(chat_store));
        let mut ctx = ClientCtx::new(delivery, contact_reg, chat_store.clone());
        chat_store
            .borrow_mut()
            .save_identity(&identity)
            .expect("in-memory storage should not fail");

        let identity = Rc::new(identity);
        let inbox = Inbox::new(Rc::clone(&chat_store), Rc::clone(&identity));
        let mut pq_inbox = InboxV2::new_with_account(LogosAccount::new_test(name));
        pq_inbox.register(&mut ctx)?;

        ctx.ds()
            .subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            identity,
            client_ctx: ctx,
            pq_inbox,
            inbox,

            store: chat_store,
        })
    }

    pub fn store(&self) -> Ref<'_, CS> {
        self.store.borrow()
    }

    pub fn client_ctx(&mut self) -> &mut ClientCtx<DS, RS, CS> {
        &mut self.client_ctx
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Returns the unique identifier associated with the account
    pub fn account_id(&self) -> &AccountId {
        self.pq_inbox.account_id()
    }

    pub fn installation_name(&self) -> &str {
        self.identity.get_name()
    }

    pub fn installation_key(&self) -> PublicKey {
        self.identity.public_key()
    }

    pub fn create_private_convo(
        &mut self,
        remote_bundle: &Introduction,
        content: &[u8],
    ) -> Result<(ConversationIdOwned, Vec<AddressedEnvelope>), ChatError> {
        let (mut convo, payloads) = self
            .inbox
            .invite_to_private_convo(remote_bundle, content, Rc::clone(&self.store))
            .unwrap_or_else(|_| todo!("Log/Surface Error"));

        let remote_id = Inbox::<CS>::inbox_identifier_for_key(*remote_bundle.installation_key());
        let payload_bytes = payloads
            .into_iter()
            .map(|p| p.into_envelope(remote_id.clone()))
            .collect();

        let convo_id = convo.persist()?;
        Ok((convo_id, payload_bytes))
    }

    pub fn create_group_convo(
        &mut self,
        participants: &[&AccountId],
    ) -> Result<Box<dyn GroupConvo<DS, RS, CS>>, ChatError> {
        let mut convo = self.pq_inbox.create_group_v1(&mut self.client_ctx)?;
        self.client_ctx
            .store()
            .save_conversation(&storage::ConversationMeta {
                local_convo_id: convo.id().to_string(),
                remote_convo_id: "0".into(),
                kind: ConversationKind::GroupV1,
            })?;
        convo.add_member(&mut self.client_ctx, participants)?;

        Ok(Box::new(convo))
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationIdOwned>, ChatError> {
        let records = self.store.borrow().load_conversations()?;
        Ok(records
            .into_iter()
            .map(|r| Arc::from(r.local_convo_id.as_str()))
            .collect())
    }

    pub fn send_content(
        &mut self,
        convo_id: ConversationId,
        content: &[u8],
    ) -> Result<Vec<AddressedEnvelope>, ChatError> {
        let mut convo = self.load_convo(convo_id)?;
        let payloads = convo.send_message(content)?;
        let remote_id = convo.remote_id();
        Ok(payloads
            .into_iter()
            .map(|p| p.into_envelope(remote_id.clone()))
            .collect())
    }

    // Decode bytes and send to protocol for processing.
    pub fn handle_payload(&mut self, payload: &[u8]) -> Result<Option<ContentData>, ChatError> {
        let env = EnvelopeV1::decode(payload)?;

        // TODO: Impl Conversation hinting
        let convo_id = env.conversation_hint;

        match convo_id {
            c if c == self.inbox.id() => self.dispatch_to_inbox(&env.payload),
            c if c == self.pq_inbox.id() => self.dispatch_to_inbox2(&env.payload),
            c if self.store.borrow().has_conversation(&c)? => {
                self.dispatch_to_convo(&c, &env.payload)
            }
            _ => Ok(Some(ContentData {
                conversation_id: "".into(),
                data: vec![],
                is_new_convo: false,
            })),
        }
    }

    // Dispatch encrypted payload to Inbox, and register the created Conversation
    fn dispatch_to_inbox(
        &mut self,
        enc_payload_bytes: &[u8],
    ) -> Result<Option<ContentData>, ChatError> {
        // EncryptedPayloads are not used by GroupConvos at this time, else this can be performed in `handle_payload`
        // TODO: (P1) reconcile envelope parsing between Covno and GroupConvo
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;
        let public_key_hex = Inbox::<CS>::extract_ephemeral_key_hex(&enc_payload)?;
        let (convo, content) =
            self.inbox
                .handle_frame(enc_payload, &public_key_hex, Rc::clone(&self.store))?;

        match convo {
            Conversation::Private(mut convo) => convo.persist()?,
        };

        self.store
            .borrow_mut()
            .remove_ephemeral_key(&public_key_hex)?;
        Ok(content)
    }

    // Dispatch encrypted payload to Inbox, and register the created Conversation
    fn dispatch_to_inbox2(&mut self, payload: &[u8]) -> Result<Option<ContentData>, ChatError> {
        self.pq_inbox.handle_frame(&mut self.client_ctx, payload)?;

        Ok(None)
    }

    // Dispatch encrypted payload to its corresponding conversation
    fn dispatch_to_convo(
        &mut self,
        convo_id: ConversationId,
        enc_payload_bytes: &[u8],
    ) -> Result<Option<ContentData>, ChatError> {
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;
        let mut convo = self.load_convo(convo_id)?;
        convo.handle_frame(enc_payload)
    }

    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        let intro = self.inbox.create_intro_bundle()?;
        Ok(intro.into())
    }

    pub fn get_convo(
        &mut self,
        convo_id: ConversationId,
    ) -> Result<Box<dyn GroupConvo<DS, RS, CS>>, ChatError> {
        self.load_group_convo(convo_id)
    }

    /// Loads a conversation from DB by constructing it from metadata.
    fn load_convo(&mut self, convo_id: ConversationId) -> Result<Box<dyn Convo>, ChatError> {
        let record = self
            .store
            .borrow()
            .load_conversation(convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))?;

        match record.kind {
            ConversationKind::PrivateV1 => {
                let private_convo = PrivateV1Convo::new(
                    self.store.clone(),
                    record.local_convo_id,
                    record.remote_convo_id,
                )?;
                Ok(Box::new(private_convo))
            }
            ConversationKind::GroupV1 => Ok(Box::new(
                self.pq_inbox
                    .load_mls_convo(&mut self.client_ctx, record.local_convo_id)?,
            )),
            ConversationKind::Unknown(_) => Err(ChatError::BadBundleValue(format!(
                "unsupported conversation type: {}",
                record.kind.as_str()
            ))),
        }
    }

    #[allow(unused)] // Temporary until GroupIntegration is completed
    fn load_group_convo(
        &mut self,
        convo_id: ConversationId,
    ) -> Result<Box<dyn GroupConvo<DS, RS, CS>>, ChatError> {
        let record = self
            .store
            .borrow()
            .load_conversation(convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))?;

        match record.kind {
            ConversationKind::PrivateV1 => {
                Err(ChatError::NoConvo("This is not a group convo".into()))
            }
            ConversationKind::GroupV1 => Ok(Box::new(
                self.pq_inbox
                    .load_mls_convo(&mut self.client_ctx, record.local_convo_id)?,
            )),
            ConversationKind::Unknown(_) => Err(ChatError::BadBundleValue(format!(
                "unsupported conversation type: {}",
                record.kind.as_str()
            ))),
        }
    }
}
