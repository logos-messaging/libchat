use std::sync::{Arc, Mutex, MutexGuard};

use crate::account::LogosAccount;
use crate::conversation::{Convo, GroupConvo};

use crate::{DeliveryService, RegistrationService};
use crate::{
    conversation::{Conversation, Id, PrivateV1Convo},
    errors::ChatError,
    event::Event,
    inbox::Inbox,
    inbox_v2::InboxV2,
    proto::{EncryptedPayload, EnvelopeV1, Message},
    types::AccountId,
};
use crypto::{Identity, PublicKey};
use storage::{ChatStore, ConversationKind};

pub use crate::conversation::{ConversationId, ConversationIdOwned};
pub use crate::inbox::Introduction;

/// Delivery address used by the legacy PrivateV1 inbox path. Consumers must
/// subscribe to this address to receive private-conversation invitations and
/// follow-up frames.
pub(crate) const PRIVATE_V1_INBOX_ADDRESS: &str = "delivery_address";

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context<DS: DeliveryService, RS: RegistrationService, CS: ChatStore> {
    identity: Arc<Identity>,
    ds: Arc<DS>,
    store: Arc<Mutex<CS>>,
    inbox: Inbox<CS>,
    pq_inbox: InboxV2<DS, RS, CS>,
}

impl<DS, RS, CS> Context<DS, RS, CS>
where
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
    CS: ChatStore + 'static,
{
    /// Opens or creates a Context with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created with the given name and saved.
    pub fn new_from_store(
        name: impl Into<String>,
        delivery: DS,
        registration: RS,
        store: CS,
    ) -> Result<Self, ChatError> {
        let name = name.into();

        // Services for sharing with Conversations/Inboxes
        let ds = Arc::new(delivery);
        let contact_registry = Arc::new(Mutex::new(registration));
        let store = Arc::new(Mutex::new(store));

        // Load or create identity
        let identity = if let Some(identity) = store.lock().unwrap().load_identity()? {
            identity
        } else {
            let identity = Identity::new(&name);
            store.lock().unwrap().save_identity(&identity)?;
            identity
        };

        let identity = Arc::new(identity);
        let inbox = Inbox::new(Arc::clone(&store), Arc::clone(&identity));

        let pq_inbox = InboxV2::new(
            LogosAccount::new_test(name),
            Arc::clone(&ds),
            contact_registry.clone(),
            store.clone(),
        );

        // Subscribe to both inbox addresses so DS::pull yields their traffic.
        ds.subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;
        ds.subscribe(PRIVATE_V1_INBOX_ADDRESS)
            .map_err(ChatError::generic)?;

        Ok(Self {
            identity,
            ds,
            store,
            inbox,
            pq_inbox,
        })
    }

    /// Creates a new in-memory Context (for testing).
    ///
    /// Uses in-memory SQLite database. Each call creates a new isolated database.
    pub fn new_with_name(
        name: impl Into<String>,
        delivery: DS,
        registration: RS,
        chat_store: CS,
    ) -> Result<Self, ChatError> {
        let name = name.into();
        let identity = Identity::new(&name);

        // Services for sharing with Conversations/Inboxes
        let ds = Arc::new(delivery);
        let contact_registry = Arc::new(Mutex::new(registration));
        let store = Arc::new(Mutex::new(chat_store));

        store
            .lock()
            .unwrap()
            .save_identity(&identity)
            .expect("in-memory storage should not fail");

        let identity = Arc::new(identity);
        let inbox = Inbox::new(store.clone(), Arc::clone(&identity));
        let mut pq_inbox = InboxV2::new(
            LogosAccount::new_test(name),
            Arc::clone(&ds),
            contact_registry.clone(),
            store.clone(),
        );

        // TODO: (P2) Initialize Account in Context or upper client.
        pq_inbox.register()?;

        ds.subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;
        ds.subscribe(PRIVATE_V1_INBOX_ADDRESS)
            .map_err(ChatError::generic)?;

        Ok(Self {
            identity,
            ds,
            store,
            pq_inbox,
            inbox,
        })
    }

    pub fn ds(&self) -> &DS {
        &self.ds
    }

    pub fn delivery_arc(&self) -> Arc<DS> {
        Arc::clone(&self.ds)
    }

    pub fn store(&self) -> MutexGuard<'_, CS> {
        self.store.lock().unwrap()
    }

    pub fn identity(&self) -> &Identity {
        &self.identity
    }

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
    ) -> Result<(ConversationIdOwned, Vec<Event>), ChatError> {
        let (mut convo, payloads) = self
            .inbox
            .invite_to_private_convo(remote_bundle, content, Arc::clone(&self.store))
            .unwrap_or_else(|_| todo!("Log/Surface Error"));

        let remote_id = Inbox::<CS>::inbox_identifier_for_key(*remote_bundle.installation_key());
        let convo_id = convo.persist()?;

        let mut events = Vec::new();
        for payload in payloads {
            let envelope = payload.into_envelope(remote_id.clone());
            if let Err(e) = self.ds.publish(envelope) {
                tracing::warn!("publish failed for convo {convo_id}: {e}");
                events.push(Event::transport_failure(convo_id.clone()));
            }
        }
        Ok((convo_id, events))
    }

    #[allow(clippy::type_complexity)]
    pub fn create_group_convo(
        &mut self,
        participants: &[&AccountId],
    ) -> Result<(Box<dyn GroupConvo<DS, RS>>, Vec<Event>), ChatError> {
        // TODO: (P1) Ensure errors are handled propertly. This is a high chance for desynchronized state.
        // MlsGroup persistence, conversation persistence, and invite delivery all happen seperately
        let mut convo = self.pq_inbox.create_group_v1()?;
        self.store
            .lock()
            .unwrap()
            .save_conversation(&storage::ConversationMeta {
                local_convo_id: convo.id().to_string(),
                remote_convo_id: "0".into(),
                kind: ConversationKind::GroupV1,
            })?;
        let events = convo.add_member(participants)?;
        Ok((Box::new(convo), events))
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationIdOwned>, ChatError> {
        let records = self.store.lock().unwrap().load_conversations()?;
        Ok(records
            .into_iter()
            .map(|r| Arc::from(r.local_convo_id.as_str()))
            .collect())
    }

    pub fn send_content(
        &mut self,
        convo_id: ConversationId,
        content: &[u8],
    ) -> Result<Vec<Event>, ChatError> {
        let mut convo = self.load_convo(convo_id)?;
        let payloads = convo.send_message(content)?;
        let remote_id = convo.remote_id();
        let convo_id_owned: ConversationIdOwned = Arc::from(convo_id);

        let mut events = Vec::new();
        for payload in payloads {
            let envelope = payload.into_envelope(remote_id.clone());
            if let Err(e) = self.ds.publish(envelope) {
                tracing::warn!("publish failed for convo {convo_id}: {e}");
                events.push(Event::transport_failure(convo_id_owned.clone()));
            }
        }
        Ok(events)
    }

    // Decode bytes and send to protocol for processing.
    pub fn handle_payload(&mut self, payload: &[u8]) -> Result<Vec<Event>, ChatError> {
        let env = EnvelopeV1::decode(payload)?;

        // TODO: Impl Conversation hinting
        let convo_id = env.conversation_hint;

        match convo_id {
            c if c == self.inbox.id() => self.dispatch_to_inbox(&env.payload),
            c if c == self.pq_inbox.id() => self.dispatch_to_inbox2(&env.payload),
            c if self.store.lock().unwrap().has_conversation(&c)? => {
                self.dispatch_to_convo(&c, &env.payload)
            }
            c => {
                tracing::warn!("dropping payload for unknown conversation hint {c}");
                Ok(Vec::new())
            }
        }
    }

    // Dispatch encrypted payload to Inbox, and register the created Conversation
    fn dispatch_to_inbox(&mut self, enc_payload_bytes: &[u8]) -> Result<Vec<Event>, ChatError> {
        // EncryptedPayloads are not used by GroupConvos at this time, else this can be performed in `handle_payload`
        // TODO: (P1) reconcile envelope parsing between Covno and GroupConvo
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;
        let public_key_hex = Inbox::<CS>::extract_ephemeral_key_hex(&enc_payload)?;
        let (convo, events) =
            self.inbox
                .handle_frame(enc_payload, &public_key_hex, Arc::clone(&self.store))?;

        match convo {
            Conversation::Private(mut convo) => convo.persist()?,
        };

        self.store
            .lock()
            .unwrap()
            .remove_ephemeral_key(&public_key_hex)?;
        Ok(events)
    }

    fn dispatch_to_inbox2(&mut self, payload: &[u8]) -> Result<Vec<Event>, ChatError> {
        self.pq_inbox.handle_frame(payload)
    }

    // Dispatch encrypted payload to its corresponding conversation
    fn dispatch_to_convo(
        &mut self,
        convo_id: ConversationId,
        enc_payload_bytes: &[u8],
    ) -> Result<Vec<Event>, ChatError> {
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
    ) -> Result<Box<dyn GroupConvo<DS, RS>>, ChatError> {
        self.load_group_convo(convo_id)
    }

    /// Loads a conversation from DB by constructing it from metadata.
    fn load_convo(&mut self, convo_id: ConversationId) -> Result<Box<dyn Convo>, ChatError> {
        let record = self
            .store
            .lock()
            .unwrap()
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
                self.pq_inbox.load_mls_convo(record.local_convo_id)?,
            )),
            ConversationKind::Unknown(_) => Err(ChatError::BadBundleValue(format!(
                "unsupported conversation type: {}",
                record.kind.as_str()
            ))),
        }
    }

    fn load_group_convo(
        &mut self,
        convo_id: ConversationId,
    ) -> Result<Box<dyn GroupConvo<DS, RS>>, ChatError> {
        let record = self
            .store
            .lock()
            .unwrap()
            .load_conversation(convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))?;

        match record.kind {
            ConversationKind::PrivateV1 => {
                Err(ChatError::NoConvo("This is not a group convo".into()))
            }
            ConversationKind::GroupV1 => Ok(Box::new(
                self.pq_inbox.load_mls_convo(record.local_convo_id)?,
            )),
            ConversationKind::Unknown(_) => Err(ChatError::BadBundleValue(format!(
                "unsupported conversation type: {}",
                record.kind.as_str()
            ))),
        }
    }
}
