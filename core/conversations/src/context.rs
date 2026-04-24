use std::sync::Arc;
use std::{cell::RefCell, rc::Rc};

use crate::conversation::{Convo, GroupConvo, IdentityProvider};
use crate::ctx::ClientCtx;

use crate::{DeliveryService, RegistrationService};
use crate::{
    conversation::{Conversation, ConversationId, Id, PrivateV1Convo},
    errors::ChatError,
    inbox::Inbox,
    inbox_v2::InboxV2,
    proto::{EncryptedPayload, EnvelopeV1, Message},
    types::{AddressedEnvelope, ContentData},
};
use crypto::{Identity, PublicKey};
use storage::{ChatStore, ConversationKind};

pub use crate::conversation::ConversationIdOwned;
pub use crate::inbox::Introduction;

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context<DS: DeliveryService, RS: RegistrationService, CS: ChatStore> {
    _identity: Rc<Identity>,
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

        let pq_inbox = InboxV2::new();

        // Subscribe
        ctx.ds()
            .subscribe(pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            _identity: identity,
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
        let mut pq_inbox = InboxV2::new();
        pq_inbox.register(&mut ctx)?;

        ctx.ds()
            .subscribe(pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            _identity: identity,
            client_ctx: ctx,
            pq_inbox,
            inbox,

            store: chat_store,
        })
    }

    /// Returns the unique identifier associated with the account
    pub fn account_id(&self) -> String {
        self.pq_inbox.account.friendly_name()
    }

    pub fn installation_name(&self) -> &str {
        self._identity.get_name()
    }

    pub fn installation_key(&self) -> PublicKey {
        self._identity.public_key()
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
        participants: &[&str],
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

#[cfg(test)]
mod tests {
    use std::ops::{Deref, DerefMut};

    use sqlite::{ChatStorage, StorageConfig};
    use storage::{ConversationStore, IdentityStore};
    use tempfile::tempdir;

    use crate::{
        test_utils::{EphemeralRegistry, LocalBroadcaster, MemStore},
        utils::hex_trunc,
    };

    use super::*;

    type TestContext = Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>;

    fn send_and_verify(
        sender: &mut TestContext,
        receiver: &mut TestContext,
        convo_id: ConversationId,
        content: &[u8],
    ) {
        let payloads = sender.send_content(convo_id, content).unwrap();
        let payload = payloads.first().unwrap();
        let received = receiver
            .handle_payload(&payload.data)
            .unwrap()
            .expect("expected content");
        assert_eq!(content, received.data.as_slice());
        assert!(!received.is_new_convo); // Check that `is_new_convo` is FALSE
    }

    // Simple client Functionality for testing
    struct Client {
        inner: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
        on_content: Option<Box<dyn Fn(ContentData)>>,
    }

    impl Client {
        fn init(
            ctx: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
            cb: Option<impl Fn(ContentData) + 'static>,
        ) -> Self {
            Client {
                inner: ctx,
                on_content: cb.map(|f| Box::new(f) as Box<dyn Fn(ContentData)>),
            }
        }

        fn process_messages(&mut self) {
            while let Some(data) = self.client_ctx.ds().poll() {
                let res = self.handle_payload(&data).unwrap();
                if let Some(cb) = &self.on_content {
                    match res {
                        Some(content_data) => cb(content_data),
                        None => continue,
                    }
                }
            }
        }

        fn convo(
            &mut self,
            convo_id: &str,
        ) -> Box<dyn GroupConvo<LocalBroadcaster, EphemeralRegistry, MemStore>> {
            // TODO: (P1) Convos are being copied somewhere, which means hanging on to a reference causes state desync
            self.load_group_convo(convo_id).unwrap()
        }
    }

    impl Deref for Client {
        type Target = Context<LocalBroadcaster, EphemeralRegistry, MemStore>;

        fn deref(&self) -> &Self::Target {
            &self.inner
        }
    }

    impl DerefMut for Client {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.inner
        }
    }

    // Higher order function to handle printing
    fn pretty_print(prefix: impl Into<String>) -> Box<dyn Fn(ContentData)> {
        let prefix = prefix.into();
        return Box::new(move |c: ContentData| {
            let cid = hex_trunc(c.conversation_id.as_bytes());
            let content = String::from_utf8(c.data).unwrap();
            println!("{}      ({}) {}", prefix, cid, content)
        });
    }

    fn process(clients: &mut Vec<Client>) {
        for client in clients {
            client.process_messages();
        }
    }

    #[test]
    fn create_group() {
        let ds = LocalBroadcaster::new();
        let rs = EphemeralRegistry::new();

        let saro_ctx =
            Context::new_with_name("saro", ds.new_consumer(), rs.clone(), MemStore::new()).unwrap();
        let raya_ctx =
            Context::new_with_name("raya", ds.clone(), rs.clone(), MemStore::new()).unwrap();

        let mut clients = vec![
            Client::init(saro_ctx, Some(pretty_print("  Saro         "))),
            Client::init(raya_ctx, Some(pretty_print("       Raya    "))),
        ];

        const SARO: usize = 0;
        const RAYA: usize = 1;

        let raya_id = clients[RAYA].account_id();
        let s_convo = clients[SARO]
            .create_group_convo(&[raya_id.as_ref()])
            .unwrap();

        let convo_id = s_convo.id();

        // Raya can read this message because
        //   1) It was sent after add_members was committed, and
        //   2) LocalBroadcaster provides historical messages.

        clients[SARO]
            .convo(convo_id)
            .send_content(
                &mut clients[SARO].client_ctx,
                b"ok who broke the group chat again",
            )
            .unwrap();

        // clients[SARO].process_messages();
        process(&mut clients);

        clients[RAYA]
            .convo(convo_id)
            .send_content(
                &mut clients[RAYA].client_ctx,
                b"it was literally working five minutes ago",
            )
            .unwrap();

        // clients[SARO].process_messages();
        process(&mut clients);

        let pax_ctx = Context::new_with_name("pax", ds, rs, MemStore::new()).unwrap();
        clients.push(Client::init(pax_ctx, Some(pretty_print("           Pax"))));
        const PAX: usize = 2;

        let pax_id = clients[PAX].account_id();
        clients[SARO]
            .convo(convo_id)
            .add_member(&mut clients[SARO].client_ctx, &[pax_id.as_ref()])
            .unwrap();

        // clients[SARO].process_messages();
        process(&mut clients);

        clients[PAX]
            .convo(convo_id)
            .send_content(
                &mut clients[PAX].client_ctx,
                b"ngl the key rotation is cooked",
            )
            .unwrap();

        // clients[SARO].process_messages();

        process(&mut clients);

        clients[SARO]
            .convo(convo_id)
            .send_content(
                &mut clients[SARO].client_ctx,
                b"bro we literally just added you to the group ",
            )
            .unwrap();

        process(&mut clients);
        // process(&mut clients);
    }

    #[test]
    fn ctx_integration() {
        let ds = LocalBroadcaster::new();
        let rs = EphemeralRegistry::new();

        let mut saro =
            Context::new_with_name("saro", ds.clone(), rs.clone(), ChatStorage::in_memory())
                .unwrap();
        let mut raya = Context::new_with_name("raya", ds, rs, ChatStorage::in_memory()).unwrap();

        // Raya creates intro bundle and sends to Saro
        let bundle = raya.create_intro_bundle().unwrap();
        let intro = Introduction::try_from(bundle.as_slice()).unwrap();

        // Saro initiates conversation with Raya
        let mut content = vec![10];
        let (saro_convo_id, payloads) = saro.create_private_convo(&intro, &content).unwrap();

        // Raya receives initial message
        let payload = payloads.first().unwrap();
        let initial_content = raya
            .handle_payload(&payload.data)
            .unwrap()
            .expect("expected initial content");

        let raya_convo_id = initial_content.conversation_id;
        assert_eq!(content, initial_content.data);
        assert!(initial_content.is_new_convo);

        // Exchange messages back and forth
        for _ in 0..10 {
            content.push(content.last().unwrap() + 1);
            send_and_verify(&mut raya, &mut saro, &raya_convo_id, &content);

            content.push(content.last().unwrap() + 1);
            send_and_verify(&mut saro, &mut raya, &saro_convo_id, &content);
        }
    }

    #[test]
    fn identity_persistence() {
        let ds = LocalBroadcaster::new();
        let rs = EphemeralRegistry::new();
        let store1 = ChatStorage::new(StorageConfig::InMemory).unwrap();
        let ctx1 = Context::new_with_name("alice", ds, rs, store1).unwrap();
        let pubkey1 = ctx1._identity.public_key();
        let name1 = ctx1.installation_name().to_string();

        // For persistence tests with file-based storage, we'd need a shared db.
        // With in-memory, we just verify the identity was created.
        assert_eq!(name1, "alice");
        assert!(!pubkey1.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn open_persists_new_identity() {
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("chat.sqlite");
        let db_path = db_path.to_string_lossy().into_owned();

        let ds = LocalBroadcaster::new();
        let rs = EphemeralRegistry::new();
        let store = ChatStorage::new(StorageConfig::File(db_path.clone())).unwrap();
        let ctx = Context::new_from_store("alice", ds, rs, store).unwrap();
        let pubkey = ctx._identity.public_key();
        drop(ctx);

        let store = ChatStorage::new(StorageConfig::File(db_path)).unwrap();
        let persisted = store.load_identity().unwrap().unwrap();

        assert_eq!(persisted.get_name(), "alice");
        assert_eq!(persisted.public_key(), pubkey);
    }

    #[test]
    fn conversation_metadata_persistence() {
        let ds = LocalBroadcaster::new();
        let rs = EphemeralRegistry::new();
        let mut alice =
            Context::new_with_name("alice", ds.clone(), rs.clone(), ChatStorage::in_memory())
                .unwrap();
        let mut bob = Context::new_with_name("bob", ds, rs, ChatStorage::in_memory()).unwrap();

        let bundle = alice.create_intro_bundle().unwrap();
        let intro = Introduction::try_from(bundle.as_slice()).unwrap();
        let (_, payloads) = bob.create_private_convo(&intro, b"hi").unwrap();

        let payload = payloads.first().unwrap();
        let content = alice.handle_payload(&payload.data).unwrap().unwrap();
        assert!(content.is_new_convo);

        let convos = alice.store.borrow().load_conversations().unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].kind.as_str(), "private_v1");
    }

    #[test]
    fn conversation_full_flow() {
        let ds = LocalBroadcaster::new();
        let rs = EphemeralRegistry::new();
        let mut alice =
            Context::new_with_name("alice", ds.clone(), rs.clone(), ChatStorage::in_memory())
                .unwrap();
        let mut bob = Context::new_with_name("bob", ds, rs, ChatStorage::in_memory()).unwrap();

        let bundle = alice.create_intro_bundle().unwrap();
        let intro = Introduction::try_from(bundle.as_slice()).unwrap();
        let (bob_convo_id, payloads) = bob.create_private_convo(&intro, b"hello").unwrap();

        let payload = payloads.first().unwrap();
        let content = alice.handle_payload(&payload.data).unwrap().unwrap();
        let alice_convo_id = content.conversation_id;

        let payloads = alice.send_content(&alice_convo_id, b"reply 1").unwrap();
        let payload = payloads.first().unwrap();
        bob.handle_payload(&payload.data).unwrap().unwrap();

        let payloads = bob.send_content(&bob_convo_id, b"reply 2").unwrap();
        let payload = payloads.first().unwrap();
        alice.handle_payload(&payload.data).unwrap().unwrap();

        // Verify conversation list
        let convo_ids = alice.list_conversations().unwrap();
        assert_eq!(convo_ids.len(), 1);

        // Continue exchanging messages
        let payloads = bob.send_content(&bob_convo_id, b"more messages").unwrap();
        let payload = payloads.first().unwrap();
        let content = alice
            .handle_payload(&payload.data)
            .expect("should decrypt")
            .expect("should have content");
        assert_eq!(content.data, b"more messages");

        // Alice can also send back
        let payloads = alice.send_content(&alice_convo_id, b"alice reply").unwrap();
        let payload = payloads.first().unwrap();
        let content = bob
            .handle_payload(&payload.data)
            .unwrap()
            .expect("bob should receive");
        assert_eq!(content.data, b"alice reply");
    }
}
