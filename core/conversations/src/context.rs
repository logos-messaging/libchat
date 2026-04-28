use std::sync::Arc;
use std::{cell::RefCell, rc::Rc};

use crypto::{Identity, PublicKey};
use storage::{ChatStore, ConversationKind};

use crate::account::LogosAccount;
use crate::{
    conversation::{Conversation, ConversationId, Convo, Id, PrivateV1Convo},
    errors::ChatError,
    inbox::Inbox,
    proto::{EncryptedPayload, EnvelopeV1, Message},
    types::{AddressedEnvelope, ContentData},
};

pub use crate::conversation::ConversationIdOwned;
pub use crate::inbox::Introduction;

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context<S: ChatStore> {
    _identity: Rc<Identity>,
    inbox: Inbox<S>,
    store: Rc<RefCell<S>>,
    #[allow(unused)] // TODO: (P2) Remove once Account integrated in future PR.
    account: LogosAccount,
}

impl<S: ChatStore> Context<S> {
    /// Opens or creates a Context with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created with the given name and saved.
    pub fn new_from_store(name: impl Into<String>, store: S) -> Result<Self, ChatError> {
        let name = name.into();
        let store = Rc::new(RefCell::new(store));

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

        Ok(Self {
            _identity: identity,
            inbox,
            store,
            account: LogosAccount::new_test(name.as_str()),
        })
    }

    /// Creates a new in-memory Context (for testing).
    ///
    /// Uses in-memory SQLite database. Each call creates a new isolated database.
    pub fn new_with_name(name: impl Into<String>, chat_store: S) -> Self {
        let name = name.into();
        let identity = Identity::new(&name);
        let chat_store = Rc::new(RefCell::new(chat_store));
        chat_store
            .borrow_mut()
            .save_identity(&identity)
            .expect("in-memory storage should not fail");

        let identity = Rc::new(identity);
        let inbox = Inbox::new(Rc::clone(&chat_store), Rc::clone(&identity));

        Self {
            _identity: identity,
            inbox,
            store: chat_store,
            account: LogosAccount::new_test(name.as_str()),
        }
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

        let remote_id = Inbox::<S>::inbox_identifier_for_key(*remote_bundle.installation_key());
        let payload_bytes = payloads
            .into_iter()
            .map(|p| p.into_envelope(remote_id.clone()))
            .collect();

        let convo_id = convo.persist()?;
        Ok((convo_id, payload_bytes))
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
        let convo = self.load_convo(convo_id)?;

        match convo {
            Conversation::Private(mut convo) => {
                let payloads = convo.send_message(content)?;
                let remote_id = convo.remote_id();

                Ok(payloads
                    .into_iter()
                    .map(|p| p.into_envelope(remote_id.clone()))
                    .collect())
            }
        }
    }

    // Decode bytes and send to protocol for processing.
    pub fn handle_payload(&mut self, payload: &[u8]) -> Result<Option<ContentData>, ChatError> {
        let env = EnvelopeV1::decode(payload)?;

        // TODO: Impl Conversation hinting
        let convo_id = env.conversation_hint;
        let enc = EncryptedPayload::decode(env.payload)?;
        match convo_id {
            c if c == self.inbox.id() => self.dispatch_to_inbox(enc),
            c if self.store.borrow().has_conversation(&c)? => self.dispatch_to_convo(&c, enc),
            _ => Ok(None),
        }
    }

    // Dispatch encrypted payload to Inbox, and register the created Conversation
    fn dispatch_to_inbox(
        &mut self,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        let public_key_hex = Inbox::<S>::extract_ephemeral_key_hex(&enc_payload)?;
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

    // Dispatch encrypted payload to its corresponding conversation
    fn dispatch_to_convo(
        &mut self,
        convo_id: ConversationId,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        let convo = self.load_convo(convo_id)?;

        match convo {
            Conversation::Private(mut convo) => {
                let result = convo.handle_frame(enc_payload)?;
                Ok(result)
            }
        }
    }

    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        let intro = self.inbox.create_intro_bundle()?;
        Ok(intro.into())
    }

    /// Loads a conversation from DB by constructing it from metadata.
    fn load_convo(&self, convo_id: ConversationId) -> Result<Conversation<S>, ChatError> {
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
                Ok(Conversation::Private(private_convo))
            }
            ConversationKind::Unknown(_) => Err(ChatError::BadBundleValue(format!(
                "unsupported conversation type: {}",
                record.kind.as_str()
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use sqlite::{ChatStorage, StorageConfig};
    use storage::{ConversationStore, IdentityStore};
    use tempfile::tempdir;

    use super::*;

    fn send_and_verify(
        sender: &mut Context<ChatStorage>,
        receiver: &mut Context<ChatStorage>,
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

    #[test]
    fn ctx_integration() {
        let mut saro = Context::new_with_name("saro", ChatStorage::in_memory());
        let mut raya = Context::new_with_name("raya", ChatStorage::in_memory());

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
        let store1 = ChatStorage::new(StorageConfig::InMemory).unwrap();
        let ctx1 = Context::new_with_name("alice", store1);
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

        let store = ChatStorage::new(StorageConfig::File(db_path.clone())).unwrap();
        let ctx = Context::new_from_store("alice", store).unwrap();
        let pubkey = ctx._identity.public_key();
        drop(ctx);

        let store = ChatStorage::new(StorageConfig::File(db_path)).unwrap();
        let persisted = store.load_identity().unwrap().unwrap();

        assert_eq!(persisted.get_name(), "alice");
        assert_eq!(persisted.public_key(), pubkey);
    }

    #[test]
    fn conversation_metadata_persistence() {
        let mut alice = Context::new_with_name("alice", ChatStorage::in_memory());
        let mut bob = Context::new_with_name("bob", ChatStorage::in_memory());

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
        let mut alice = Context::new_with_name("alice", ChatStorage::in_memory());
        let mut bob = Context::new_with_name("bob", ChatStorage::in_memory());

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
