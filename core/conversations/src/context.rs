use std::rc::Rc;
use std::sync::Arc;

use double_ratchets::{RatchetState, RatchetStorage};
use storage::StorageConfig;

use crate::{
    conversation::{ConversationId, Convo, Id, PrivateV1Convo},
    errors::ChatError,
    identity::Identity,
    inbox::Inbox,
    proto::{EncryptedPayload, EnvelopeV1, Message},
    sqlite::ChatStorage,
    store::{ChatStore, ConversationKind, ConversationMeta, IdentityStore},
    types::{AddressedEnvelope, ContentData},
};

pub use crate::conversation::ConversationIdOwned;
pub use crate::inbox::Introduction;

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context<T: ChatStore> {
    _identity: Rc<Identity>,
    inbox: Inbox,
    storage: T,
    ratchet_storage: RatchetStorage,
}

impl<T: ChatStore> Context<T> {
    /// Opens or creates a Context with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created with the given name and saved.
    pub fn open(
        name: impl Into<String>,
        config: StorageConfig,
        store: T,
    ) -> Result<Self, ChatError> {
        let mut storage = ChatStorage::new(config.clone())?;
        let ratchet_storage = RatchetStorage::from_config(config)?;
        let name = name.into();

        // Load or create identity
        let identity = if let Some(identity) = storage.load_identity()? {
            identity
        } else {
            let identity = Identity::new(&name);
            storage.save_identity(&identity)?;
            identity
        };

        let identity = Rc::new(identity);
        let inbox = Inbox::new(Rc::clone(&identity));

        Ok(Self {
            _identity: identity,
            inbox,
            storage: store,
            ratchet_storage,
        })
    }

    /// Creates a new in-memory Context (for testing).
    ///
    /// Uses in-memory SQLite database. Each call creates a new isolated database.
    pub fn new_with_name(name: impl Into<String>, chat_store: T) -> Self {
        Self::open(name, StorageConfig::InMemory, chat_store)
            .expect("in-memory storage should not fail")
    }

    pub fn installation_name(&self) -> &str {
        self._identity.get_name()
    }

    pub fn create_private_convo(
        &mut self,
        remote_bundle: &Introduction,
        content: &[u8],
    ) -> (ConversationIdOwned, Vec<AddressedEnvelope>) {
        let (convo, payloads) = self
            .inbox
            .invite_to_private_convo(remote_bundle, content)
            .unwrap_or_else(|_| todo!("Log/Surface Error"));

        let remote_id = Inbox::inbox_identifier_for_key(*remote_bundle.installation_key());
        let payload_bytes = payloads
            .into_iter()
            .map(|p| p.into_envelope(remote_id.clone()))
            .collect();

        let convo_id = self.persist_convo(&convo);
        (convo_id, payload_bytes)
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationIdOwned>, ChatError> {
        let records = self.storage.load_conversations()?;
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
        convo.save_ratchet_state(&mut self.ratchet_storage)?;

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
        let enc = EncryptedPayload::decode(env.payload)?;
        match convo_id {
            c if c == self.inbox.id() => self.dispatch_to_inbox(enc),
            c if self.storage.has_conversation(&c)? => self.dispatch_to_convo(&c, enc),
            _ => Ok(None),
        }
    }

    // Dispatch encrypted payload to Inbox, and register the created Conversation
    fn dispatch_to_inbox(
        &mut self,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        // Look up the ephemeral key from storage
        let key_hex = Inbox::extract_ephemeral_key_hex(&enc_payload)?;
        let ephemeral_key = self
            .storage
            .load_ephemeral_key(&key_hex)?
            .ok_or(ChatError::UnknownEphemeralKey())?;

        let (convo, content) = self.inbox.handle_frame(&ephemeral_key, enc_payload)?;

        // Remove consumed ephemeral key from storage
        self.storage.remove_ephemeral_key(&key_hex)?;

        self.persist_convo(convo.as_ref());
        Ok(content)
    }

    // Dispatch encrypted payload to its corresponding conversation
    fn dispatch_to_convo(
        &mut self,
        convo_id: ConversationId,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        let mut convo = self.load_convo(convo_id)?;

        let result = convo.handle_frame(enc_payload)?;
        convo.save_ratchet_state(&mut self.ratchet_storage)?;

        Ok(result)
    }

    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        let (intro, public_key_hex, private_key) = self.inbox.create_intro_bundle();
        self.storage
            .save_ephemeral_key(&public_key_hex, &private_key)?;
        Ok(intro.into())
    }

    /// Loads a conversation from DB by constructing it from metadata + ratchet state.
    fn load_convo(&self, convo_id: ConversationId) -> Result<PrivateV1Convo, ChatError> {
        let record = self
            .storage
            .load_conversation(convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))?;

        match record.kind {
            ConversationKind::PrivateV1 => {}
            ConversationKind::Unknown(_) => {
                return Err(ChatError::BadBundleValue(format!(
                    "unsupported conversation type: {}",
                    record.kind.as_str()
                )));
            }
        }

        let dr_state: RatchetState = self.ratchet_storage.load(&record.local_convo_id)?;

        Ok(PrivateV1Convo::from_stored(
            record.local_convo_id,
            record.remote_convo_id,
            dr_state,
        ))
    }

    /// Persists a conversation's metadata and ratchet state to DB.
    fn persist_convo(&mut self, convo: &dyn Convo) -> ConversationIdOwned {
        let convo_info = ConversationMeta {
            local_convo_id: convo.id().to_string(),
            remote_convo_id: convo.remote_id(),
            kind: convo.convo_type().into(),
        };
        let _ = self.storage.save_conversation(&convo_info);
        let _ = convo.save_ratchet_state(&mut self.ratchet_storage);
        Arc::from(convo.id())
    }
}

#[cfg(test)]
mod mock {
    use crypto::PrivateKey;
    use storage::StorageError;

    use crate::store::{ConversationStore, EphemeralKeyStore, IdentityStore};

    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    // Simple in-memory implementation of ChatStore for tests.
    // Adjust the methods to match the exact trait definition in `crate::store::ChatStore`.
    #[derive(Default)]
    pub struct MockChatStore {
        identity: Option<Identity>,
        conversations: Mutex<HashMap<String, ConversationMeta>>,
        ephemeral_keys: Mutex<HashMap<String, PrivateKey>>,
    }

    impl IdentityStore for MockChatStore {
        fn load_identity(&self) -> Result<Option<Identity>, StorageError> {
            Ok(self.identity.clone())
        }

        fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError> {
            self.identity = Some(identity.clone());
            Ok(())
        }
    }

    impl EphemeralKeyStore for MockChatStore {
        fn load_ephemeral_key(&self, key_hex: &str) -> Result<Option<PrivateKey>, StorageError> {
            Ok(self.ephemeral_keys.lock().unwrap().get(key_hex).cloned())
        }

        fn save_ephemeral_key(
            &mut self,
            key_hex: &str,
            private_key: &PrivateKey,
        ) -> Result<(), StorageError> {
            self.ephemeral_keys
                .lock()
                .unwrap()
                .insert(key_hex.to_string(), private_key.clone());
            Ok(())
        }

        fn remove_ephemeral_key(&mut self, key_hex: &str) -> Result<(), StorageError> {
            self.ephemeral_keys.lock().unwrap().remove(key_hex);
            Ok(())
        }
    }

    impl ConversationStore for MockChatStore {
        fn save_conversation(&mut self, meta: &ConversationMeta) -> Result<(), StorageError> {
            self.conversations
                .lock()
                .unwrap()
                .insert(meta.local_convo_id.clone(), meta.clone());
            Ok(())
        }

        fn load_conversation(
            &self,
            local_convo_id: &str,
        ) -> Result<Option<ConversationMeta>, StorageError> {
            Ok(self
                .conversations
                .lock()
                .unwrap()
                .get(local_convo_id)
                .cloned())
        }

        fn remove_conversation(&mut self, local_convo_id: &str) -> Result<(), StorageError> {
            self.conversations.lock().unwrap().remove(local_convo_id);
            Ok(())
        }

        fn load_conversations(&self) -> Result<Vec<ConversationMeta>, StorageError> {
            Ok(self
                .conversations
                .lock()
                .unwrap()
                .values()
                .cloned()
                .collect())
        }

        fn has_conversation(&self, local_convo_id: &str) -> Result<bool, StorageError> {
            Ok(self
                .conversations
                .lock()
                .unwrap()
                .contains_key(local_convo_id))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{context::mock::MockChatStore, sqlite::ChatStorage, store::ConversationStore};

    use super::*;

    fn send_and_verify(
        sender: &mut Context<MockChatStore>,
        receiver: &mut Context<MockChatStore>,
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
        let mut saro = Context::new_with_name("saro", MockChatStore::default());
        let mut raya = Context::new_with_name("raya", MockChatStore::default());

        // Raya creates intro bundle and sends to Saro
        let bundle = raya.create_intro_bundle().unwrap();
        let intro = Introduction::try_from(bundle.as_slice()).unwrap();

        // Saro initiates conversation with Raya
        let mut content = vec![10];
        let (saro_convo_id, payloads) = saro.create_private_convo(&intro, &content);

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
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir
            .path()
            .join("test_identity.db")
            .to_string_lossy()
            .to_string();
        let config = StorageConfig::File(db_path);

        let ctx1 = Context::open("alice", config.clone(), MockChatStore::default()).unwrap();
        let pubkey1 = ctx1._identity.public_key();
        let name1 = ctx1.installation_name().to_string();

        drop(ctx1);
        let ctx2 = Context::open("alice", config, MockChatStore::default()).unwrap();
        let pubkey2 = ctx2._identity.public_key();
        let name2 = ctx2.installation_name().to_string();

        assert_eq!(pubkey1, pubkey2, "public key should persist");
        assert_eq!(name1, name2, "name should persist");
    }

    #[test]
    fn ephemeral_key_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir
            .path()
            .join("test_ephemeral.db")
            .to_string_lossy()
            .to_string();
        let config = StorageConfig::File(db_path);

        let store1 = ChatStorage::new(config.clone()).unwrap();
        let mut ctx1 = Context::open("alice", config.clone(), store1).unwrap();
        let bundle1 = ctx1.create_intro_bundle().unwrap();

        drop(ctx1);
        let store2 = ChatStorage::new(config.clone()).unwrap();
        let mut ctx2 = Context::open("alice", config.clone(), store2).unwrap();

        let intro = Introduction::try_from(bundle1.as_slice()).unwrap();
        let mut bob = Context::new_with_name("bob", MockChatStore::default());
        let (_, payloads) = bob.create_private_convo(&intro, b"hello after restart");

        let payload = payloads.first().unwrap();
        let content = ctx2
            .handle_payload(&payload.data)
            .expect("should handle payload with persisted ephemeral key")
            .expect("should have content");
        assert_eq!(content.data, b"hello after restart");
        assert!(content.is_new_convo);
    }

    #[test]
    fn conversation_metadata_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir
            .path()
            .join("test_convo_meta.db")
            .to_string_lossy()
            .to_string();
        let config = StorageConfig::File(db_path);

        let store = ChatStorage::new(config.clone()).unwrap();
        let mut alice = Context::open("alice", config.clone(), store).unwrap();
        let mut bob = Context::new_with_name("bob", MockChatStore::default());

        let bundle = alice.create_intro_bundle().unwrap();
        let intro = Introduction::try_from(bundle.as_slice()).unwrap();
        let (_, payloads) = bob.create_private_convo(&intro, b"hi");

        let payload = payloads.first().unwrap();
        let content = alice.handle_payload(&payload.data).unwrap().unwrap();
        assert!(content.is_new_convo);

        let convos = alice.storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].kind.as_str(), "private_v1");

        drop(alice);
        let store2 = ChatStorage::new(config.clone()).unwrap();
        let alice2 = Context::open("alice", config, store2).unwrap();
        let convos = alice2.storage.load_conversations().unwrap();
        assert_eq!(convos.len(), 1, "conversation metadata should persist");
    }

    #[test]
    fn conversation_full_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir
            .path()
            .join("test_full_persist.db")
            .to_string_lossy()
            .to_string();
        let config = StorageConfig::File(db_path);

        // Alice and Bob establish a conversation
        let store = ChatStorage::new(config.clone()).unwrap();
        let mut alice = Context::open("alice", config.clone(), store).unwrap();
        let mut bob = Context::new_with_name("bob", MockChatStore::default());

        let bundle = alice.create_intro_bundle().unwrap();
        let intro = Introduction::try_from(bundle.as_slice()).unwrap();
        let (bob_convo_id, payloads) = bob.create_private_convo(&intro, b"hello");

        let payload = payloads.first().unwrap();
        let content = alice.handle_payload(&payload.data).unwrap().unwrap();
        let alice_convo_id = content.conversation_id;

        // Exchange a few messages to advance ratchet state
        let payloads = alice.send_content(&alice_convo_id, b"reply 1").unwrap();
        let payload = payloads.first().unwrap();
        bob.handle_payload(&payload.data).unwrap().unwrap();

        let payloads = bob.send_content(&bob_convo_id, b"reply 2").unwrap();
        let payload = payloads.first().unwrap();
        alice.handle_payload(&payload.data).unwrap().unwrap();

        // Drop Alice and reopen - conversation should survive
        drop(alice);
        let store2 = ChatStorage::new(config.clone()).unwrap();
        let mut alice2 = Context::open("alice", config, store2).unwrap();

        // Verify conversation was restored
        let convo_ids = alice2.list_conversations().unwrap();
        assert_eq!(convo_ids.len(), 1);

        // Bob sends a new message - Alice should be able to decrypt after restart
        let payloads = bob.send_content(&bob_convo_id, b"after restart").unwrap();
        let payload = payloads.first().unwrap();
        let content = alice2
            .handle_payload(&payload.data)
            .expect("should decrypt after restart")
            .expect("should have content");
        assert_eq!(content.data, b"after restart");

        // Alice can also send back
        let payloads = alice2
            .send_content(&alice_convo_id, b"alice after restart")
            .unwrap();
        let payload = payloads.first().unwrap();
        let content = bob
            .handle_payload(&payload.data)
            .unwrap()
            .expect("bob should receive");
        assert_eq!(content.data, b"alice after restart");
    }
}
