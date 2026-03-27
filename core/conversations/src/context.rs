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
    storage::ChatStorage,
    store::{
        ConversationKind, ConversationMeta, ConversationStore, EphemeralKeyStore, IdentityStore,
    },
    types::{AddressedEnvelope, ContentData},
};

pub use crate::conversation::ConversationIdOwned;
pub use crate::inbox::Introduction;

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context {
    _identity: Rc<Identity>,
    inbox: Inbox,
    storage: ChatStorage,
    ratchet_storage: RatchetStorage,
}

impl Context {
    /// Opens or creates a Context with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created with the given name and saved.
    pub fn open(name: impl Into<String>, config: StorageConfig) -> Result<Self, ChatError> {
        let mut storage = ChatStorage::new(config.clone())?;
        let ratchet_storage = RatchetStorage::from_config(config)?;
        let name = name.into();

        // Load or create identity
        let identity = if let Some(identity) = IdentityStore::load_identity(&storage)? {
            identity
        } else {
            let identity = Identity::new(&name);
            IdentityStore::save_identity(&mut storage, &identity)?;
            identity
        };

        let identity = Rc::new(identity);
        let inbox = Inbox::new(Rc::clone(&identity));

        Ok(Self {
            _identity: identity,
            inbox,
            storage,
            ratchet_storage,
        })
    }

    /// Creates a new in-memory Context (for testing).
    ///
    /// Uses in-memory SQLite database. Each call creates a new isolated database.
    pub fn new_with_name(name: impl Into<String>) -> Self {
        Self::open(name, StorageConfig::InMemory).expect("in-memory storage should not fail")
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
        let records = ConversationStore::load_conversations(&self.storage)?;
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
            c if ConversationStore::has_conversation(&self.storage, &c)? => {
                self.dispatch_to_convo(&c, enc)
            }
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
        let ephemeral_key = EphemeralKeyStore::load_ephemeral_key(&self.storage, &key_hex)?
            .ok_or(ChatError::UnknownEphemeralKey())?;

        let (convo, content) = self.inbox.handle_frame(&ephemeral_key, enc_payload)?;

        // Remove consumed ephemeral key from storage
        EphemeralKeyStore::remove_ephemeral_key(&mut self.storage, &key_hex)?;

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
        EphemeralKeyStore::save_ephemeral_key(&mut self.storage, &public_key_hex, &private_key)?;
        Ok(intro.into())
    }

    /// Loads a conversation from DB by constructing it from metadata + ratchet state.
    fn load_convo(&self, convo_id: ConversationId) -> Result<PrivateV1Convo, ChatError> {
        let meta = ConversationStore::load_conversation(&self.storage, convo_id)?
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))?;

        match meta.kind {
            ConversationKind::PrivateV1 => {
                let dr_state: RatchetState = self.ratchet_storage.load(&meta.local_convo_id)?;

                Ok(PrivateV1Convo::from_stored(
                    meta.local_convo_id,
                    meta.remote_convo_id,
                    dr_state,
                ))
            }
            ConversationKind::Unknown(kind) => Err(ChatError::UnsupportedConvoType(kind)),
        }
    }

    /// Persists a conversation's metadata and ratchet state to DB.
    fn persist_convo(&mut self, convo: &dyn Convo) -> ConversationIdOwned {
        let meta = ConversationMeta {
            local_convo_id: convo.id().to_string(),
            remote_convo_id: convo.remote_id(),
            kind: ConversationKind::from_db(convo.convo_type()),
        };

        let _ = ConversationStore::save_conversation(&mut self.storage, &meta);
        let _ = convo.save_ratchet_state(&mut self.ratchet_storage);
        Arc::from(convo.id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn send_and_verify(
        sender: &mut Context,
        receiver: &mut Context,
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
        let mut saro = Context::new_with_name("saro");
        let mut raya = Context::new_with_name("raya");

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

        let ctx1 = Context::open("alice", config.clone()).unwrap();
        let pubkey1 = ctx1._identity.public_key();
        let name1 = ctx1.installation_name().to_string();

        drop(ctx1);
        let ctx2 = Context::open("alice", config).unwrap();
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

        let mut ctx1 = Context::open("alice", config.clone()).unwrap();
        let bundle1 = ctx1.create_intro_bundle().unwrap();

        drop(ctx1);
        let mut ctx2 = Context::open("alice", config.clone()).unwrap();

        let intro = Introduction::try_from(bundle1.as_slice()).unwrap();
        let mut bob = Context::new_with_name("bob");
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

        let mut alice = Context::open("alice", config.clone()).unwrap();
        let mut bob = Context::new_with_name("bob");

        let bundle = alice.create_intro_bundle().unwrap();
        let intro = Introduction::try_from(bundle.as_slice()).unwrap();
        let (_, payloads) = bob.create_private_convo(&intro, b"hi");

        let payload = payloads.first().unwrap();
        let content = alice.handle_payload(&payload.data).unwrap().unwrap();
        assert!(content.is_new_convo);

        let convos = ConversationStore::load_conversations(&alice.storage).unwrap();
        assert_eq!(convos.len(), 1);
        assert_eq!(convos[0].kind, ConversationKind::PrivateV1);

        drop(alice);
        let alice2 = Context::open("alice", config).unwrap();
        let convos = ConversationStore::load_conversations(&alice2.storage).unwrap();
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
        let mut alice = Context::open("alice", config.clone()).unwrap();
        let mut bob = Context::new_with_name("bob");

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
        let mut alice2 = Context::open("alice", config).unwrap();

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
