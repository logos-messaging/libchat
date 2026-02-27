use std::rc::Rc;

use storage::StorageConfig;

use crate::{
    conversation::{ConversationId, ConversationStore, Convo, Id},
    errors::ChatError,
    identity::Identity,
    inbox::Inbox,
    proto::{EncryptedPayload, EnvelopeV1, Message},
    storage::{ChatStorage, StorageError},
    types::{AddressedEnvelope, ContentData},
};

pub use crate::conversation::ConversationIdOwned;
pub use crate::inbox::Introduction;

/// Error type for Context operations.
#[derive(Debug, thiserror::Error)]
pub enum ContextError {
    #[error("chat error: {0}")]
    Chat(#[from] ChatError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
}

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context {
    _identity: Rc<Identity>,
    store: ConversationStore,
    inbox: Inbox,
    storage: ChatStorage,
}

impl Context {
    /// Opens or creates a Context with the given storage configuration.
    ///
    /// If an identity exists in storage, it will be restored.
    /// Otherwise, a new identity will be created with the given name and saved.
    pub fn open(name: impl Into<String>, config: StorageConfig) -> Result<Self, ContextError> {
        let mut storage = ChatStorage::new(config)?;
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
            store: ConversationStore::new(),
            inbox,
            storage,
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

        let convo_id = self.add_convo(Box::new(convo));
        (convo_id, payload_bytes)
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationIdOwned>, ChatError> {
        Ok(self.store.conversation_ids())
    }

    pub fn send_content(
        &mut self,
        convo_id: ConversationId,
        content: &[u8],
    ) -> Result<Vec<AddressedEnvelope>, ChatError> {
        // Lookup convo by id
        let convo = self.get_convo_mut(convo_id)?;

        // Generate encrypted payloads
        let payloads = convo.send_message(content)?;

        // Attach conversation_ids to Envelopes
        Ok(payloads
            .into_iter()
            .map(|p| p.into_envelope(convo.remote_id()))
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
            c if self.store.has(&c) => self.dispatch_to_convo(&c, enc),
            _ => Ok(None),
        }
    }

    // Dispatch encrypted payload to Inbox, and register the created Conversation
    fn dispatch_to_inbox(
        &mut self,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        let (convo, content) = self.inbox.handle_frame(enc_payload)?;
        self.add_convo(convo);
        Ok(content)
    }

    // Dispatch encrypted payload to its corresponding conversation
    fn dispatch_to_convo(
        &mut self,
        convo_id: ConversationId,
        enc_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        let Some(convo) = self.store.get_mut(convo_id) else {
            return Err(ChatError::Protocol("convo id not found".into()));
        };

        convo.handle_frame(enc_payload)
    }

    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        Ok(self.inbox.create_intro_bundle().into())
    }

    fn add_convo(&mut self, convo: Box<dyn Convo>) -> ConversationIdOwned {
        self.store.insert_convo(convo)
    }

    // Returns a mutable reference to a Convo for a given ConvoId
    fn get_convo_mut(&mut self, convo_id: ConversationId) -> Result<&mut dyn Convo, ChatError> {
        self.store
            .get_mut(convo_id)
            .ok_or_else(|| ChatError::NoConvo(convo_id.into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conversation::GroupTestConvo;

    #[test]
    fn convo_store_get() {
        let mut store: ConversationStore = ConversationStore::new();

        let new_convo = GroupTestConvo::new();
        let convo_id = store.insert_convo(Box::new(new_convo));

        let convo = store.get_mut(&convo_id).ok_or(0);
        convo.unwrap();
    }

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
        // Use file-based storage to test real persistence
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir
            .path()
            .join("test_identity.db")
            .to_string_lossy()
            .to_string();
        let config = StorageConfig::File(db_path);

        // Create context - this should create and save a new identity
        let ctx1 = Context::open("alice", config.clone()).unwrap();
        let pubkey1 = ctx1._identity.public_key();
        let name1 = ctx1.installation_name().to_string();

        // Drop and reopen - should load the same identity
        drop(ctx1);
        let ctx2 = Context::open("alice", config).unwrap();
        let pubkey2 = ctx2._identity.public_key();
        let name2 = ctx2.installation_name().to_string();

        // Identity should be the same
        assert_eq!(pubkey1, pubkey2, "public key should persist");
        assert_eq!(name1, name2, "name should persist");
    }
}
