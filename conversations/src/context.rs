use std::rc::Rc;

use crate::{
    conversation::{ConversationId, ConversationStore, Convo, Id},
    errors::ChatError,
    identity::Identity,
    inbox::Inbox,
    proto::{EncryptedPayload, EnvelopeV1, Message},
    types::{AddressedEnvelope, ContentData},
};

pub use crate::conversation::ConversationIdOwned;
pub use crate::inbox::Introduction;

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context {
    _identity: Rc<Identity>,
    store: ConversationStore,
    inbox: Inbox,
}

impl Context {
    pub fn new() -> Self {
        let identity = Rc::new(Identity::new());
        let inbox = Inbox::new(Rc::clone(&identity)); //
        Self {
            _identity: identity,
            store: ConversationStore::new(),
            inbox,
        }
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

        let remote_id = Inbox::inbox_identifier_for_key(remote_bundle.installation_key);
        let payload_bytes = payloads
            .into_iter()
            .map(|p| p.into_envelope(remote_id.clone()))
            .collect();

        let convo_id = self.add_convo(Box::new(convo));
        (convo_id, payload_bytes)
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
            _ => Err(ChatError::NoConvo(convo_id)),
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
        let pkb = self.inbox.create_bundle();
        Ok(Introduction::from(pkb).into())
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
}
