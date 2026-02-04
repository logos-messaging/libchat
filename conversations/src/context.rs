use std::rc::Rc;

use crate::{
    conversation::{ConversationStore, Convo, Id},
    errors::ChatError,
    identity::Identity,
    inbox::Inbox,
    types::{AddressedEnvelope, ContentData},
};

pub use crate::conversation::{ConversationId, ConversationIdOwned};
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
        content: String,
    ) -> (ConversationIdOwned, Vec<AddressedEnvelope>) {
        let (convo, payloads) = self
            .inbox
            .invite_to_private_convo(remote_bundle, content)
            .unwrap_or_else(|_| todo!("Log/Surface Error"));

        let payload_bytes = payloads
            .into_iter()
            .map(|p| p.to_envelope(convo.id().to_string()))
            .collect();

        let convo_id = self.add_convo(convo);
        (convo_id, payload_bytes)
    }

    pub fn send_content(
        &mut self,
        convo_id: ConversationId,
        content: &[u8],
    ) -> Result<Vec<AddressedEnvelope>, ChatError> {
        // Lookup convo from handle
        let convo = self.get_convo_mut(convo_id)?;

        // Generate encrypted payloads
        let payloads = convo.send_message(content)?;

        // Attach conversation_ids to Envelopes
        Ok(payloads
            .into_iter()
            .map(|p| p.to_envelope(convo.remote_id()))
            .collect())
    }

    pub fn handle_payload(&mut self, _payload: &[u8]) -> Option<ContentData> {
        // !TODO Replace Mock
        Some(ContentData {
            conversation_id: "convo_id".into(),
            data: vec![1, 2, 3, 4, 5, 6],
            isNewConvo: false,
        })
    }

    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        let pkb = self.inbox.create_bundle();
        Ok(Introduction::from(pkb).into())
    }

    fn add_convo(&mut self, convo: impl Convo + Id + 'static) -> ConversationIdOwned {
        let convo_id = self.store.insert_convo(convo);

        convo_id
    }

    // Returns a mutable reference to a Convo for a given ConvoId
    fn get_convo_mut(&mut self, convo_id: ConversationId) -> Result<&mut dyn Convo, ChatError> {
        self.store
            .get_mut(&convo_id)
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
        let convo_id = store.insert_convo(new_convo);

        let convo = store.get_mut(&convo_id).ok_or_else(|| 0);
        convo.unwrap();
    }
}
