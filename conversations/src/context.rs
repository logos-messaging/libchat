use std::{collections::HashMap, rc::Rc, sync::Arc};

use crate::{
    conversation::{ConversationStore, Convo, Id},
    errors::ChatError,
    identity::Identity,
    inbox::Inbox,
    types::{AddressedEnvelope, ContentData},
};

pub use crate::inbox::Introduction;

//Offset handles to make debuging easier
const INITIAL_CONVO_HANDLE: u32 = 0xF5000001;

/// Used to identify a conversation on the othersize of the FFI.
pub type ConvoHandle = u32;

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Context {
    _identity: Rc<Identity>,
    store: ConversationStore,
    inbox: Inbox,
    buf_size: usize,
    convo_handle_map: HashMap<u32, Arc<str>>,
    next_convo_handle: ConvoHandle,
}

impl Context {
    pub fn new() -> Self {
        let identity = Rc::new(Identity::new());
        let inbox = Inbox::new(Rc::clone(&identity)); //
        Self {
            _identity: identity,
            store: ConversationStore::new(),
            inbox,
            buf_size: 0,
            convo_handle_map: HashMap::new(),
            next_convo_handle: INITIAL_CONVO_HANDLE,
        }
    }

    pub fn buffer_size(&self) -> usize {
        self.buf_size
    }

    pub fn set_buffer_size(&mut self, size: usize) {
        self.buf_size = size
    }

    pub fn create_private_convo(
        &mut self,
        remote_bundle: &Introduction,
        content: String,
    ) -> (ConvoHandle, Vec<AddressedEnvelope>) {
        let (convo, payloads) = self
            .inbox
            .invite_to_private_convo(remote_bundle, content)
            .unwrap_or_else(|_| todo!("Log/Surface Error"));

        let payload_bytes = payloads
            .into_iter()
            .map(|p| p.stamp_to(convo.id().to_string()))
            .collect();

        let convo_handle = self.add_convo(convo);
        (convo_handle, payload_bytes)
    }

    pub fn send_content(
        &mut self,
        convo_handle: ConvoHandle,
        content: &[u8],
    ) -> Result<Vec<AddressedEnvelope>, ChatError> {
        // Lookup convo from handle
        let convo = self.get_convo_mut(convo_handle)?;

        // Generate encrypted payloads
        let payloads = convo.send_message(content)?;

        // Attach conversation_ids to Envelopes
        Ok(payloads
            .into_iter()
            .map(|p| p.stamp_to(convo.remote_id()))
            .collect())
    }

    pub fn handle_payload(&mut self, _payload: &[u8]) -> Option<ContentData> {
        // !TODO Replace Mock
        Some(ContentData {
            conversation_id: "convo_id".into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
    }

    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ChatError> {
        let pkb = self.inbox.create_bundle();
        Ok(Introduction::from(pkb).into())
    }

    fn add_convo(&mut self, convo: impl Convo + Id + 'static) -> ConvoHandle {
        let handle = self.next_convo_handle;
        self.next_convo_handle += 1;
        let convo_id = self.store.insert_convo(convo);
        self.convo_handle_map.insert(handle, convo_id);

        handle
    }

    // Returns a mutable reference to a Convo for a given ConvoHandle
    fn get_convo_mut(&mut self, handle: ConvoHandle) -> Result<&mut dyn Convo, ChatError> {
        let convo_id = self
            .convo_handle_map
            .get(&handle)
            .ok_or_else(|| ChatError::NoConvo(handle))?
            .clone();

        self.store
            .get_mut(&convo_id)
            .ok_or_else(|| ChatError::NoConvo(handle))
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
