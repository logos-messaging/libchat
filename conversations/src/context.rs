use std::rc::Rc;

use crypto::PrekeyBundle;

use crate::{
    conversation::{ConversationId, ConversationIdOwned, ConversationStore},
    identity::Identity,
    inbox::Inbox,
    types::{ContentData, PayloadData},
};

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Ctx {
    _identity: Rc<Identity>,
    store: ConversationStore,
    inbox: Inbox,
}

impl Ctx {
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
        remote_bundle: &PrekeyBundle,
        content: String,
    ) -> ConversationIdOwned {
        let (convo, _payloads) = self
            .inbox
            .invite_to_private_convo(remote_bundle, content)
            .unwrap_or_else(|_| todo!("Log/Surface Error"));

        self.store.insert_convo(convo)

        // TODO: Change return type to handle outbout packets.
    }

    pub fn send_content(&mut self, _convo_id: ConversationId, _content: &[u8]) -> Vec<PayloadData> {
        // !TODO Replace Mock
        vec![PayloadData {
            delivery_address: _convo_id.into(),
            data: vec![40, 30, 20, 10],
        }]
    }

    pub fn handle_payload(&mut self, _payload: &[u8]) -> Option<ContentData> {
        // !TODO Replace Mock
        Some(ContentData {
            conversation_id: "convo_id".into(),
            data: vec![1, 2, 3, 4, 5, 6],
        })
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
