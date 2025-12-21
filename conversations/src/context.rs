use crate::conversation::{ConversationId, ConversationIdOwned, ConversationStore, PrivateV1Convo};

pub struct PayloadData {
    pub delivery_address: String,
    pub data: Vec<u8>,
}

pub struct ContentData {
    pub conversation_id: String,
    pub data: Vec<u8>,
}

pub struct Ctx {
    store: ConversationStore,
}

impl Ctx {
    pub fn new() -> Self {
        Self {
            store: ConversationStore::new(),
        }
    }

    pub fn create_private_convo(&mut self, _content: &[u8]) -> ConversationIdOwned {
        let new_convo = PrivateV1Convo::new();
        self.store.insert(new_convo)
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
