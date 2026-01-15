use crypto::PrekeyBundle;

use crate::{
    conversation::{ConversationId, ConversationIdOwned, ConversationStore},
    inbox::RemoteInbox,
    keystore::{IdentityProvider, InMemKeyStore},
};

// This struct represents Outbound data.
// It wraps an encoded payload with a delivery address, so it can be handled by the delivery service.
pub struct PayloadData {
    pub delivery_address: String,
    pub data: Vec<u8>,
}

// This struct represents the result of processed inbound data.
// It wraps content payload with a conversation_id
pub struct ContentData {
    pub conversation_id: String,
    pub data: Vec<u8>,
}

// This is the main entry point to the conversations api.
// Ctx manages lifetimes of objects to process and generate payloads.
pub struct Ctx {
    store: ConversationStore,
    keystore: InMemKeyStore,
}

impl Ctx {
    pub fn new() -> Self {
        Self {
            store: ConversationStore::new(),
            keystore: InMemKeyStore::new(),
        }
    }

    pub fn create_private_convo(
        &mut self,
        remote_bundle: &PrekeyBundle,
        content: String,
    ) -> ConversationIdOwned {
        let remote = RemoteInbox::new(self.keystore.identity());
        let convo = match remote.invite_to_private_convo(remote_bundle, content) {
            Ok(x) => x.0,
            Err(_) => todo!("Log/Surface Error"),
        };

        self.store.insert(convo)
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
        let convo_id = store.insert(new_convo);

        let convo = store.get_mut(&convo_id).ok_or_else(|| 0);
        convo.unwrap();
    }

    // #[test]
    // fn multi_convo_example() {
    //     // Bypass Lifetime erasure
    //     let raya_ident: &'static Identity = Box::leak(Box::new(Identity::new()));
    //     let mut store: ConversationStore = ConversationStore::new();

    //     let raya = Inbox::new(raya_ident);
    //     let saro = PrivateV1Convo::new([1u8; 32]);
    //     let pax = GroupTestConvo::new();

    //     store.insert_handler(raya);
    //     store.insert(saro);
    //     let convo_id = store.insert(pax);

    //     for id in store.conversation_ids().collect::<Vec<_>>() {
    //         let a = store.get_mut(&id).unwrap();
    //         a.send_message(b"test message").unwrap();
    //         println!("Conversation ID: {} :: {:?}", id, a);
    //     }

    //     for id in store.conversation_ids().collect::<Vec<_>>() {
    //         let a = store.get_mut(&id).unwrap();
    //         let _ = a.handle_frame(&[0x1, 0x2]);
    //     }
    //     println!("ID -> {}", store.get(&convo_id).unwrap().id());
    // }
}
