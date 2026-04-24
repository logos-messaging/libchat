// use std::ops::{Deref, DerefMut};

// use components::{EphemeralRegistry, LocalBroadcaster, MemStore};
// use libchat::{
//     AddressedEnvelope, ChatStorage, ContentData, Context, ConversationIdOwned, Introduction,
//     StorageConfig,
// };

// fn send_and_verify(
//     sender: &mut Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>,
//     receiver: &mut Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>,
//     convo_id: &str,
//     content: &[u8],
// ) {
//     let payloads = sender.send_content(convo_id, content).unwrap();
//     let payload = payloads.first().unwrap();
//     let received = receiver
//         .handle_payload(&payload.data)
//         .unwrap()
//         .expect("expected content");
//     assert_eq!(content, received.data.as_slice());
//     assert!(!received.is_new_convo);
// }
