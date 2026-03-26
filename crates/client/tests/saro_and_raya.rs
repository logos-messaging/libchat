use client::{
    ChatClient, ContentData, ConversationIdOwned, Cursor, InProcessDelivery, StorageConfig,
};
use std::sync::Arc;

fn receive(receiver: &mut ChatClient<InProcessDelivery>, cursor: &mut Cursor) -> ContentData {
    let raw = cursor.next().expect("expected envelope");
    receiver
        .receive(&raw)
        .expect("receive failed")
        .expect("expected content")
}

#[test]
fn saro_raya_message_exchange() {
    let delivery = InProcessDelivery::new(Default::default());
    let mut cursor = delivery.cursor_at_tail("delivery_address");

    let mut saro = ChatClient::new("saro", delivery.clone());
    let mut raya = ChatClient::new("raya", delivery);

    let raya_bundle = raya.create_intro_bundle().unwrap();
    let saro_convo_id = saro
        .create_conversation(&raya_bundle, b"hello raya")
        .unwrap();

    let content = receive(&mut raya, &mut cursor);
    assert_eq!(content.data, b"hello raya");
    assert!(content.is_new_convo);

    let raya_convo_id: ConversationIdOwned = Arc::from(content.conversation_id.as_str());

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    let content = receive(&mut saro, &mut cursor);
    assert_eq!(content.data, b"hi saro");
    assert!(!content.is_new_convo);

    for i in 0u8..5 {
        let msg = format!("msg {i}");
        saro.send_message(&saro_convo_id, msg.as_bytes()).unwrap();
        let content = receive(&mut raya, &mut cursor);
        assert_eq!(content.data, msg.as_bytes());

        let reply = format!("reply {i}");
        raya.send_message(&raya_convo_id, reply.as_bytes()).unwrap();
        let content = receive(&mut saro, &mut cursor);
        assert_eq!(content.data, reply.as_bytes());
    }

    assert_eq!(saro.list_conversations().unwrap().len(), 1);
    assert_eq!(raya.list_conversations().unwrap().len(), 1);
}

#[test]
fn open_persistent_client() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db").to_string_lossy().to_string();
    let config = StorageConfig::File(db_path);

    let client1 = ChatClient::open("saro", config.clone(), InProcessDelivery::default()).unwrap();
    let name1 = client1.installation_name().to_string();
    drop(client1);

    let client2 = ChatClient::open("saro", config, InProcessDelivery::default()).unwrap();
    let name2 = client2.installation_name().to_string();

    assert_eq!(
        name1, name2,
        "installation name should persist across restarts"
    );
}
