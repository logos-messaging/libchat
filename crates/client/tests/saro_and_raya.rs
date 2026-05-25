use logos_chat::{
    ChatClient, ConversationClass, ConversationIdOwned, Cursor, Event, InProcessDelivery,
    StorageConfig,
};
use std::sync::Arc;

/// Pulls one envelope, decrypts, and returns the events emitted.
fn receive(receiver: &mut ChatClient<InProcessDelivery>, cursor: &mut Cursor) -> Vec<Event> {
    let raw = cursor.next().expect("expected envelope");
    receiver.receive(&raw).expect("receive failed")
}

fn expect_message(event: &Event) -> (&ConversationIdOwned, &[u8]) {
    match event {
        Event::MessageReceived {
            convo_id, content, ..
        } => (convo_id, content.as_slice()),
        other => panic!("expected MessageReceived, got {other:?}"),
    }
}

fn expect_conversation_started(event: &Event) -> (&ConversationIdOwned, ConversationClass) {
    match event {
        Event::ConversationStarted {
            convo_id, class, ..
        } => (convo_id, *class),
        other => panic!("expected ConversationStarted, got {other:?}"),
    }
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

    let events = receive(&mut raya, &mut cursor);
    assert_eq!(
        events.len(),
        2,
        "expected ConversationStarted + MessageReceived"
    );
    let (started_id, class) = expect_conversation_started(&events[0]);
    assert_eq!(class, ConversationClass::Private);
    let (msg_id, content) = expect_message(&events[1]);
    assert_eq!(content, b"hello raya");
    assert_eq!(started_id, msg_id);
    let raya_convo_id: ConversationIdOwned = Arc::clone(started_id);

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    let events = receive(&mut saro, &mut cursor);
    assert_eq!(events.len(), 1);
    let (_, content) = expect_message(&events[0]);
    assert_eq!(content, b"hi saro");

    for i in 0u8..5 {
        let msg = format!("msg {i}");
        saro.send_message(&saro_convo_id, msg.as_bytes()).unwrap();
        let events = receive(&mut raya, &mut cursor);
        assert_eq!(events.len(), 1);
        let (_, content) = expect_message(&events[0]);
        assert_eq!(content, msg.as_bytes());

        let reply = format!("reply {i}");
        raya.send_message(&raya_convo_id, reply.as_bytes()).unwrap();
        let events = receive(&mut saro, &mut cursor);
        assert_eq!(events.len(), 1);
        let (_, content) = expect_message(&events[0]);
        assert_eq!(content, reply.as_bytes());
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
