use client::{ChatClient, ConversationIdOwned, InProcessDelivery};
use std::sync::Arc;

fn main() {
    let delivery = InProcessDelivery::new(Default::default());
    let mut cursor = delivery.cursor_at_tail("delivery_address");

    let mut saro = ChatClient::new("saro", delivery.clone());
    let mut raya = ChatClient::new("raya", delivery);

    let raya_bundle = raya.create_intro_bundle().unwrap();
    saro.create_conversation(&raya_bundle, b"hello raya")
        .unwrap();

    let raw = cursor.next().unwrap();
    let content = raya.receive(&raw).unwrap().unwrap();
    println!(
        "Raya received: {:?}",
        std::str::from_utf8(&content.data).unwrap()
    );

    let raya_convo_id: ConversationIdOwned = Arc::from(content.conversation_id.as_str());
    raya.send_message(&raya_convo_id, b"hi saro").unwrap();

    let raw = cursor.next().unwrap();
    let content = saro.receive(&raw).unwrap().unwrap();
    println!(
        "Saro received: {:?}",
        std::str::from_utf8(&content.data).unwrap()
    );

    println!("Message exchange complete.");
}
