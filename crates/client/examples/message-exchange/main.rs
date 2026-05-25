use logos_chat::{ChatClient, ConversationIdOwned, Event, InProcessDelivery};
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
    let events = raya.receive(&raw).unwrap();
    let raya_convo_id: ConversationIdOwned = events
        .iter()
        .find_map(|e| match e {
            Event::ConversationStarted { convo_id, .. } => Some(Arc::clone(convo_id)),
            _ => None,
        })
        .expect("expected ConversationStarted");
    for event in &events {
        if let Event::MessageReceived { content, .. } = event {
            println!("Raya received: {:?}", std::str::from_utf8(content).unwrap());
        }
    }

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();

    let raw = cursor.next().unwrap();
    let events = saro.receive(&raw).unwrap();
    for event in &events {
        if let Event::MessageReceived { content, .. } = event {
            println!("Saro received: {:?}", std::str::from_utf8(content).unwrap());
        }
    }

    println!("Message exchange complete.");
}
