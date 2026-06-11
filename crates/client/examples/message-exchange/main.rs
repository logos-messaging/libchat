use logos_chat::{ChatClient, Event, InProcessDelivery, MessageBus};
use std::time::Duration;

fn main() {
    let bus = MessageBus::default();
    let saro_delivery = InProcessDelivery::new(bus.clone());
    let raya_delivery = InProcessDelivery::new(bus);

    let (mut saro, saro_events) = ChatClient::new("saro", saro_delivery);
    let (mut raya, raya_events) = ChatClient::new("raya", raya_delivery);

    let raya_bundle = raya.create_intro_bundle().unwrap();
    saro.create_conversation(&raya_bundle, b"hello raya")
        .unwrap();

    // Raya's worker delivers the new conversation, then its initial message.
    let raya_convo_id = match raya_events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::ConversationStarted { convo_id, .. } => convo_id,
        other => panic!("expected ConversationStarted, got {other:?}"),
    };
    if let Event::MessageReceived { content, .. } =
        raya_events.recv_timeout(Duration::from_secs(5)).unwrap()
    {
        println!(
            "Raya received: {:?}",
            std::str::from_utf8(&content).unwrap()
        );
    }

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();

    if let Event::MessageReceived { content, .. } =
        saro_events.recv_timeout(Duration::from_secs(5)).unwrap()
    {
        println!(
            "Saro received: {:?}",
            std::str::from_utf8(&content).unwrap()
        );
    }

    println!("Message exchange complete.");
}
