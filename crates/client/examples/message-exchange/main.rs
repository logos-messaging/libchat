use components::EphemeralRegistry;
use logos_chat::{ChatClientBuilder, Event, InProcessDelivery, MessageBus};
use std::time::Duration;

fn main() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, saro_events) = ChatClientBuilder::new()
        .transport(InProcessDelivery::new(bus.clone()))
        .registration(reg.clone())
        .build()
        .unwrap();

    let (mut raya, raya_events) = ChatClientBuilder::new()
        .transport(InProcessDelivery::new(bus))
        .registration(reg)
        .build()
        .unwrap();

    let raya_bundle = raya.create_intro_bundle().unwrap();
    #[allow(deprecated)]
    saro.create_conversation(&raya_bundle, b"hello raya")
        .unwrap();

    let raya_convo_id = match raya_events.recv_timeout(Duration::from_secs(5)).unwrap() {
        Event::ConversationStarted { convo_id, .. } => convo_id,
        other => panic!("expected ConversationStarted, got {other:?}"),
    };
    if let Event::MessageReceived { content, .. } =
        raya_events.recv_timeout(Duration::from_secs(5)).unwrap()
    {
        println!("Raya received: {:?}", std::str::from_utf8(&content).unwrap());
    }

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();

    if let Event::MessageReceived { content, .. } =
        saro_events.recv_timeout(Duration::from_secs(5)).unwrap()
    {
        println!("Saro received: {:?}", std::str::from_utf8(&content).unwrap());
    }

    println!("Message exchange complete.");
}
