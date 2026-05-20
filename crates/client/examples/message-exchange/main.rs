use std::sync::mpsc;
use std::time::Duration;

use logos_chat::{ChatClient, ConversationIdOwned, Event, InProcessDelivery};

fn main() {
    let delivery = InProcessDelivery::new(Default::default());

    let (mut saro, saro_events) = ChatClient::new("saro", delivery.clone());
    let (mut raya, raya_events) = ChatClient::new("raya", delivery);

    let raya_bundle = raya.create_intro_bundle().unwrap();
    let (_saro_convo_id, _events) = saro
        .create_conversation(&raya_bundle, b"hello raya")
        .unwrap();

    let raya_convo_id = expect_invite(&raya_events, "Raya");

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    expect_message(&saro_events, "Saro");

    println!("Message exchange complete.");
}

fn expect_invite(events: &mpsc::Receiver<Event>, who: &str) -> ConversationIdOwned {
    let started = events.recv_timeout(Duration::from_secs(5)).unwrap();
    let convo_id = match started {
        Event::ConversationStarted {
            conversation_id, ..
        } => conversation_id,
        other => panic!("expected ConversationStarted, got {other:?}"),
    };
    let received = events.recv_timeout(Duration::from_secs(5)).unwrap();
    match received {
        Event::MessageReceived { data, .. } => {
            println!("{who} received: {:?}", std::str::from_utf8(&data).unwrap());
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }
    convo_id
}

fn expect_message(events: &mpsc::Receiver<Event>, who: &str) {
    let event = events.recv_timeout(Duration::from_secs(5)).unwrap();
    match event {
        Event::MessageReceived { data, .. } => {
            println!("{who} received: {:?}", std::str::from_utf8(&data).unwrap());
        }
        other => panic!("expected MessageReceived, got {other:?}"),
    }
}
