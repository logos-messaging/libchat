use std::sync::mpsc;
use std::time::Duration;

use logos_chat::{
    AddressedEnvelope, ChatClient, DeliveryService, Event, InProcessDelivery, StorageConfig,
};

fn expect_event<F, T>(events: &mpsc::Receiver<Event>, label: &str, mut f: F) -> T
where
    F: FnMut(Event) -> Result<T, Event>,
{
    let event = events
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
    f(event).unwrap_or_else(|other| panic!("expected {label}, got {other:?}"))
}

#[test]
fn saro_raya_message_exchange() {
    let delivery = InProcessDelivery::new(Default::default());

    let (mut saro, saro_events) = ChatClient::new("saro", delivery.clone());
    let (mut raya, raya_events) = ChatClient::new("raya", delivery);

    let raya_bundle = raya.create_intro_bundle().unwrap();
    let (saro_convo_id, send_events) = saro
        .create_conversation(&raya_bundle, b"hello raya")
        .unwrap();
    assert!(
        send_events.is_empty(),
        "unexpected send events: {send_events:?}"
    );

    // The invite payload yields ConversationStarted then MessageReceived.
    let raya_convo_id = expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted {
            conversation_id, ..
        } => Ok(conversation_id),
        other => Err(other),
    });
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived {
            conversation_id,
            data,
            ..
        } => {
            assert_eq!(conversation_id, raya_convo_id);
            assert_eq!(data.as_slice(), b"hello raya");
            Ok(())
        }
        other => Err(other),
    });

    let send_events = raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    assert!(send_events.is_empty());
    expect_event(&saro_events, "MessageReceived", |e| match e {
        Event::MessageReceived { data, .. } => {
            assert_eq!(data.as_slice(), b"hi saro");
            Ok(())
        }
        other => Err(other),
    });

    for i in 0u8..5 {
        let msg = format!("msg {i}");
        let send_events = saro.send_message(&saro_convo_id, msg.as_bytes()).unwrap();
        assert!(send_events.is_empty());
        expect_event(
            &raya_events,
            &format!("MessageReceived(msg {i})"),
            |e| match e {
                Event::MessageReceived { data, .. } => {
                    assert_eq!(data.as_slice(), msg.as_bytes());
                    Ok(())
                }
                other => Err(other),
            },
        );

        let reply = format!("reply {i}");
        let send_events = raya.send_message(&raya_convo_id, reply.as_bytes()).unwrap();
        assert!(send_events.is_empty());
        expect_event(
            &saro_events,
            &format!("MessageReceived(reply {i})"),
            |e| match e {
                Event::MessageReceived { data, .. } => {
                    assert_eq!(data.as_slice(), reply.as_bytes());
                    Ok(())
                }
                other => Err(other),
            },
        );
    }

    assert_eq!(saro.list_conversations().unwrap().len(), 1);
    assert_eq!(raya.list_conversations().unwrap().len(), 1);
}

#[derive(Debug, Default)]
struct FailingDelivery;

impl DeliveryService for FailingDelivery {
    type Error = &'static str;

    fn publish(&self, _: AddressedEnvelope) -> Result<(), Self::Error> {
        Err("simulated transport failure")
    }

    fn subscribe(&self, _: &str) -> Result<(), Self::Error> {
        Ok(())
    }

    fn pull(&self) -> Vec<Vec<u8>> {
        Vec::new()
    }
}

#[test]
fn dropping_client_shuts_down_translator() {
    let (client, events) = ChatClient::new("saro", InProcessDelivery::default());
    drop(client);
    // Drop must join the translator thread; once joined, the translator's
    // Sender<Event> is gone and recv returns Disconnected immediately.
    let res = events.recv_timeout(Duration::from_secs(5));
    assert!(matches!(res, Err(mpsc::RecvTimeoutError::Disconnected)));
}

#[test]
fn publish_failure_surfaces_as_event() {
    // Spin a real raya just to mint a valid intro bundle.
    let (mut raya, _) = ChatClient::new("raya", InProcessDelivery::default());
    let bundle = raya.create_intro_bundle().unwrap();

    let (mut saro, _) = ChatClient::new("saro", FailingDelivery);
    let (_, send_events) = saro.create_conversation(&bundle, b"hello").unwrap();
    assert!(
        send_events.iter().any(Event::is_delivery_failure),
        "expected a DeliveryFailed event, got {send_events:?}"
    );
}

#[test]
fn open_persistent_client() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db").to_string_lossy().to_string();
    let config = StorageConfig::File(db_path);

    let (client1, _events1) =
        ChatClient::open("saro", config.clone(), InProcessDelivery::default()).unwrap();
    let name1 = client1.installation_name();
    drop(client1);

    let (client2, _events2) =
        ChatClient::open("saro", config, InProcessDelivery::default()).unwrap();
    let name2 = client2.installation_name();

    assert_eq!(
        name1, name2,
        "installation name should persist across restarts"
    );
}
