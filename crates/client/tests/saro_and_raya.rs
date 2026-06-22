use std::time::Duration;

use components::EphemeralRegistry;
use crossbeam_channel::{Receiver, Sender};
use libchat::IdentityProvider;
use logos_account::TestLogosAccount;
use logos_chat::{
    AddressedEnvelope, ChatClient, DelegateSigner, DeliveryService, Event, InProcessDelivery,
    MessageBus, StorageConfig, Transport,
};

/// Block until the next event arrives and matches; panic on timeout/mismatch.
fn expect_event<F, T>(events: &Receiver<Event>, label: &str, mut f: F) -> T
where
    F: FnMut(Event) -> Result<T, Event>,
{
    let event = events
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_else(|_| panic!("timed out waiting for {label}"));
    f(event).unwrap_or_else(|other| panic!("expected {label}, got {other:?}"))
}

#[test]
fn direct_v1_integration() {
    let bus = MessageBus::default();
    let saro_delivery = InProcessDelivery::new(bus.clone());
    let raya_delivery = InProcessDelivery::new(bus);

    let reg_service = EphemeralRegistry::new();

    // Create Accounts, Deletage and Associate the two.
    let saro_account = TestLogosAccount::new("Saro");
    let mut saro_delegate = DelegateSigner::random();
    // TODO: Submit Delegate to Account for auth.
    saro_delegate.associate(saro_account.id().to_string());

    let raya_account = TestLogosAccount::new("Raya");
    let mut raya_delegate = DelegateSigner::random();
    // TODO: Submit Delegate to Account for auth.
    raya_delegate.associate(raya_account.id().to_string());
    let raya_delegate_id = raya_delegate.id().clone();

    let (mut saro, _saro_events) =
        ChatClient::new_ephemeral(saro_delegate, saro_delivery, reg_service.clone()).unwrap();
    let (_raya, raya_events) =
        ChatClient::new_ephemeral(raya_delegate, raya_delivery, reg_service.clone()).unwrap();

    let convo_id = saro
        .create_direct_conversation(raya_delegate_id.as_str())
        .unwrap();

    // The invite payload yields ConversationStarted then MessageReceived.
    expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, .. } => Ok(convo_id),
        other => Err(other),
    });

    saro.send_message(&convo_id, b"Hey from saro")
        .expect("payload mismatch");
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived { content, .. } => {
            assert_eq!(content.as_slice(), b"Hey from saro");
            Ok(())
        }
        other => Err(other),
    });
}

#[test]
fn saro_raya_message_exchange() {
    let bus = MessageBus::default();
    let saro_delivery = InProcessDelivery::new(bus.clone());
    let raya_delivery = InProcessDelivery::new(bus);

    let (mut saro, saro_events) = ChatClient::new("saro", saro_delivery);
    let (mut raya, raya_events) = ChatClient::new("raya", raya_delivery);

    let raya_bundle = raya.create_intro_bundle().unwrap();
    let saro_convo_id = saro
        .create_conversation(&raya_bundle, b"hello raya")
        .unwrap();

    // The invite payload yields ConversationStarted then MessageReceived.
    let raya_convo_id = expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, .. } => Ok(convo_id),
        other => Err(other),
    });
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived { convo_id, content } => {
            assert_eq!(convo_id, raya_convo_id);
            assert_eq!(content.as_slice(), b"hello raya");
            Ok(())
        }
        other => Err(other),
    });

    raya.send_message(&raya_convo_id, b"hi saro").unwrap();
    expect_event(&saro_events, "MessageReceived", |e| match e {
        Event::MessageReceived { content, .. } => {
            assert_eq!(content.as_slice(), b"hi saro");
            Ok(())
        }
        other => Err(other),
    });

    for i in 0u8..5 {
        let msg = format!("msg {i}");
        saro.send_message(&saro_convo_id, msg.as_bytes()).unwrap();
        expect_event(
            &raya_events,
            &format!("MessageReceived(msg {i})"),
            |e| match e {
                Event::MessageReceived { content, .. } => {
                    assert_eq!(content.as_slice(), msg.as_bytes());
                    Ok(())
                }
                other => Err(other),
            },
        );

        let reply = format!("reply {i}");
        raya.send_message(&raya_convo_id, reply.as_bytes()).unwrap();
        expect_event(
            &saro_events,
            &format!("MessageReceived(reply {i})"),
            |e| match e {
                Event::MessageReceived { content, .. } => {
                    assert_eq!(content.as_slice(), reply.as_bytes());
                    Ok(())
                }
                other => Err(other),
            },
        );
    }

    assert_eq!(saro.list_conversations().unwrap().len(), 1);
    assert_eq!(raya.list_conversations().unwrap().len(), 1);
}

#[derive(Debug)]
struct FailingDelivery {
    inbound_tx: Sender<Vec<u8>>,
    inbound_rx: Option<Receiver<Vec<u8>>>,
}

impl FailingDelivery {
    fn new() -> Self {
        let (inbound_tx, inbound_rx) = crossbeam_channel::unbounded();
        Self {
            inbound_tx,
            inbound_rx: Some(inbound_rx),
        }
    }

    /// A sender into this transport's inbound stream — for tests to feed the
    /// worker, or to hold open so it doesn't see a disconnect.
    fn inbound_sender(&self) -> Sender<Vec<u8>> {
        self.inbound_tx.clone()
    }
}

impl DeliveryService for FailingDelivery {
    type Error = &'static str;

    fn publish(&mut self, _: AddressedEnvelope) -> Result<(), Self::Error> {
        Err("simulated transport failure")
    }

    fn subscribe(&mut self, _: &str) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Transport for FailingDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        self.inbound_rx
            .take()
            .expect("FailingDelivery::inbound called more than once")
    }
}

#[test]
fn dropping_client_shuts_down_worker() {
    let delivery = InProcessDelivery::new(MessageBus::default());
    let (client, events) = ChatClient::new("saro", delivery);
    drop(client);
    // Drop joins the worker; once joined its Sender<Event> is gone, so recv
    // reports the channel as disconnected.
    let res = events.recv_timeout(Duration::from_secs(5));
    assert!(matches!(
        res,
        Err(crossbeam_channel::RecvTimeoutError::Disconnected)
    ));
}

#[test]
fn publish_failure_surfaces_as_error() {
    // A real raya just to mint a valid intro bundle.
    let raya_delivery = InProcessDelivery::new(MessageBus::default());
    let (mut raya, _raya_events) = ChatClient::new("raya", raya_delivery);
    let bundle = raya.create_intro_bundle().unwrap();

    // FailingDelivery never receives; keep the inbound sender alive so the
    // worker doesn't exit early on a disconnected channel.
    let delivery = FailingDelivery::new();
    let _keep_inbound = delivery.inbound_sender();
    let (mut saro, _saro_events) = ChatClient::new("saro", delivery);
    let result = saro.create_conversation(&bundle, b"hello");
    assert!(
        result.is_err(),
        "publish failure should surface as an error on the synchronous call"
    );
}

#[test]
fn malformed_inbound_surfaces_as_error_event() {
    // Feed the worker's inbound channel bytes that can't be decoded and assert
    // it emits an InboundError instead of silently dropping the failure.
    let delivery = FailingDelivery::new();
    let inbound_tx = delivery.inbound_sender();
    let (_saro, events) = ChatClient::new("saro", delivery);

    inbound_tx.send(b"not a valid payload".to_vec()).unwrap();

    expect_event(&events, "InboundError", |e| match e {
        Event::InboundError { message } => {
            assert!(!message.is_empty(), "error event should carry a message");
            Ok(())
        }
        other => Err(other),
    });
}

#[test]
fn open_persistent_client() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("test.db").to_string_lossy().to_string();
    let config = StorageConfig::File(db_path);

    let delivery1 = InProcessDelivery::new(MessageBus::default());
    let (client1, _events1) = ChatClient::open("saro", config.clone(), delivery1).unwrap();
    let name1 = client1.installation_name();
    drop(client1);

    let delivery2 = InProcessDelivery::new(MessageBus::default());
    let (client2, _events2) = ChatClient::open("saro", config, delivery2).unwrap();
    let name2 = client2.installation_name();

    assert_eq!(
        name1, name2,
        "installation name should persist across restarts"
    );
}
