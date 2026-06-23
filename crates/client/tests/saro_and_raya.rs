use std::time::Duration;

use components::EphemeralRegistry;
use crossbeam_channel::{Receiver, Sender};
use crypto::Ed25519VerifyingKey;
use libchat::{AccountDirectory, IdentityProvider, SignedDeviceBundle, encode_bundle_payload};
use logos_account::TestLogosAccount;
use logos_chat::{
    AddressedEnvelope, ChatClient, ChatClientBuilder, DelegateSigner, DeliveryService, Event,
    InProcessDelivery, MessageBus, Transport,
};

/// Publish a signed device bundle endorsing `device` as a device of `account`,
/// so a receiver can verify the sender's account → device mapping.
fn publish_device_bundle(
    reg: &mut EphemeralRegistry,
    account: &TestLogosAccount,
    device: &Ed25519VerifyingKey,
) {
    let payload = encode_bundle_payload(0, std::slice::from_ref(device));
    let signature = account.sign(&payload);
    let bundle = SignedDeviceBundle {
        account_pub: account.public_key().clone(),
        payload,
        signature,
    };
    reg.publish(&bundle).unwrap();
}

#[allow(clippy::type_complexity)]
fn create_test_client(
    message_bus: MessageBus,
    reg: EphemeralRegistry,
) -> Result<
    (
        ChatClient<DelegateSigner, InProcessDelivery, EphemeralRegistry, libchat::ChatStorage>,
        Receiver<Event>,
    ),
    logos_chat::ClientError,
> {
    let d = InProcessDelivery::new(message_bus);
    ChatClientBuilder::new()
        .transport(d)
        .registration(reg)
        .build()
}

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
    let reg_service = EphemeralRegistry::new();

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");
    let (raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");

    let convo_id = saro.create_direct_conversation(raya.addr()).unwrap();

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
fn direct_v1_standalone_integration() {
    let bus = MessageBus::default();

    let mut reg_service = EphemeralRegistry::new();

    // Create accounts and delegates, associate each delegate with its account
    // address, and publish a device bundle so the receiver can verify the
    // account → device mapping carried in the sender's credential.
    let saro_account = TestLogosAccount::new("Saro");
    let saro_account_id = hex::encode(saro_account.public_key().as_ref());
    let mut saro_delegate = DelegateSigner::random();
    saro_delegate.associate(saro_account_id.clone());
    let saro_device_id = hex::encode(saro_delegate.public_key().as_ref());
    publish_device_bundle(&mut reg_service, &saro_account, saro_delegate.public_key());

    let raya_account = TestLogosAccount::new("Raya");
    let mut raya_delegate = DelegateSigner::random();
    raya_delegate.associate(hex::encode(raya_account.public_key().as_ref()));
    publish_device_bundle(&mut reg_service, &raya_account, raya_delegate.public_key());

    let (mut saro, _saro_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");
    let (raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");

    let raya_addr = raya.addr();
    let convo_id = saro.create_direct_conversation(raya_addr).unwrap();

    // The invite payload yields ConversationStarted then MessageReceived.
    expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, .. } => Ok(convo_id),
        other => Err(other),
    });

    saro.send_message(&convo_id, b"Hey from saro")
        .expect("payload mismatch");
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived { content, sender, .. } => {
            assert_eq!(content.as_slice(), b"Hey from saro");
            // saro associated an account and published a matching bundle, so the
            // sender surfaces with a verified account and its device.
            let sender = sender.expect("verified sender present");
            assert_eq!(
                sender.account.as_ref().map(|a| a.as_str()),
                Some(saro_account_id.as_str())
            );
            assert_eq!(sender.local_identity.as_str(), saro_device_id.as_str());
            Ok(())
        }
        other => Err(other),
    });
}

#[test]
fn saro_raya_message_exchange() {
    let bus = MessageBus::default();
    let reg_service = EphemeralRegistry::new();

    let (mut saro, saro_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");
    let (mut raya, raya_events) =
        create_test_client(bus.clone(), reg_service.clone()).expect("client create");

    let saro_convo_id = saro
        .create_direct_conversation(raya.addr())
        .expect("convo create");

    // Wait for raya to process the Welcome and subscribe to the convo delivery
    // address before saro sends — MessageBus only fans out to current subscribers,
    // so a message sent before raya subscribes would be silently dropped.
    let raya_convo_id = expect_event(&raya_events, "ConversationStarted", |e| match e {
        Event::ConversationStarted { convo_id, .. } => Ok(convo_id),
        other => Err(other),
    });

    saro.send_message(&saro_convo_id, b"hello raya").unwrap();
    expect_event(&raya_events, "MessageReceived", |e| match e {
        Event::MessageReceived {
            convo_id,
            content,
            sender,
        } => {
            assert_eq!(convo_id, raya_convo_id);
            assert_eq!(content.as_slice(), b"hello raya");
            // PrivateV1 1:1 carries no credential, so there is no sender.
            assert!(sender.is_none());
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
    let (client, events) =
        create_test_client(MessageBus::default(), EphemeralRegistry::new()).expect("client create");

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
fn malformed_inbound_surfaces_as_error_event() {
    // Feed the worker's inbound channel bytes that can't be decoded and assert
    // it emits an InboundError instead of silently dropping the failure.
    let delivery = FailingDelivery::new();
    let inbound_tx = delivery.inbound_sender();

    let (_client, events) = ChatClientBuilder::new()
        .transport(delivery)
        .build()
        .expect("client create");

    inbound_tx.send(b"not a valid payload".to_vec()).unwrap();

    expect_event(&events, "InboundError", |e| match e {
        Event::InboundError { message } => {
            assert!(!message.is_empty(), "error event should carry a message");
            Ok(())
        }
        other => Err(other),
    });
}
