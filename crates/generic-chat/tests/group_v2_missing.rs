//! A GroupV2 message lost in transit reaches the application as
//! [`Event::MessageMissing`].
//!
//! Saro and Raya share a group over the in-process bus, with Raya's transport
//! wrapped so one inbound payload can be swallowed. Saro sends three messages;
//! Raya never receives the second, and the third's causal history reveals it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use components::EphemeralRegistry;
use crossbeam_channel::{Receiver, Sender, unbounded};
use libchat::ChatStorage;
use logos_account::TestLogosAccount;
use logos_generic_chat::{
    AddressedEnvelope, ChatClient, ChatClientBuilder, DelegateSigner, DeliveryService, Event,
    GroupMetadata, GroupV2Config, InProcessDelivery, MessageBus, Transport,
};

/// Millisecond GroupV2 timers so the de-mls commit/consensus dance completes in
/// test time; the library defaults wait 60s before committing an add.
fn fast_group_v2_config() -> GroupV2Config {
    GroupV2Config {
        commit_inactivity_duration: Duration::from_millis(50),
        freeze_duration: Duration::from_millis(20),
        voting_delay: Duration::from_millis(30),
        election_voting_delay: Duration::from_millis(30),
        consensus_timeout: Duration::from_millis(150),
        proposal_expiration: Duration::from_millis(2000),
        ..GroupV2Config::default()
    }
}

/// An [`InProcessDelivery`] whose inbound stream can be told to swallow the
/// next payload, simulating a frame the transport never delivered.
///
/// The filter sits on the receiving side only: the payload is published to the
/// bus as usual and simply never reaches this client's core.
#[derive(Debug)]
struct LossyDelivery {
    inner: InProcessDelivery,
    drop_next: Arc<AtomicBool>,
}

impl LossyDelivery {
    fn new(bus: MessageBus) -> (Self, Arc<AtomicBool>) {
        let drop_next = Arc::new(AtomicBool::new(false));
        let delivery = Self {
            inner: InProcessDelivery::new(bus),
            drop_next: Arc::clone(&drop_next),
        };
        (delivery, drop_next)
    }
}

impl DeliveryService for LossyDelivery {
    type Error = <InProcessDelivery as DeliveryService>::Error;

    fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error> {
        self.inner.publish(envelope)
    }

    fn subscribe(&mut self, delivery_address: &str) -> Result<(), Self::Error> {
        self.inner.subscribe(delivery_address)
    }
}

impl Transport for LossyDelivery {
    fn inbound(&mut self) -> Receiver<Vec<u8>> {
        let source = self.inner.inbound();
        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = unbounded();
        let drop_next = Arc::clone(&self.drop_next);
        // Relay every payload through, minus the one the test armed a drop for.
        std::thread::spawn(move || {
            for payload in source {
                if drop_next.swap(false, Ordering::SeqCst) {
                    continue;
                }
                if tx.send(payload).is_err() {
                    return; // client gone
                }
            }
        });
        rx
    }
}

/// Mint an account and delegate, publish the endorsing bundle, and build a
/// client on `transport`. Returns the account address peers invite by.
fn create_client<T: Transport + Send + 'static>(
    mut reg: EphemeralRegistry,
    transport: T,
) -> (
    ChatClient<T, EphemeralRegistry, ChatStorage>,
    Receiver<Event>,
    String,
) {
    let account = TestLogosAccount::new();
    let delegate = DelegateSigner::random();
    account
        .add_delegate_signer(&mut reg, delegate.public_key())
        .unwrap();
    let (client, events) = ChatClientBuilder::new(account.address())
        .ident(delegate)
        .transport(transport)
        .registration(reg)
        .group_v2_config(fast_group_v2_config())
        .build()
        .expect("client create");
    let addr = client.addr().to_string();
    (client, events, addr)
}

/// Wait until an event matching `f` arrives, skipping unrelated events (group
/// protocol traffic can interleave observations); panic after `timeout`.
fn wait_for_event<F, T>(events: &Receiver<Event>, label: &str, timeout: Duration, mut f: F) -> T
where
    F: FnMut(&Event) -> Option<T>,
{
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .unwrap_or_else(|| panic!("timed out waiting for {label}"));
        match events.recv_timeout(remaining) {
            Ok(event) => {
                if let Some(out) = f(&event) {
                    return out;
                }
            }
            Err(_) => panic!("timed out waiting for {label}"),
        }
    }
}

fn wait_for_message(events: &Receiver<Event>, content: &[u8]) {
    let label = format!("MessageReceived({})", String::from_utf8_lossy(content));
    wait_for_event(events, &label, Duration::from_secs(10), |e| match e {
        Event::MessageReceived { content: got, .. } if got == content => Some(()),
        _ => None,
    })
}

#[test]
fn a_dropped_group_v2_message_is_reported_to_the_application() {
    let bus = MessageBus::default();
    let reg = EphemeralRegistry::new();

    let (mut saro, _saro_events, saro_addr) =
        create_client(reg.clone(), InProcessDelivery::new(bus.clone()));
    let (lossy, drop_next) = LossyDelivery::new(bus.clone());
    let (_raya, raya_events, raya_addr) = create_client(reg.clone(), lossy);

    let convo_id = saro
        .create_group_conversation(&[&raya_addr], GroupMetadata::new("", ""))
        .expect("saro create group");

    wait_for_event(
        &raya_events,
        "raya ConversationStarted",
        Duration::from_secs(10),
        |e| match e {
            Event::ConversationStarted { convo_id, .. } => Some(convo_id.to_string()),
            _ => None,
        },
    );

    // M1 arrives normally, which also proves the group is live on both sides.
    saro.send_message(&convo_id, b"first").expect("send m1");
    wait_for_message(&raya_events, b"first");

    // Let the group go quiet, so the payload the drop swallows is M2 and not a
    // straggler of the join dance.
    std::thread::sleep(Duration::from_millis(300));
    while raya_events.try_recv().is_ok() {}

    // M2 is published but never reaches Raya's core.
    drop_next.store(true, Ordering::SeqCst);
    saro.send_message(&convo_id, b"second").expect("send m2");

    // M3 is delivered; its causal history references the dropped M2.
    saro.send_message(&convo_id, b"third").expect("send m3");

    let (message_id, sender_hint) = wait_for_event(
        &raya_events,
        "raya MessageMissing",
        Duration::from_secs(10),
        |e| match e {
            Event::MessageMissing {
                convo_id: id,
                message_id,
                sender_hint,
            } if **id == *convo_id => Some((message_id.clone(), sender_hint.clone())),
            _ => None,
        },
    );

    assert!(!message_id.is_empty(), "the gap must identify a message");
    let sender_hint = sender_hint.expect("the referencing peer named an author");
    assert_eq!(
        sender_hint.account.as_ref().map(|a| a.as_str()),
        Some(saro_addr.as_str()),
        "the missing message should be attributed to Saro"
    );
}
