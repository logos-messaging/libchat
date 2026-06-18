use libchat::{ConversationId, Core, IdentityProvider, MessageSender, PayloadOutcome};
use logos_account::TestLogosAccount;
use shared_traits::IdentId;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::time::Duration;
use tracing::{info, warn};

use components::{EphemeralRegistry, LocalBroadcaster, MemStore};

use crate::wakeup::{TestWakeupProvider, TestWakeupService, WakeupRecord};

type OnMessageCallback = dyn Fn(&TestClient, PayloadOutcome);

type WS = TestWakeupService;
type WP = TestWakeupProvider;

const SARO: usize = 0;
const RAYA: usize = 1;
const PAX: usize = 2;
const MIRA: usize = 3;

// type ClientType = CoreClient<TestLogosAccount, LocalBroadcaster, EphemeralRegistry, WP, MemStore>;
type ClientType = Core<(
    TestLogosAccount,
    LocalBroadcaster,
    EphemeralRegistry,
    WP,
    MemStore,
)>;

#[derive(Debug)]
pub struct ReceivedMessage<T> {
    pub convo_id: ConversationId,
    pub contents: T,
    /// The verified sender (Account + LocalIdentity) surfaced with the message.
    pub sender: Option<MessageSender>,
}

pub struct TestClient {
    inner: ClientType,
    received_messages: Vec<ReceivedMessage<Vec<u8>>>,
    sender_identity: MessageSender,
}

impl TestClient {
    fn init(client: ClientType, sender_identity: MessageSender) -> Self {
        Self {
            inner: client,
            received_messages: vec![],
            sender_identity,
        }
    }

    pub fn addr(&self) -> IdentId {
        self.inner.ident_id().clone()
    }

    pub fn as_sender(&self) -> MessageSender {
        self.sender_identity.clone()
    }

    fn drain_outcomes(&mut self) -> Vec<PayloadOutcome> {
        let mut messages = vec![];
        while let Some(data) = self.inner.ds().poll() {
            messages.push(data);
        }

        let mut outcomes = vec![];
        for data in messages {
            let outcome = self.inner.handle_payload(&data).unwrap();
            warn!(id= ?self.ident_id(),?outcome, "DRAIN CLIENT");
            // Copy Convo Messages to received buffer

            match &outcome {
                PayloadOutcome::Empty => continue,
                PayloadOutcome::Convo(convo_outcome) => {
                    if let Some(data) = &convo_outcome.content {
                        info!(
                            content = String::from_utf8_lossy(&data.bytes).to_string(),
                            "COT"
                        );
                        // Validate the raw credential against the account
                        // directory, exactly as the client does.
                        let sender = convo_outcome
                            .credential
                            .as_ref()
                            .and_then(|c| self.inner.validate_sender(c).ok().flatten());
                        self.received_messages.push(ReceivedMessage {
                            convo_id: convo_outcome.convo_id.clone(),
                            contents: data.bytes.clone(),
                            sender,
                        });
                    }
                }
                PayloadOutcome::Inbox(_) => {}
            }

            if !matches!(outcome, PayloadOutcome::Empty) {
                outcomes.push(outcome);
            }
        }
        outcomes
    }

    pub fn received_messages(&self) -> &[ReceivedMessage<Vec<u8>>] {
        &self.received_messages
    }

    pub fn check(&self, convo_id: &str, content: &[u8], sender: Option<MessageSender>) -> bool {
        for msg in &self.received_messages {
            if msg.convo_id == convo_id && msg.contents == content && msg.sender == sender {
                return true;
            }
        }
        false
    }

    /// The verified sender recorded for the (first) message matching
    /// `convo_id`/`content`, if any was received.
    pub fn sender_of(&self, convo_id: &str, content: &[u8]) -> Option<&MessageSender> {
        self.received_messages
            .iter()
            .find(|m| m.convo_id == convo_id && m.contents == content)
            .and_then(|m| m.sender.as_ref())
    }

    pub fn convo_count(&self) -> usize {
        self.list_conversations().map_or(0, |v| v.len())
    }
}

impl Deref for TestClient {
    type Target = ClientType;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for TestClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

#[allow(unused)]
pub struct Observation {
    ident: IdentId,
    outcome: PayloadOutcome,
}

#[allow(unused)]
pub struct TestHarness<const N: usize> {
    addresses: HashMap<usize, IdentId>,
    clients: Vec<TestClient>,
    wakeup_service: WS,
    cb: Box<OnMessageCallback>,
    // List of outcomes that were detected across all clients.
    pub observed_outcomes: Vec<Observation>,
}

impl<const N: usize> TestHarness<N> {
    pub fn new(cb: impl Fn(&TestClient, PayloadOutcome) + 'static) -> Self {
        const { assert!(N > 0, "TestHarness requires at least one client") };
        const { assert!(N <= 4, "Only 4 clients are supported(Soft Limit") };

        let mut clients = vec![];
        let mut addresses = HashMap::new();

        let ds = LocalBroadcaster::new();
        let rs = EphemeralRegistry::new();
        let ws = TestWakeupService::new();

        for i in 0..N {
            let wp = ws.new_provider(i);
            let ident = TestLogosAccount::new(Self::names(i));

            addresses.insert(i, ident.id().clone());
            let iden_id = ident.iden_id();
            let sender_identity = MessageSender {
                account: iden_id.clone(),
                local_identity: iden_id,
            };
            let core_client =
                ClientType::new_with_name(ident, ds.clone(), rs.clone(), wp, MemStore::new())
                    .unwrap();

            let client = TestClient::init(core_client, sender_identity);

            clients.push(client);
        }

        dbg!(&rs);

        Self {
            addresses,
            clients,
            wakeup_service: ws,
            cb: Box::new(cb),
            observed_outcomes: vec![],
        }
    }

    pub fn client(&mut self, i: usize) -> &TestClient {
        &self.clients[i]
    }

    pub fn client_mut(&mut self, i: usize) -> &mut TestClient {
        &mut self.clients[i]
    }

    fn names(i: usize) -> &'static str {
        match i {
            SARO => "saro",
            RAYA => "raya",
            PAX => "pax",
            MIRA => "mira",
            _ => "unnamed",
        }
    }

    pub fn process(&mut self, duration: Duration) {
        self.process_payloads();

        let records = self.wakeup_service.advance_time(duration);
        self.process_records(records);
    }

    pub fn process_until(&mut self, predicate: impl Fn(&mut TestHarness<N>) -> bool) {
        let timeout = Duration::from_mins(1);
        let step = Duration::from_millis(50);
        let mut elapsed = Duration::ZERO;

        while !predicate(self) {
            if elapsed >= timeout {
                panic!("process_until timed out after {:?}", timeout);
            }
            self.process(step);
            elapsed += step;
        }
    }

    pub fn process_until_label(
        &mut self,
        label: &str,
        predicate: impl Fn(&mut TestHarness<N>) -> bool,
    ) {
        info!(label, "Process Until");
        self.process_until(predicate);
    }

    fn process_payloads(&mut self) {
        // Process existing payloads for all clients.
        for client in self.clients.iter_mut() {
            for outcome in client.drain_outcomes() {
                info!(id = ?client.ident_id(), ?outcome, "Process drain");
                self.observed_outcomes.push(Observation {
                    ident: client.ident_id().clone(),
                    outcome: outcome.clone(),
                });
                info!(id = ?client.ident_id(), ?outcome, "Process drain");
                (self.cb)(client, outcome)
            }
        }
    }

    fn process_records(&mut self, records: Vec<WakeupRecord>) {
        for record in records {
            self.clients[record.client_index]
                .wakeup(&record.convo_id)
                .expect("Error During wakeup");
        }
    }
}

// Avoid Developer confusion by gating access functions
// based on the number of clients in the harness

impl TestHarness<1> {
    pub fn saro(&mut self) -> &mut TestClient {
        &mut self.clients[SARO]
    }
}

impl TestHarness<2> {
    pub fn saro(&mut self) -> &mut TestClient {
        &mut self.clients[SARO]
    }

    pub fn raya(&mut self) -> &mut TestClient {
        &mut self.clients[RAYA]
    }
}

impl TestHarness<3> {
    pub fn saro(&mut self) -> &mut TestClient {
        &mut self.clients[SARO]
    }

    pub fn raya(&mut self) -> &mut TestClient {
        &mut self.clients[RAYA]
    }

    pub fn pax(&mut self) -> &mut TestClient {
        &mut self.clients[PAX]
    }
}

impl TestHarness<4> {
    pub fn saro(&mut self) -> &mut TestClient {
        &mut self.clients[SARO]
    }

    pub fn raya(&mut self) -> &mut TestClient {
        &mut self.clients[RAYA]
    }

    pub fn pax(&mut self) -> &mut TestClient {
        &mut self.clients[PAX]
    }

    pub fn mira(&mut self) -> &mut TestClient {
        &mut self.clients[MIRA]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .with_test_writer()
            .try_init();

        let mut harness = TestHarness::<2>::new(|client, outcome| {
            info!( id=?&client.ident_id(), outcome = ?outcome, "Result");
        });

        //Create Convo
        let particpants = &[&harness.raya().addr()];
        let convo_id = harness
            .saro()
            .create_group_convo(particpants)
            .expect("saro create group");

        harness.process_until_label("Raya Join", |h| h.raya().convo_count() == 1);

        assert_eq!(harness.raya().convo_count(), 1, "raya did not join");

        harness
            .saro()
            .send_content(convo_id.as_str(), b"Hello")
            .expect("raya send");

        harness.process(Duration::from_millis(200));

        // GroupV2 (de-mls) carries no account-bound credential yet, so the
        // sender can't be validated — it resolves to `None`.
        assert!(harness.raya().check(&convo_id, b"Hello", None))
    }
}
