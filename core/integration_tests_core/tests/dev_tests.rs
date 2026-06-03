use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::time::Duration;
use tracing::{debug, info, warn};

use components::{EphemeralRegistry, LocalBroadcaster, MemStore};

use core_client::CoreClient;
use libchat::{ContentData, WakeupService, hex_trunc};
use logos_account::TestLogosAccount;

struct PollableClient {
    inner: CoreClient<
        TestLogosAccount,
        LocalBroadcaster,
        EphemeralRegistry,
        ManualWakeupService,
        MemStore,
    >,
    on_content: Option<Box<dyn Fn(ContentData)>>,
}

impl PollableClient {
    fn init(
        ctx: CoreClient<
            TestLogosAccount,
            LocalBroadcaster,
            EphemeralRegistry,
            ManualWakeupService,
            MemStore,
        >,
        cb: Option<impl Fn(ContentData) + 'static>,
    ) -> Self {
        Self {
            inner: ctx,
            on_content: cb.map(|f| Box::new(f) as Box<dyn Fn(ContentData)>),
        }
    }

    fn process_messages(&mut self) {
        let messages = self.inner.ds().poll_all();
        for data in messages {
            let res = self.handle_payload(&data).unwrap();
            if let Some(cb) = &self.on_content
                && let Some(content_data) = res
            {
                cb(content_data);
            }
        }
    }
}

impl Deref for PollableClient {
    type Target = CoreClient<
        TestLogosAccount,
        LocalBroadcaster,
        EphemeralRegistry,
        ManualWakeupService,
        MemStore,
    >;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for PollableClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

fn process(clients: &mut Vec<PollableClient>, wakeups: &mut Vec<WakeupProvider>, ms: u32) {
    info!(ms, "processing");
    let step = 5;
    for _ in (0..ms).step_by(step as usize) {
        for w in wakeups.iter().as_ref() {
            w.advance_time(step as u64);
        }

        for client in clients.as_mut_slice() {
            client.process_messages();
        }

        // de-mls deadlines are real wall-clock; sleep so the millisecond-scale
        // commit/consensus timers actually elapse between poll cycles.
        std::thread::sleep(std::time::Duration::from_millis(step));
    }
}

use std::cmp::Reverse;
use std::collections::BinaryHeap;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
struct WakeupRecord {
    expiry: Duration,
    convo_id: String,
}

struct ManualWakeupService {
    now: Duration,
    pub pending: BinaryHeap<Reverse<WakeupRecord>>,
    on_wakeup: Box<dyn Fn(String)>,
}

impl std::fmt::Debug for ManualWakeupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ManualWakeupService")
            .field("now", &self.now)
            .field("pending", &self.pending)
            .finish()
    }
}

impl ManualWakeupService {
    pub fn new(on_wakeup: impl Fn(String) + 'static) -> Self {
        Self {
            now: Duration::new(0, 0),
            pending: BinaryHeap::new(),
            on_wakeup: Box::new(on_wakeup),
        }
    }

    pub fn tick(&mut self, ms: u64) -> Vec<String> {
        self.now = self.now.checked_add(Duration::from_millis(ms)).unwrap();
        let mut fired = vec![];
        while self
            .pending
            .peek()
            .is_some_and(|Reverse(w)| w.expiry <= self.now)
        {
            let Reverse(w) = self.pending.pop().unwrap();
            debug!(now = self.now.as_secs(), w.convo_id, "Popping");
            fired.push(w.convo_id);
        }
        fired
    }

    pub fn advance_time(&mut self, ms: u64) {
        for convo_id in self.tick(ms) {
            (self.on_wakeup)(convo_id);
        }
    }
}

impl WakeupService for ManualWakeupService {
    fn wakeup_in(&mut self, duration: Duration, convo_id: libchat::ConversationId) {
        debug!(
            now = self.now.as_secs(),
            duration = duration.as_secs(),
            convo_id,
            "Pushing"
        );
        self.pending.push(Reverse(WakeupRecord {
            expiry: self.now + duration,
            convo_id: convo_id.to_string(),
        }));
    }
}

// Higher order function to handle printing
fn pretty_print(prefix: impl Into<String>) -> Box<dyn Fn(ContentData)> {
    let prefix = prefix.into();
    Box::new(move |c: ContentData| {
        let cid = hex_trunc(c.conversation_id.as_bytes());
        let content = String::from_utf8_lossy(&c.data);
        // Log via tracing (not println!) so received messages appear inline in
        // the same INFO stream as the de-mls events, without needing --nocapture.
        warn!(target: "chat", convo = ?cid, "{prefix} received: {content}");
    })
}

struct WakeupProvider {
    client_slot: Rc<
        RefCell<
            Option<
                CoreClient<
                    TestLogosAccount,
                    LocalBroadcaster,
                    EphemeralRegistry,
                    ManualWakeupService,
                    MemStore,
                >,
            >,
        >,
    >,
}

impl std::fmt::Debug for WakeupProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeupProvider").finish()
    }
}

impl WakeupProvider {
    pub fn new() -> Self {
        Self {
            client_slot: Rc::new(RefCell::new(None)),
        }
    }

    pub fn create_wakeup_service(&self) -> ManualWakeupService {
        let slot = self.client_slot.clone();
        ManualWakeupService::new(move |convo_id| {
            if let Some(client) = slot.borrow().as_ref() {
                client.on_wakeup(&convo_id).unwrap();
            }
        })
    }

    pub fn advance_time(&self, ms: u64) {
        // borrow_mut must be released before on_wakeup fires — it re-borrows client_slot
        let fired = {
            let mut slot = self.client_slot.borrow_mut();
            slot.as_mut().map_or(vec![], |client| client.ws().tick(ms))
        };
        for convo_id in fired {
            if let Some(client) = self.client_slot.borrow().as_ref() {
                let _ = client.on_wakeup(&convo_id).unwrap();
            }
        }
    }

    pub fn fill_slot(
        &self,
        client: &CoreClient<
            TestLogosAccount,
            LocalBroadcaster,
            EphemeralRegistry,
            ManualWakeupService,
            MemStore,
        >,
    ) {
        *self.client_slot.borrow_mut() = Some(client.clone());
    }
}

#[test]
fn wakup() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let mut w = ManualWakeupService::new(|c| println!("Wakeup: {}.     ", c));

    println!("STARTing");
    w.wakeup_in(Duration::from_secs(5), "5");
    info!(w = format!("{:?}", w));
    w.wakeup_in(Duration::from_secs(1), "1");
    info!(w = format!("{:?}", w));
    w.wakeup_in(Duration::from_secs(2), "2");
    info!(w = format!("{:?}", w));

    println!("GO");

    w.advance_time(1000);
    info!(w = format!("{:?}", w));
    w.advance_time(1000);
    info!(w = format!("{:?}", w));
    w.advance_time(1000);
    info!(w = format!("{:?}", w));
    w.wakeup_in(Duration::from_secs(3), "3");
    w.advance_time(1000);

    w.advance_time(1000);

    w.advance_time(1000);
    w.advance_time(1000);
    w.advance_time(1000);
    w.advance_time(1000);

    println!("DONE");
}

#[test]
fn core_client() {
    // Test Toggle:
    // If Raya Invites PAX, The Welcome is not sent, and Pax does not join the conversation.
    // If Saro does everything works
    const RAYA_INVITE: bool = false;

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let swp = WakeupProvider::new();
    let rwp = WakeupProvider::new();
    let pwp = WakeupProvider::new();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro_account = TestLogosAccount::new("saro");
    let raya_account = TestLogosAccount::new("raya");
    let pax_account = TestLogosAccount::new("pax");

    let saro = CoreClient::new(
        saro_account,
        ds.clone(),
        rs.clone(),
        swp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    swp.fill_slot(&saro);
    let raya = CoreClient::new(
        raya_account,
        ds.clone(),
        rs.clone(),
        rwp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    rwp.fill_slot(&raya);

    let pax = CoreClient::new(
        pax_account,
        ds.clone(),
        rs.clone(),
        pwp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    pwp.fill_slot(&pax);

    let mut clients = vec![
        PollableClient::init(saro, Some(pretty_print("  Saro         "))),
        PollableClient::init(raya, Some(pretty_print("       Raya    "))),
        PollableClient::init(pax, Some(pretty_print("            Pax "))),
    ];

    let mut wakeups = vec![swp, rwp];

    const SARO: usize = 0;
    const RAYA: usize = 1;
    const PAX: usize = 2;

    let wait_time_ms: u32 = 400;

    let saro_convo = clients[SARO]
        .create_group_convo(&[&clients[RAYA].account_id()])
        .unwrap();

    // Bounded driver: de-mls reschedules its steward poll every tick, so a
    // drain-until-empty loop (`process_all`) never terminates. Step a fixed
    // number of seconds instead, like the de-mls integration tests do.
    //
    // This carries the commit through, fires `WelcomeReady`, routes the
    // welcome to Raya's InboxV2 1-1 channel, and lets her `accept_welcome`.
    // Run extra cycles afterward so Raya polls her inbox and joins after the
    // welcome is published.
    process(&mut clients, &mut wakeups, wait_time_ms);

    // Raya joined via the invite path.
    let raya_convos = clients[RAYA].list_conversations().unwrap();
    assert!(
        !raya_convos.is_empty(),
        "Raya should have joined the conversation via the welcome invite"
    );

    // Saro sends a message; Raya receives it (look for "Raya received: HI"
    // in the log).
    info!(target: "chat", "Saro -> sending: HI");
    saro_convo.send_content(b"HI").unwrap();
    process(&mut clients, &mut wakeups, wait_time_ms);

    // Raya replies; Saro receives it (look for "Saro received: hi back").
    let raya_convo = clients[RAYA]
        .convo(&raya_convos[0])
        .expect("Raya must have a usable conversation handle");
    info!(target: "chat", "Raya -> sending: hi back");
    raya_convo.send_content(b"hi back").unwrap();
    process(&mut clients, &mut wakeups, wait_time_ms);

    if RAYA_INVITE {
        &raya_convo
    } else {
        &saro_convo
    }
    .add_member(&[&clients[PAX].account_id()])
    .unwrap();

    process(&mut clients, &mut wakeups, wait_time_ms);
    process(&mut clients, &mut wakeups, wait_time_ms);
    process(&mut clients, &mut wakeups, wait_time_ms);

    let pax_convos = clients[PAX].list_conversations().unwrap();
    let pax_convo = clients[PAX]
        .convo(&pax_convos[0])
        .expect("PAX must have a usable conversation handle");
    info!(target: "chat", "Pax -> sending: hi back");
    raya_convo.send_content(b"hi yall").unwrap();
    pax_convo.send_content(b"Hey I'm PAX").unwrap();
    process(&mut clients, &mut wakeups, wait_time_ms);
}
