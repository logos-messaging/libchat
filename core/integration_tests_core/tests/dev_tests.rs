use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use std::time::Duration;
use tracing::{debug, info, warn};

use components::{EphemeralRegistry, LocalBroadcaster, MemStore};

use core_client::{ConversationState, CoreClient};
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

/// Pump the event loop until `done` holds, re-checking between fixed slices.
/// This is the settle barrier between test actions: do an action, call
/// `process_until(<expected post-condition>)`, then do the next action. It
/// waits for the actual outcome rather than a guessed cycle count, so it
/// absorbs consensus retries and the ms-timer jitter. Fails loudly if the
/// condition isn't reached within `max_ms`.
fn process_until(
    clients: &mut Vec<PollableClient>,
    wakeups: &mut Vec<WakeupProvider>,
    label: &str,
    mut done: impl FnMut(&[PollableClient]) -> bool,
    max_ms: u32,
) {
    let slice = 200;
    let mut elapsed = 0;
    while elapsed < max_ms {
        if done(clients) {
            return;
        }
        process(clients, wakeups, slice);
        elapsed += slice;
    }
    assert!(
        done(clients),
        "process_until({label}): not settled within {max_ms}ms"
    );
}

/// True once `client` has joined (has a conversation).
fn joined(client: &PollableClient) -> bool {
    client
        .list_conversations()
        .map(|c| !c.is_empty())
        .unwrap_or(false)
}

/// True once `client`'s (first) conversation is back in `Working`.
fn is_working(client: &PollableClient) -> bool {
    let Ok(convos) = client.list_conversations() else {
        return false;
    };
    let Some(id) = convos.first() else {
        return false;
    };
    client
        .convo(id)
        .map(|h| h.conversation_state().unwrap() == ConversationState::Working)
        .unwrap_or(false)
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

/// Per-client `on_content` callback: log each received message and record it into `sink` so a
/// test can assert who decrypted it — i.e. who is at the current epoch.
fn pretty_print(
    prefix: impl Into<String>,
    sink: Rc<RefCell<Vec<String>>>,
) -> Box<dyn Fn(ContentData)> {
    let prefix = prefix.into();
    Box::new(move |c: ContentData| {
        let cid = hex_trunc(c.conversation_id.as_bytes());
        let content = String::from_utf8_lossy(&c.data).to_string();
        warn!(target: "chat", convo = ?cid, "{prefix} received: {content}");
        sink.borrow_mut().push(content);
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
    const RAYA_INVITE: bool = true;

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

    let saro_rx = Rc::new(RefCell::new(Vec::<String>::new()));
    let raya_rx = Rc::new(RefCell::new(Vec::<String>::new()));
    let pax_rx = Rc::new(RefCell::new(Vec::<String>::new()));

    let mut clients = vec![
        PollableClient::init(saro, Some(pretty_print("  Saro         ", saro_rx.clone()))),
        PollableClient::init(raya, Some(pretty_print("       Raya    ", raya_rx.clone()))),
        PollableClient::init(pax, Some(pretty_print("            Pax ", pax_rx.clone()))),
    ];

    let mut wakeups = vec![swp, rwp];

    const SARO: usize = 0;
    const RAYA: usize = 1;
    const PAX: usize = 2;

    let saro_convo = clients[SARO]
        .create_group_convo(&[&clients[RAYA].account_id()])
        .unwrap();

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    process_until(
        &mut clients,
        &mut wakeups,
        "raya joins",
        |c| joined(&c[RAYA]),
        6000,
    );

    let raya_convo = clients[RAYA]
        .convo(&clients[RAYA].list_conversations().unwrap()[0])
        .expect("Raya must have a usable conversation handle");

    // Saro sends a message; settle until Raya receives it.
    info!(target: "chat", "Saro -> sending: HI");
    saro_convo.send_content(b"HI").unwrap();
    process_until(
        &mut clients,
        &mut wakeups,
        "raya receives HI",
        |_| raya_rx.borrow().iter().any(|m| m == "HI"),
        4000,
    );

    // Raya replies; settle until Saro receives it.
    info!(target: "chat", "Raya -> sending: hi back");
    raya_convo.send_content(b"hi back").unwrap();
    process_until(
        &mut clients,
        &mut wakeups,
        "saro receives hi back",
        |_| saro_rx.borrow().iter().any(|m| m == "hi back"),
        4000,
    );

    // Raya (a non-creator) invites Pax; settle until Pax has joined.
    if RAYA_INVITE {
        &raya_convo
    } else {
        &saro_convo
    }
    .add_member(&[&clients[PAX].account_id()])
    .unwrap();
    process_until(
        &mut clients,
        &mut wakeups,
        "pax joins",
        |c| joined(&c[PAX]),
        8000,
    );

    // Everyone must be at the SAME epoch after Pax joined: a marker Saro sends
    // now decrypts only for members that applied the Add commit.
    info!(target: "chat", "Saro -> sending: EPOCHCHK");
    saro_convo.send_content(b"EPOCHCHK").unwrap();
    process_until(
        &mut clients,
        &mut wakeups,
        "raya+pax receive EPOCHCHK",
        |_| {
            raya_rx.borrow().iter().any(|m| m == "EPOCHCHK")
                && pax_rx.borrow().iter().any(|m| m == "EPOCHCHK")
        },
        4000,
    );
}

#[test]
fn core_client_batch_add() {
    // Saro creates the group and adds BOTH Raya and Pax at the same time: one
    // Add commit producing a single welcome that names both joiners.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let swp = WakeupProvider::new();
    let rwp = WakeupProvider::new();
    let pwp = WakeupProvider::new();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro = CoreClient::new(
        TestLogosAccount::new("saro"),
        ds.clone(),
        rs.clone(),
        swp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    swp.fill_slot(&saro);
    let raya = CoreClient::new(
        TestLogosAccount::new("raya"),
        ds.clone(),
        rs.clone(),
        rwp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    rwp.fill_slot(&raya);
    let pax = CoreClient::new(
        TestLogosAccount::new("pax"),
        ds.clone(),
        rs.clone(),
        pwp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    pwp.fill_slot(&pax);

    // This test asserts only on joins, not message receipt — discard the sinks.
    let mut clients = vec![
        PollableClient::init(
            saro,
            Some(pretty_print(
                "  Saro         ",
                Rc::new(RefCell::new(vec![])),
            )),
        ),
        PollableClient::init(
            raya,
            Some(pretty_print(
                "       Raya    ",
                Rc::new(RefCell::new(vec![])),
            )),
        ),
        PollableClient::init(
            pax,
            Some(pretty_print(
                "            Pax ",
                Rc::new(RefCell::new(vec![])),
            )),
        ),
    ];
    let mut wakeups = vec![swp, rwp];

    const SARO: usize = 0;
    const RAYA: usize = 1;
    const PAX: usize = 2;

    clients[SARO]
        .create_group_convo(&[&clients[RAYA].account_id(), &clients[PAX].account_id()])
        .unwrap();

    // One welcome names both joiners; settle until both have joined.
    process_until(
        &mut clients,
        &mut wakeups,
        "raya+pax join via batch welcome",
        |c| joined(&c[RAYA]) && joined(&c[PAX]),
        6000,
    );
}

#[test]
fn core_client_four_members_two_epochs() {
    // Epoch 1: Saro creates and batch-adds Raya + Pax (3 members). Epoch 2: Raya
    // (a non-creator) adds a 4th member, Mira. Afterwards every member must be
    // at the same epoch (each can decrypt a freshly-sent message) and settled
    // back in Working (the >sn_max election that the 4th member triggers must
    // have completed — no one stuck in Freezing/Selection/Reelection).
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let swp = WakeupProvider::new();
    let rwp = WakeupProvider::new();
    let pwp = WakeupProvider::new();
    let mwp = WakeupProvider::new();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro_rx = Rc::new(RefCell::new(Vec::<String>::new()));
    let raya_rx = Rc::new(RefCell::new(Vec::<String>::new()));
    let pax_rx = Rc::new(RefCell::new(Vec::<String>::new()));
    let mira_rx = Rc::new(RefCell::new(Vec::<String>::new()));

    let saro = CoreClient::new(
        TestLogosAccount::new("saro"),
        ds.clone(),
        rs.clone(),
        swp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    swp.fill_slot(&saro);
    let raya = CoreClient::new(
        TestLogosAccount::new("raya"),
        ds.clone(),
        rs.clone(),
        rwp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    rwp.fill_slot(&raya);
    let pax = CoreClient::new(
        TestLogosAccount::new("pax"),
        ds.clone(),
        rs.clone(),
        pwp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    pwp.fill_slot(&pax);
    let mira = CoreClient::new(
        TestLogosAccount::new("mira"),
        ds.clone(),
        rs.clone(),
        mwp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    mwp.fill_slot(&mira);

    let mut clients = vec![
        PollableClient::init(saro, Some(pretty_print("  Saro         ", saro_rx.clone()))),
        PollableClient::init(raya, Some(pretty_print("       Raya    ", raya_rx.clone()))),
        PollableClient::init(pax, Some(pretty_print("            Pax ", pax_rx.clone()))),
        PollableClient::init(
            mira,
            Some(pretty_print("                Mira ", mira_rx.clone())),
        ),
    ];
    let mut wakeups = vec![swp, rwp, pwp, mwp];

    const SARO: usize = 0;
    const RAYA: usize = 1;
    const PAX: usize = 2;
    const MIRA: usize = 3;

    // Epoch 1: batch-add Raya and Pax; settle until both have joined.
    let saro_convo = clients[SARO]
        .create_group_convo(&[&clients[RAYA].account_id(), &clients[PAX].account_id()])
        .unwrap();
    process_until(
        &mut clients,
        &mut wakeups,
        "raya+pax join",
        |c| joined(&c[RAYA]) && joined(&c[PAX]),
        6000,
    );

    let raya_convo = clients[RAYA]
        .convo(&clients[RAYA].list_conversations().unwrap()[0])
        .expect("Raya must have a usable conversation handle");

    // Epoch 2: Raya adds the 4th member; settle until Mira has joined and the
    // >sn_max election has returned everyone to Working.
    raya_convo
        .add_member(&[&clients[MIRA].account_id()])
        .unwrap();
    process_until(
        &mut clients,
        &mut wakeups,
        "mira joins + all working",
        |c| joined(&c[MIRA]) && [SARO, RAYA, PAX, MIRA].iter().all(|&i| is_working(&c[i])),
        10000,
    );

    // Same epoch: a message Saro sends now must reach all three peers.
    saro_convo.send_content(b"CONVERGED").unwrap();
    process_until(
        &mut clients,
        &mut wakeups,
        "everyone receives CONVERGED",
        |_| {
            [&raya_rx, &pax_rx, &mira_rx]
                .iter()
                .all(|rx| rx.borrow().iter().any(|m| m == "CONVERGED"))
        },
        4000,
    );
}
