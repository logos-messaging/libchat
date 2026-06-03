use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
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

fn process_all(clients: &mut Vec<PollableClient>, wakeups: &mut Vec<WakeupProvider>) {
    info!("Process All");
    while process_next(clients, wakeups) {
        info!(" -- process");
    }
}

fn process_next(clients: &mut Vec<PollableClient>, wakeups: &mut Vec<WakeupProvider>) -> bool {
    for w in wakeups.iter().as_ref() {
        if let Some(client) = w.client_slot.borrow().as_ref() {
            dbg!(&client.ws().pending);
        }
    }

    for w in wakeups.iter().as_ref() {
        if let Some(client) = w.client_slot.borrow().as_ref() {
            let n = w.next();
            info!(n, "<<<");
        }
    }

    let Some(next_wakeup) = wakeups
        .iter()
        .map(|w| w.next())
        .filter(|x| x.is_some())
        .min()
        .flatten()
    else {
        info!("Nothing to do for process_next");
        return false;
    };

    info!(next = next_wakeup, "Process");
    // };

    for w in wakeups.iter().as_ref() {
        w.advance_time(next_wakeup);
    }

    for client in clients.as_mut_slice() {
        client.process_messages();
    }

    return true;
}

fn process(clients: &mut Vec<PollableClient>, wakeups: &mut Vec<WakeupProvider>, secs: u32) {
    for _ in 0..secs {
        for w in wakeups.iter().as_ref() {
            w.advance_time(1);
        }

        for client in clients.as_mut_slice() {
            client.process_messages();
        }

        // de-mls deadlines are real wall-clock; sleep so the millisecond-scale
        // commit/consensus timers actually elapse between poll cycles.
        std::thread::sleep(std::time::Duration::from_millis(60));
    }
}

use std::cmp::Reverse;
use std::collections::BinaryHeap;

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
struct WakeupRecord {
    expiry: u32,
    convo_id: String,
}

struct ManualWakeupService {
    now: u32,
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
            now: 0,
            pending: BinaryHeap::new(),
            on_wakeup: Box::new(on_wakeup),
        }
    }

    pub fn tick(&mut self, secs: u32) -> Vec<String> {
        self.now += secs;
        let mut fired = vec![];
        while self
            .pending
            .peek()
            .is_some_and(|Reverse(w)| w.expiry <= self.now)
        {
            let Reverse(w) = self.pending.pop().unwrap();
            debug!(now = self.now, w.convo_id, "Popping");
            fired.push(w.convo_id);
        }
        fired
    }

    pub fn advance_time(&mut self, secs: u32) {
        for convo_id in self.tick(secs) {
            (self.on_wakeup)(convo_id);
        }
    }

    pub fn next(&self) -> Option<u32> {
        Some(self.pending.peek()?.0.expiry)
    }
}

impl WakeupService for ManualWakeupService {
    fn wakeup_in(&mut self, secs: u32, convo_id: libchat::ConversationId) {
        debug!(now = self.now, secs, convo_id, "Pushing");
        self.pending.push(Reverse(WakeupRecord {
            expiry: self.now + secs,
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

    pub fn has_pending(&self) -> bool {
        if let Some(client) = self.client_slot.borrow().as_ref() {
            return true;
        }
        false
    }

    pub fn next(&self) -> Option<u32> {
        if let Some(client) = self.client_slot.borrow().as_ref() {
            let ws = client.ws();
            return Some(ws.next()? - ws.now);
        }

        None
    }

    pub fn create_wakeup_service(&self) -> ManualWakeupService {
        let slot = self.client_slot.clone();
        ManualWakeupService::new(move |convo_id| {
            if let Some(client) = slot.borrow().as_ref() {
                client.on_wakeup(&convo_id);
            }
        })
    }

    pub fn advance_time(&self, secs: u32) {
        // borrow_mut must be released before on_wakeup fires — it re-borrows client_slot
        let fired = {
            let mut slot = self.client_slot.borrow_mut();
            slot.as_mut()
                .map_or(vec![], |client| client.ws().tick(secs))
        };
        for convo_id in fired {
            if let Some(client) = self.client_slot.borrow().as_ref() {
                client.on_wakeup(&convo_id).unwrap();
            }
        }
    }

    pub fn fill_slot(
        &self,
        saro: &CoreClient<
            TestLogosAccount,
            LocalBroadcaster,
            EphemeralRegistry,
            ManualWakeupService,
            MemStore,
        >,
    ) {
        *self.client_slot.borrow_mut() = Some(saro.clone());
    }
}

#[test]
fn wakup() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let mut w = ManualWakeupService::new(|c| println!("Wakeup: {}.     ", c));

    println!("STARTing");
    w.wakeup_in(5, "5");
    info!(next = w.next(), all = format!("{:?}", w.pending));
    w.wakeup_in(1, "1");
    info!(next = w.next(), all = format!("{:?}", w.pending));
    w.wakeup_in(2, "2");
    info!(next = w.next(), all = format!("{:?}", w.pending));

    println!("GO");

    w.advance_time(1);
    info!(next = w.next(), all = format!("{:?}", w.pending));
    w.advance_time(1);
    info!(next = w.next(), all = format!("{:?}", w.pending));
    w.advance_time(1);
    info!(next = w.next(), all = format!("{:?}", w.pending));
    w.wakeup_in(3, "3");
    w.advance_time(1);

    w.advance_time(1);
    w.advance_time(1);
    w.advance_time(1);
    w.advance_time(1);

    println!("DONE");
}

#[test]
fn core_client() {
    // let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let swp = WakeupProvider::new();
    let rwp = WakeupProvider::new();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro_account = TestLogosAccount::new("saro");

    let raya_account = TestLogosAccount::new("raya");

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
        ds,
        rs,
        rwp.create_wakeup_service(),
        MemStore::new(),
    )
    .unwrap();
    rwp.fill_slot(&raya);
    let mut clients = vec![
        PollableClient::init(saro, Some(pretty_print("  Saro         "))),
        PollableClient::init(raya, Some(pretty_print("       Raya    "))),
    ];

    let mut wakeups = vec![swp, rwp];

    const SARO: usize = 0;
    const RAYA: usize = 1;

    let s_convo = clients[SARO]
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
    process(&mut clients, &mut wakeups, 80);

    // Raya joined via the invite path.
    let raya_convos = clients[RAYA].list_conversations().unwrap();
    assert!(
        !raya_convos.is_empty(),
        "Raya should have joined the conversation via the welcome invite"
    );

    // Saro sends a message; Raya receives it (look for "Raya received: HI"
    // in the log).
    info!(target: "chat", "Saro -> sending: HI");
    s_convo.send_content(b"HI").unwrap();
    process(&mut clients, &mut wakeups, 20);

    // Raya replies; Saro receives it (look for "Saro received: hi back").
    let raya_convo = clients[RAYA]
        .convo(&raya_convos[0])
        .expect("Raya must have a usable conversation handle");
    info!(target: "chat", "Raya -> sending: hi back");
    raya_convo.send_content(b"hi back").unwrap();
    process(&mut clients, &mut wakeups, 20);
}
