use std::cell::RefCell;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use tracing::info;

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

fn process(clients: &mut Vec<PollableClient>, wakeups: &mut Vec<WakeupProvider>, secs: u32) {
    for _ in 0..secs {
        for w in wakeups.iter().as_ref() {
            w.advance_time(1);
        }

        for client in clients.as_mut_slice() {
            client.process_messages();
        }
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
    pending: BinaryHeap<Reverse<WakeupRecord>>,
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
            info!(now = self.now, w.convo_id, "Popping");
            fired.push(w.convo_id);
        }
        fired
    }

    pub fn advance_time(&mut self, secs: u32) {
        for convo_id in self.tick(secs) {
            (self.on_wakeup)(convo_id);
        }
    }
}

impl WakeupService for ManualWakeupService {
    fn wakeup_in(&mut self, secs: u32, convo_id: libchat::ConversationId) {
        info!(now = self.now, convo_id, "Pushing");
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
        let content = String::from_utf8(c.data).unwrap();
        println!("{}      ({:?}) {}", prefix, cid, content)
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
                client.on_wakeup(&convo_id);
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

    w.wakeup_in(1, "1");
    w.wakeup_in(2, "2");

    println!("GO");

    w.advance_time(1);
    w.advance_time(1);
    w.advance_time(1);
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
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();

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

    // Manaully process the DS
    process(&mut clients, &mut wakeups, 10);

    s_convo.send_content(b"HI").unwrap();

    // Manaully process the DS
    process(&mut clients, &mut wakeups, 10);

    // TODO: Needs Invite path working first
    // let convo_id = clients[RAYA].list_conversations().unwrap().pop().unwrap();
    // let r_convo = clients[RAYA].convo(&convo_id).expect("Convo exists");
    // process(&mut clients);
    // r_convo.send_content(b"PEW").unwrap();
    // process(&mut clients);

    // s_convo.send_content(b"SARO again").unwrap();
    // process(&mut clients);
    // println!("Hello");
}
