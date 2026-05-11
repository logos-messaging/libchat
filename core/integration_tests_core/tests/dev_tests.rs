use std::ops::{Deref, DerefMut};

use components::{EphemeralRegistry, LocalBroadcaster, MemStore};

use core_client::{ChatError, CoreClient};
use libchat::{ContentData, hex_trunc};
use logos_account::TestLogosAccount;

struct PollableClient {
    inner: CoreClient<TestLogosAccount, LocalBroadcaster, EphemeralRegistry, MemStore>,
    on_content: Option<Box<dyn Fn(ContentData)>>,
}

impl PollableClient {
    fn init(
        ctx: CoreClient<TestLogosAccount, LocalBroadcaster, EphemeralRegistry, MemStore>,
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
    type Target = CoreClient<TestLogosAccount, LocalBroadcaster, EphemeralRegistry, MemStore>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for PollableClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

fn process(clients: &mut Vec<PollableClient>) {
    for client in clients {
        client.process_messages();
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

#[test]
fn core_client() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro_account = TestLogosAccount::new("saro");

    let raya_account = TestLogosAccount::new("raya");

    let saro = CoreClient::new(saro_account, ds.clone(), rs.clone(), MemStore::new()).unwrap();
    let raya = CoreClient::new(raya_account, ds, rs, MemStore::new()).unwrap();

    let mut clients = vec![
        PollableClient::init(saro, Some(pretty_print("  Saro         "))),
        PollableClient::init(raya, Some(pretty_print("       Raya    "))),
    ];

    const SARO: usize = 0;
    const RAYA: usize = 1;

    let s_convo = clients[SARO]
        .create_group_convo(&[&clients[RAYA].account_id()])
        .unwrap();

    process(&mut clients);

    s_convo.send_content(b"HI").unwrap();
    let convo_id = clients[RAYA].list_conversations().unwrap().pop().unwrap();
    let r_convo = clients[RAYA].convo(&convo_id).expect("Convo exists");
    process(&mut clients);
    r_convo.send_content(b"PEW").unwrap();
    process(&mut clients);

    s_convo.send_content(b"SARO again").unwrap();
    process(&mut clients);
    println!("Hello");
}
