use std::ops::{Deref, DerefMut};

use components::{EphemeralRegistry, LocalBroadcaster, MemStore};
use libchat::{ContentData, Context, GroupConvo, hex_trunc};

// Simple client Functionality for testing
struct Client {
    inner: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
    on_content: Option<Box<dyn Fn(ContentData)>>,
}

impl Client {
    fn init(
        ctx: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
        cb: Option<impl Fn(ContentData) + 'static>,
    ) -> Self {
        Client {
            inner: ctx,
            on_content: cb.map(|f| Box::new(f) as Box<dyn Fn(ContentData)>),
        }
    }

    fn process_messages(&mut self) {
        let messages: Vec<_> = {
            let mut ds = self.ds();
            std::iter::from_fn(|| ds.poll()).collect()
        };

        for data in messages {
            let res = self.handle_payload(&data).unwrap();
            if let Some(cb) = &self.on_content {
                if let Some(content_data) = res {
                    cb(content_data);
                }
            }
        }
    }

    fn convo(
        &mut self,
        convo_id: &str,
    ) -> Box<dyn GroupConvo<LocalBroadcaster, EphemeralRegistry>> {
        // TODO: (P1) Convos are being copied somewhere, which means hanging on to a reference causes state desync
        self.get_convo(convo_id).unwrap()
    }
}

impl Deref for Client {
    type Target = Context<LocalBroadcaster, EphemeralRegistry, MemStore>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Client {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

// Higher order function to handle printing
fn pretty_print(prefix: impl Into<String>) -> Box<dyn Fn(ContentData)> {
    let prefix = prefix.into();
    return Box::new(move |c: ContentData| {
        let cid = hex_trunc(c.conversation_id.as_bytes());
        let content = String::from_utf8(c.data).unwrap();
        println!("{}      ({:?}) {}", prefix, cid, content)
    });
}

fn process(clients: &mut Vec<Client>) {
    for client in clients {
        client.process_messages();
    }
}

#[test]
fn create_group() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro_ctx =
        Context::new_with_name("saro", ds.new_consumer(), rs.clone(), MemStore::new()).unwrap();
    let raya_ctx = Context::new_with_name("raya", ds.clone(), rs.clone(), MemStore::new()).unwrap();

    let mut clients = vec![
        Client::init(saro_ctx, Some(pretty_print("  Saro         "))),
        Client::init(raya_ctx, Some(pretty_print("       Raya    "))),
    ];

    const SARO: usize = 0;
    const RAYA: usize = 1;

    let raya_id = clients[RAYA].account_id().clone();
    let s_convo = clients[SARO].create_group_convo(&[&raya_id]).unwrap();

    let convo_id = s_convo.id();

    // Raya can read this message because
    //   1) It was sent after add_members was committed, and
    //   2) LocalBroadcaster provides historical messages.

    clients[SARO]
        .convo(convo_id)
        .send_content(b"ok who broke the group chat again")
        .unwrap();

    process(&mut clients);

    clients[RAYA]
        .convo(convo_id)
        .send_content(b"it was literally working five minutes ago")
        .unwrap();

    process(&mut clients);

    let pax_ctx = Context::new_with_name("pax", ds, rs, MemStore::new()).unwrap();
    clients.push(Client::init(pax_ctx, Some(pretty_print("           Pax"))));
    const PAX: usize = 2;

    let pax_id = clients[PAX].account_id().clone();
    clients[SARO]
        .convo(convo_id)
        .add_member(&[&pax_id])
        .unwrap();

    process(&mut clients);

    clients[PAX]
        .convo(convo_id)
        .send_content(b"ngl the key rotation is cooked")
        .unwrap();

    process(&mut clients);

    clients[SARO]
        .convo(convo_id)
        .send_content(b"bro we literally just added you to the group ")
        .unwrap();

    process(&mut clients);
}
