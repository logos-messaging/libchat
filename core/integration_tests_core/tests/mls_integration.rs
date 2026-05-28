use std::ops::{Deref, DerefMut};

use components::{EphemeralRegistry, LocalBroadcaster, MemStore};
use libchat::{
    Content, Context, ConversationClass, ConvoOutcome, GroupConvo, NewConversation, PayloadOutcome,
    hex_trunc,
};

type ResultCallback = Box<dyn Fn(&PayloadOutcome)>;

// Simple client Functionality for testing
struct Client {
    inner: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
    on_result: Option<ResultCallback>,
    new_conversations: Vec<NewConversation>,
    received_messages: Vec<(libchat::ConversationId, Content)>,
}

impl Client {
    fn init(
        ctx: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
        cb: Option<impl Fn(&PayloadOutcome) + 'static>,
    ) -> Self {
        Client {
            inner: ctx,
            on_result: cb.map(|f| Box::new(f) as ResultCallback),
            new_conversations: Vec::new(),
            received_messages: Vec::new(),
        }
    }

    fn process_messages(&mut self) {
        let payloads: Vec<_> = {
            let mut ds = self.ds();
            std::iter::from_fn(|| ds.poll()).collect()
        };

        for data in payloads {
            let result = self.handle_payload(&data).unwrap();
            if let Some(cb) = &self.on_result {
                cb(&result);
            }
            match result {
                PayloadOutcome::Empty => {}
                PayloadOutcome::Convo(co) => self.absorb_convo_outcome(co),
                PayloadOutcome::Inbox(io) => {
                    self.new_conversations.push(io.new_conversation);
                    if let Some(initial) = io.initial {
                        self.absorb_convo_outcome(initial);
                    }
                }
            }
        }
    }

    fn absorb_convo_outcome(&mut self, outcome: ConvoOutcome) {
        if let Some(content) = outcome.content {
            self.received_messages.push((outcome.convo_id, content));
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
fn pretty_print(prefix: impl Into<String>) -> ResultCallback {
    let prefix = prefix.into();
    Box::new(move |result: &PayloadOutcome| match result {
        PayloadOutcome::Empty => {}
        PayloadOutcome::Inbox(io) => {
            let cid = hex_trunc(io.new_conversation.convo_id.as_bytes());
            println!(
                "{prefix}      ({cid:?}) [conversation started: {:?}]",
                io.new_conversation.class
            );
            if let Some(initial) = &io.initial {
                print_contents(&prefix, initial);
            }
        }
        PayloadOutcome::Convo(co) => print_contents(&prefix, co),
    })
}

fn print_contents(prefix: &str, outcome: &ConvoOutcome) {
    let cid = hex_trunc(outcome.convo_id.as_bytes());
    if let Some(content) = &outcome.content {
        let text = String::from_utf8_lossy(&content.bytes);
        println!("{prefix}      ({cid:?}) {text}");
    }
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

    let convo_id = s_convo.id().to_string();

    // Raya can read this message because
    //   1) It was sent after add_members was committed, and
    //   2) LocalBroadcaster provides historical messages.

    clients[SARO]
        .convo(&convo_id)
        .send_content(b"ok who broke the group chat again")
        .unwrap();

    process(&mut clients);

    // Raya should observe exactly one new Group conversation from the
    // welcome, even though no initial content arrives with it.
    let raya_started = clients[RAYA]
        .new_conversations
        .iter()
        .filter(|nc| matches!(nc.class, ConversationClass::Group))
        .count();
    assert_eq!(
        raya_started, 1,
        "Raya should have observed exactly one new Group conversation for the welcome"
    );

    clients[RAYA]
        .convo(&convo_id)
        .send_content(b"it was literally working five minutes ago")
        .unwrap();

    process(&mut clients);

    let pax_ctx = Context::new_with_name("pax", ds, rs, MemStore::new()).unwrap();
    clients.push(Client::init(pax_ctx, Some(pretty_print("           Pax"))));
    const PAX: usize = 2;

    let pax_id = clients[PAX].account_id().clone();
    clients[SARO]
        .convo(&convo_id)
        .add_member(&[&pax_id])
        .unwrap();

    process(&mut clients);

    let pax_started = clients[PAX]
        .new_conversations
        .iter()
        .filter(|nc| matches!(nc.class, ConversationClass::Group))
        .count();
    assert_eq!(
        pax_started, 1,
        "Pax should have observed exactly one new Group conversation for the welcome"
    );

    clients[PAX]
        .convo(&convo_id)
        .send_content(b"ngl the key rotation is cooked")
        .unwrap();

    process(&mut clients);

    clients[SARO]
        .convo(&convo_id)
        .send_content(b"bro we literally just added you to the group ")
        .unwrap();

    process(&mut clients);
}
