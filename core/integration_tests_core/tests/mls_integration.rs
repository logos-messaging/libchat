use std::ops::{Deref, DerefMut};

use components::{EphemeralRegistry, LocalBroadcaster, MemStore};
use libchat::{Context, DeliveryService, Event, GroupConvo, hex_trunc};

// Simple client Functionality for testing
struct Client {
    inner: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
    on_event: Option<Box<dyn Fn(Event)>>,
}

impl Client {
    fn init(
        ctx: Context<LocalBroadcaster, EphemeralRegistry, MemStore>,
        cb: Option<impl Fn(Event) + 'static>,
    ) -> Self {
        Client {
            inner: ctx,
            on_event: cb.map(|f| Box::new(f) as Box<dyn Fn(Event)>),
        }
    }

    fn process_messages(&mut self) {
        let messages: Vec<_> = {
            let ds = self.ds();
            ds.pull()
        };

        for data in messages {
            let events = self.handle_payload(&data).unwrap();
            if let Some(cb) = &self.on_event {
                for event in events {
                    cb(event);
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
fn pretty_print(prefix: impl Into<String>) -> Box<dyn Fn(Event)> {
    let prefix = prefix.into();
    Box::new(move |e: Event| match e {
        Event::ConversationStarted {
            conversation_id, ..
        } => {
            let cid = hex_trunc(conversation_id.as_bytes());
            println!("{prefix}      ({cid:?}) [conversation started]");
        }
        Event::MessageReceived {
            conversation_id,
            data,
            ..
        } => {
            let cid = hex_trunc(conversation_id.as_bytes());
            let content = String::from_utf8(data).unwrap();
            println!("{prefix}      ({cid:?}) {content}");
        }
        _ => {}
    })
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
    let (s_convo, _events) = clients[SARO].create_group_convo(&[&raya_id]).unwrap();

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

/// Regression for the silent-group-join bug fixed by the event system: when
/// Saro creates a group with Raya, Raya processes a Welcome message that
/// carries no application content. The application must still observe a
/// `ConversationStarted` event so the new group becomes visible.
#[test]
fn group_join_emits_conversation_started() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut saro =
        Context::new_with_name("saro", ds.new_consumer(), rs.clone(), MemStore::new()).unwrap();
    let mut raya = Context::new_with_name("raya", ds, rs, MemStore::new()).unwrap();

    let raya_account_id = raya.account_id().clone();

    let (group_convo, _events) = saro.create_group_convo(&[&raya_account_id]).unwrap();
    let expected_group_id = group_convo.id().to_string();

    // Drain everything Raya's transport produced and collect every event.
    let payloads: Vec<_> = {
        let ds = raya.ds();
        ds.pull()
    };
    let mut events = Vec::new();
    for data in payloads {
        events.extend(raya.handle_payload(&data).unwrap());
    }

    // Welcome carries no content, so we expect exactly one ConversationStarted
    // and nothing else. Prior to the bug fix Raya received Ok(None) and the
    // new group was invisible to the application layer.
    assert_eq!(
        events.len(),
        1,
        "expected exactly one event, got {events:?}"
    );
    match &events[0] {
        Event::ConversationStarted {
            conversation_id, ..
        } => {
            assert_eq!(conversation_id.as_ref(), expected_group_id.as_str());
        }
        other => panic!("expected ConversationStarted, got {other:?}"),
    }
}
