use chat_sqlite::{ChatStorage, StorageConfig};
use libchat::{Context, ConversationIdOwned, DeliveryService, Event, Introduction};
use storage::{ConversationStore, IdentityStore};
use tempfile::tempdir;

use components::{EphemeralRegistry, LocalBroadcaster};

fn poll_one(ctx: &Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>) -> Vec<u8> {
    ctx.ds()
        .pull()
        .into_iter()
        .next()
        .expect("expected payload in delivery queue")
}

fn send_and_verify(
    sender: &mut Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>,
    receiver: &mut Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>,
    convo_id: &str,
    content: &[u8],
) {
    let events = sender.send_content(convo_id, content).unwrap();
    assert!(events.is_empty(), "unexpected send events: {events:?}");

    let payload = poll_one(receiver);
    let events = receiver.handle_payload(&payload).unwrap();
    match events.as_slice() {
        [Event::MessageReceived { data, .. }] => assert_eq!(data.as_slice(), content),
        other => panic!("expected [MessageReceived], got {other:?}"),
    }
}

fn expect_invite(events: &[Event], expected_data: &[u8]) -> ConversationIdOwned {
    match events {
        [
            Event::ConversationStarted {
                conversation_id: started,
                ..
            },
            Event::MessageReceived {
                conversation_id: received,
                data,
                ..
            },
        ] => {
            assert_eq!(started, received);
            assert_eq!(data.as_slice(), expected_data);
            started.clone()
        }
        other => panic!("expected [ConversationStarted, MessageReceived], got {other:?}"),
    }
}

#[test]
fn ctx_integration() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let mut saro =
        Context::new_with_name("saro", ds.clone(), rs.clone(), ChatStorage::in_memory()).unwrap();
    let mut raya = Context::new_with_name("raya", ds, rs, ChatStorage::in_memory()).unwrap();

    // Raya creates intro bundle and sends to Saro
    let bundle = raya.create_intro_bundle().unwrap();
    let intro = Introduction::try_from(bundle.as_slice()).unwrap();

    // Saro initiates conversation with Raya
    let mut content = vec![10];
    let (saro_convo_id, events) = saro.create_private_convo(&intro, &content).unwrap();
    assert!(events.is_empty(), "unexpected create events: {events:?}");

    // Raya receives initial message
    let payload = poll_one(&raya);
    let events = raya.handle_payload(&payload).unwrap();
    let raya_convo_id = expect_invite(&events, &content);

    // Exchange messages back and forth
    for _ in 0..10 {
        content.push(content.last().unwrap() + 1);
        send_and_verify(&mut raya, &mut saro, &raya_convo_id, &content);

        content.push(content.last().unwrap() + 1);
        send_and_verify(&mut saro, &mut raya, &saro_convo_id, &content);
    }
}

#[test]
fn identity_persistence() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();
    let store1 = ChatStorage::new(StorageConfig::InMemory).unwrap();
    let ctx1 = Context::new_with_name("alice", ds, rs, store1).unwrap();
    let pubkey1 = ctx1.identity().public_key();
    let name1 = ctx1.installation_name().to_string();

    assert_eq!(name1, "alice");
    assert!(!pubkey1.as_bytes().iter().all(|&b| b == 0));
}

#[test]
fn open_persists_new_identity() {
    let dir = tempdir().unwrap();
    let db_path = dir.path().join("chat.sqlite");
    let db_path = db_path.to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();
    let store = ChatStorage::new(StorageConfig::File(db_path.clone())).unwrap();
    let ctx = Context::new_from_store("alice", ds, rs, store).unwrap();
    let pubkey = ctx.identity().public_key();
    drop(ctx);

    let store = ChatStorage::new(StorageConfig::File(db_path)).unwrap();
    let persisted = store.load_identity().unwrap().unwrap();

    assert_eq!(persisted.get_name(), "alice");
    assert_eq!(persisted.public_key(), pubkey);
}

#[test]
fn conversation_metadata_persistence() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();
    let mut alice =
        Context::new_with_name("alice", ds.clone(), rs.clone(), ChatStorage::in_memory()).unwrap();
    let mut bob = Context::new_with_name("bob", ds, rs, ChatStorage::in_memory()).unwrap();

    let bundle = alice.create_intro_bundle().unwrap();
    let intro = Introduction::try_from(bundle.as_slice()).unwrap();
    let (_, events) = bob.create_private_convo(&intro, b"hi").unwrap();
    assert!(events.is_empty());

    let payload = poll_one(&alice);
    let events = alice.handle_payload(&payload).unwrap();
    expect_invite(&events, b"hi");

    let convos = alice.store().load_conversations().unwrap();
    assert_eq!(convos.len(), 1);
    assert_eq!(convos[0].kind.as_str(), "private_v1");
}

#[test]
fn conversation_full_flow() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();
    let mut alice =
        Context::new_with_name("alice", ds.clone(), rs.clone(), ChatStorage::in_memory()).unwrap();
    let mut bob = Context::new_with_name("bob", ds, rs, ChatStorage::in_memory()).unwrap();

    let bundle = alice.create_intro_bundle().unwrap();
    let intro = Introduction::try_from(bundle.as_slice()).unwrap();
    let (bob_convo_id, events) = bob.create_private_convo(&intro, b"hello").unwrap();
    assert!(events.is_empty());

    let payload = poll_one(&alice);
    let events = alice.handle_payload(&payload).unwrap();
    let alice_convo_id = expect_invite(&events, b"hello");

    let events = alice.send_content(&alice_convo_id, b"reply 1").unwrap();
    assert!(events.is_empty());
    let payload = poll_one(&bob);
    bob.handle_payload(&payload).unwrap();

    let events = bob.send_content(&bob_convo_id, b"reply 2").unwrap();
    assert!(events.is_empty());
    let payload = poll_one(&alice);
    alice.handle_payload(&payload).unwrap();

    // Verify conversation list
    let convo_ids = alice.list_conversations().unwrap();
    assert_eq!(convo_ids.len(), 1);

    // Continue exchanging messages
    let events = bob.send_content(&bob_convo_id, b"more messages").unwrap();
    assert!(events.is_empty());
    let payload = poll_one(&alice);
    let events = alice.handle_payload(&payload).expect("should decrypt");
    match events.as_slice() {
        [Event::MessageReceived { data, .. }] => assert_eq!(data.as_slice(), b"more messages"),
        other => panic!("expected [MessageReceived], got {other:?}"),
    }

    // Alice can also send back
    let events = alice.send_content(&alice_convo_id, b"alice reply").unwrap();
    assert!(events.is_empty());
    let payload = poll_one(&bob);
    let events = bob.handle_payload(&payload).unwrap();
    match events.as_slice() {
        [Event::MessageReceived { data, .. }] => assert_eq!(data.as_slice(), b"alice reply"),
        other => panic!("expected [MessageReceived], got {other:?}"),
    }
}
