use libchat::{Context, Introduction};
use sqlite::{ChatStorage, StorageConfig};
use storage::{ConversationStore, IdentityStore};
use tempfile::tempdir;

use components::{EphemeralRegistry, LocalBroadcaster};

fn send_and_verify(
    sender: &mut Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>,
    receiver: &mut Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>,
    convo_id: &str,
    content: &[u8],
) {
    let payloads = sender.send_content(convo_id, content).unwrap();
    let payload = payloads.first().unwrap();
    let received = receiver
        .handle_payload(&payload.data)
        .unwrap()
        .expect("expected content");
    assert_eq!(content, received.data.as_slice());
    assert!(!received.is_new_convo);
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
    let (saro_convo_id, payloads) = saro.create_private_convo(&intro, &content).unwrap();

    // Raya receives initial message
    let payload = payloads.first().unwrap();
    let initial_content = raya
        .handle_payload(&payload.data)
        .unwrap()
        .expect("expected initial content");

    let raya_convo_id = initial_content.conversation_id;
    assert_eq!(content, initial_content.data);
    assert!(initial_content.is_new_convo);

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

    // For persistence tests with file-based storage, we'd need a shared db.
    // With in-memory, we just verify the identity was created.
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
    let (_, payloads) = bob.create_private_convo(&intro, b"hi").unwrap();

    let payload = payloads.first().unwrap();
    let content = alice.handle_payload(&payload.data).unwrap().unwrap();
    assert!(content.is_new_convo);

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
    let (bob_convo_id, payloads) = bob.create_private_convo(&intro, b"hello").unwrap();

    let payload = payloads.first().unwrap();
    let content = alice.handle_payload(&payload.data).unwrap().unwrap();
    let alice_convo_id = content.conversation_id;

    let payloads = alice.send_content(&alice_convo_id, b"reply 1").unwrap();
    let payload = payloads.first().unwrap();
    bob.handle_payload(&payload.data).unwrap().unwrap();

    let payloads = bob.send_content(&bob_convo_id, b"reply 2").unwrap();
    let payload = payloads.first().unwrap();
    alice.handle_payload(&payload.data).unwrap().unwrap();

    // Verify conversation list
    let convo_ids = alice.list_conversations().unwrap();
    assert_eq!(convo_ids.len(), 1);

    // Continue exchanging messages
    let payloads = bob.send_content(&bob_convo_id, b"more messages").unwrap();
    let payload = payloads.first().unwrap();
    let content = alice
        .handle_payload(&payload.data)
        .expect("should decrypt")
        .expect("should have content");
    assert_eq!(content.data, b"more messages");

    // Alice can also send back
    let payloads = alice.send_content(&alice_convo_id, b"alice reply").unwrap();
    let payload = payloads.first().unwrap();
    let content = bob
        .handle_payload(&payload.data)
        .unwrap()
        .expect("bob should receive");
    assert_eq!(content.data, b"alice reply");
}
