use chat_sqlite::{ChatStorage, StorageConfig};
use libchat::{Context, ConversationKind, Introduction, ProcessResponse};
use storage::{ConversationStore, IdentityStore};
use tempfile::tempdir;

use components::{EphemeralRegistry, LocalBroadcaster};

fn expect_convo_response(result: ProcessResponse) -> libchat::FrameOutcome {
    match result {
        ProcessResponse::ConvoResponse(r) => r.frame,
        other => panic!("expected ConvoResponse, got {other:?}"),
    }
}

fn expect_inbox_response(result: ProcessResponse) -> libchat::InboxResponse {
    match result {
        ProcessResponse::InboxResponse(r) => r,
        other => panic!("expected InboxResponse, got {other:?}"),
    }
}

fn send_and_verify(
    sender: &mut Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>,
    receiver: &mut Context<LocalBroadcaster, EphemeralRegistry, ChatStorage>,
    convo_id: &str,
    content: &[u8],
) {
    let payloads = sender.send_content(convo_id, content).unwrap();
    let payload = payloads.first().unwrap();
    let result = receiver.handle_payload(&payload.data).unwrap();
    let frame = expect_convo_response(result);
    let msg = frame
        .message
        .as_ref()
        .expect("steady-state send should yield one message");
    assert_eq!(content, msg.content.as_slice());
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

    // Raya receives the invite + initial message
    let payload = payloads.first().unwrap();
    let initial = expect_inbox_response(raya.handle_payload(&payload.data).unwrap());
    let new_convo = &initial.new_conversation;
    assert!(matches!(new_convo.kind, ConversationKind::PrivateV1));
    let initial_msg = initial
        .frame
        .as_ref()
        .and_then(|f| f.message.as_ref())
        .expect("invite must include initial message");
    assert_eq!(content, initial_msg.content);
    assert_eq!(new_convo.convo_id, initial_msg.convo_id);
    let raya_convo_id = new_convo.convo_id.clone();

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
    let result = expect_inbox_response(alice.handle_payload(&payload.data).unwrap());
    let new_convo = &result.new_conversation;
    assert!(matches!(new_convo.kind, ConversationKind::PrivateV1));

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
    let result = expect_inbox_response(alice.handle_payload(&payload.data).unwrap());
    let alice_convo_id = result.new_conversation.convo_id.clone();

    let payloads = alice.send_content(&alice_convo_id, b"reply 1").unwrap();
    let payload = payloads.first().unwrap();
    let frame = expect_convo_response(bob.handle_payload(&payload.data).unwrap());
    assert_eq!(frame.message.unwrap().content, b"reply 1");

    let payloads = bob.send_content(&bob_convo_id, b"reply 2").unwrap();
    let payload = payloads.first().unwrap();
    let frame = expect_convo_response(alice.handle_payload(&payload.data).unwrap());
    assert_eq!(frame.message.unwrap().content, b"reply 2");

    // Verify conversation list
    let convo_ids = alice.list_conversations().unwrap();
    assert_eq!(convo_ids.len(), 1);

    // Continue exchanging messages
    let payloads = bob.send_content(&bob_convo_id, b"more messages").unwrap();
    let payload = payloads.first().unwrap();
    let frame = expect_convo_response(alice.handle_payload(&payload.data).expect("should decrypt"));
    assert_eq!(frame.message.unwrap().content, b"more messages");

    // Alice can also send back
    let payloads = alice.send_content(&alice_convo_id, b"alice reply").unwrap();
    let payload = payloads.first().unwrap();
    let frame = expect_convo_response(bob.handle_payload(&payload.data).unwrap());
    assert_eq!(frame.message.unwrap().content, b"alice reply");
}
