use chat_sqlite::{ChatStorage, StorageConfig};
use libchat::{ConversationClass, Core, Introduction, PayloadOutcome, WakeupService};
use logos_account::TestLogosAccount;
use storage::{ConversationStore, IdentityStore};
use tempfile::tempdir;

use components::{EphemeralRegistry, LocalBroadcaster};

#[derive(Debug)]
struct NoopWakeupService {}
impl WakeupService for NoopWakeupService {
    fn wakeup_in(&mut self, _: std::time::Duration, _: libchat::ConversationId) {}
}

type PrivateCore = Core<(
    TestLogosAccount,
    LocalBroadcaster,
    EphemeralRegistry,
    NoopWakeupService,
    ChatStorage,
)>;

/// Drains everything published to `receiver`'s delivery service and feeds each
/// payload back through `handle_payload`, returning the observed outcomes.
fn deliver(receiver: &mut PrivateCore) -> Vec<PayloadOutcome> {
    let payloads: Vec<_> = {
        let ds = receiver.ds();
        std::iter::from_fn(|| ds.poll()).collect()
    };
    payloads
        .iter()
        .map(|data| receiver.handle_payload(data).unwrap())
        .collect()
}

/// Delivers to `receiver`, asserting it observed exactly one outcome.
fn recv_one(receiver: &mut PrivateCore) -> PayloadOutcome {
    let mut outcomes = deliver(receiver);
    assert_eq!(
        outcomes.len(),
        1,
        "expected exactly one delivered outcome, got {outcomes:?}"
    );
    outcomes.pop().unwrap()
}

fn send_and_verify(
    sender: &mut PrivateCore,
    receiver: &mut PrivateCore,
    convo_id: &str,
    content: &[u8],
) {
    sender.send_content(convo_id, content).unwrap();
    let content_out = expect_convo(recv_one(receiver))
        .content
        .expect("steady-state send should yield one content");
    assert_eq!(content, content_out.bytes.as_slice());
}

#[test]
fn ctx_integration() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    let saro_account = TestLogosAccount::new("saro");
    let mut saro = Core::new_with_name(
        saro_account,
        ds.clone(),
        rs.clone(),
        NoopWakeupService {},
        ChatStorage::in_memory(),
    )
    .unwrap();
    let raya_account = TestLogosAccount::new("raya");
    let mut raya = Core::new_with_name(
        raya_account,
        ds,
        rs,
        NoopWakeupService {},
        ChatStorage::in_memory(),
    )
    .unwrap();

    // Raya creates intro bundle and sends to Saro
    let bundle = raya.create_intro_bundle().unwrap();
    let intro = Introduction::try_from(bundle.as_slice()).unwrap();

    // Saro initiates conversation with Raya
    let mut content = vec![10];
    let saro_convo_id = saro.create_private_convo_v1(&intro, &content).unwrap();

    // Raya receives the invite + initial message
    let initial = recv_one(&mut raya);
    let PayloadOutcome::Inbox(io) = initial else {
        panic!("invite must yield PayloadOutcome::Inbox, got {initial:?}");
    };
    assert!(matches!(
        io.new_conversation.class,
        ConversationClass::Private
    ));
    let initial_co = io.initial.expect("invite must include initial content");
    assert_eq!(io.new_conversation.convo_id, initial_co.convo_id);
    let initial_content = initial_co
        .content
        .expect("invite must include initial message");
    assert_eq!(content, initial_content.bytes);
    let raya_convo_id = io.new_conversation.convo_id.clone();

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
    let alice_account = TestLogosAccount::new("alice");
    let ctx1 = Core::new_with_name(alice_account, ds, rs, NoopWakeupService {}, store1).unwrap();
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
    let alice_account = TestLogosAccount::new("alice");
    let core = Core::new_from_store(alice_account, ds, rs, NoopWakeupService {}, store).unwrap();
    let pubkey = core.identity().public_key();
    drop(core);

    let store = ChatStorage::new(StorageConfig::File(db_path)).unwrap();
    let persisted = store.load_identity().unwrap().unwrap();

    assert_eq!(persisted.get_name(), "alice");
    assert_eq!(persisted.public_key(), pubkey);
}

#[test]
fn conversation_metadata_persistence() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();
    let alice_account = TestLogosAccount::new("alice");
    let mut alice = Core::new_with_name(
        alice_account,
        ds.clone(),
        rs.clone(),
        NoopWakeupService {},
        ChatStorage::in_memory(),
    )
    .unwrap();
    let bob_account = TestLogosAccount::new("bob");
    let mut bob = Core::new_with_name(
        bob_account,
        ds,
        rs,
        NoopWakeupService {},
        ChatStorage::in_memory(),
    )
    .unwrap();

    let bundle = alice.create_intro_bundle().unwrap();
    let intro = Introduction::try_from(bundle.as_slice()).unwrap();
    bob.create_private_convo_v1(&intro, b"hi").unwrap();

    let result = recv_one(&mut alice);
    let PayloadOutcome::Inbox(io) = result else {
        panic!("invite must yield PayloadOutcome::Inbox, got {result:?}");
    };
    assert!(matches!(
        io.new_conversation.class,
        ConversationClass::Private
    ));

    let convos = alice.store().load_conversations().unwrap();
    assert_eq!(convos.len(), 1);
    assert_eq!(convos[0].kind.as_str(), "private_v1");
}

#[test]
fn conversation_full_flow() {
    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();
    let alice_account = TestLogosAccount::new("alice");
    let mut alice = Core::new_with_name(
        alice_account,
        ds.clone(),
        rs.clone(),
        NoopWakeupService {},
        ChatStorage::in_memory(),
    )
    .unwrap();
    let bob_account = TestLogosAccount::new("bob");
    let mut bob = Core::new_with_name(
        bob_account,
        ds,
        rs,
        NoopWakeupService {},
        ChatStorage::in_memory(),
    )
    .unwrap();

    let bundle = alice.create_intro_bundle().unwrap();
    let intro = Introduction::try_from(bundle.as_slice()).unwrap();
    let bob_convo_id = bob.create_private_convo_v1(&intro, b"hello").unwrap();

    let result = recv_one(&mut alice);
    let PayloadOutcome::Inbox(io) = result else {
        panic!("invite must yield PayloadOutcome::Inbox, got {result:?}");
    };
    let alice_convo_id = io.new_conversation.convo_id.clone();

    alice.send_content(&alice_convo_id, b"reply 1").unwrap();
    assert_eq!(
        expect_convo(recv_one(&mut bob))
            .content
            .expect("message content")
            .bytes,
        b"reply 1"
    );

    bob.send_content(&bob_convo_id, b"reply 2").unwrap();
    assert_eq!(
        expect_convo(recv_one(&mut alice))
            .content
            .expect("message content")
            .bytes,
        b"reply 2"
    );

    // Verify conversation list
    let convo_ids = alice.list_conversations().unwrap();
    assert_eq!(convo_ids.len(), 1);

    // Continue exchanging messages
    bob.send_content(&bob_convo_id, b"more messages").unwrap();
    assert_eq!(
        expect_convo(recv_one(&mut alice))
            .content
            .expect("message content")
            .bytes,
        b"more messages"
    );

    // Alice can also send back
    alice.send_content(&alice_convo_id, b"alice reply").unwrap();
    assert_eq!(
        expect_convo(recv_one(&mut bob))
            .content
            .expect("message content")
            .bytes,
        b"alice reply"
    );
}

fn expect_convo(result: PayloadOutcome) -> libchat::ConvoOutcome {
    match result {
        PayloadOutcome::Convo(co) => co,
        other => panic!("expected PayloadOutcome::Convo, got {other:?}"),
    }
}
