//! Proves a GroupV1 conversation survives a full `Core` restart once MLS state
//! is backed by the durable SQLite `StorageProvider` (issue #112).
//!
//! Saro and Raya exchange over a group; Saro's `Core` is dropped and rebuilt
//! against the same DB files and identity; Saro sends again and Raya still
//! receives it. The post-restart send rehydrates the MLS group via
//! `MlsGroup::load` from durable storage — with the in-memory provider the
//! group would be gone and the send would fail.

use chat_sqlite::{ChatStorage, StorageConfig};
use components::{EphemeralRegistry, LocalBroadcaster};
use libchat::{ConvoOutcome, Core, PayloadOutcome, WakeupService};
use logos_account::TestLogosAccount;

#[derive(Debug)]
struct NoopWakeupService {}
impl WakeupService for NoopWakeupService {
    fn wakeup_in(&mut self, _: std::time::Duration, _: libchat::ConversationId) {}
}

type TestCore = Core<(
    TestLogosAccount,
    LocalBroadcaster,
    EphemeralRegistry,
    NoopWakeupService,
    ChatStorage,
)>;

/// Builds a `Core` whose single store holds both the conversation metadata and
/// the MLS group state in one on-disk DB, so both persist across a restart.
fn build(
    account: TestLogosAccount,
    ds: LocalBroadcaster,
    rs: EphemeralRegistry,
    db_path: &str,
) -> TestCore {
    let chat = ChatStorage::new(StorageConfig::File(db_path.to_string())).unwrap();
    Core::new_with_name(account, ds, rs, NoopWakeupService {}, chat).unwrap()
}

/// Drains everything queued for `core`, returning the bytes of any received
/// conversation messages.
fn drain(core: &mut TestCore) -> Vec<Vec<u8>> {
    let payloads: Vec<_> = {
        let ds = core.ds();
        std::iter::from_fn(|| ds.poll()).collect()
    };
    let mut received = vec![];
    for data in payloads {
        if let PayloadOutcome::Convo(ConvoOutcome {
            content: Some(content),
            ..
        }) = core.handle_payload(&data).unwrap()
        {
            received.push(content.bytes);
        }
    }
    received
}

#[test]
fn group_v1_resumes_after_core_restart() {
    let dir = tempfile::tempdir().unwrap();
    let saro_db = dir.path().join("saro.db").to_string_lossy().into_owned();
    let raya_db = dir.path().join("raya.db").to_string_lossy().into_owned();

    let ds = LocalBroadcaster::new();
    let rs = EphemeralRegistry::new();

    // Cloned so Saro keeps the same identity across the restart (delegate
    // persistence is a separate concern; here we hold identity fixed to isolate
    // the MLS-storage contribution).
    let saro_account = TestLogosAccount::new("saro");
    let raya_account = TestLogosAccount::new("raya");

    let mut saro = build(
        saro_account.clone(),
        ds.new_consumer(),
        rs.clone(),
        &saro_db,
    );
    let mut raya = build(raya_account, ds.new_consumer(), rs.clone(), &raya_db);

    // Saro creates a group with Raya; Raya processes the Welcome and joins.
    let raya_id = raya.ident_id().clone();
    let convo_id = saro.create_group_convo_v1(&[&raya_id]).unwrap().to_string();
    drain(&mut raya);

    saro.send_content(&convo_id, b"before restart").unwrap();
    assert_eq!(drain(&mut raya), vec![b"before restart".to_vec()]);

    // Restart Saro: drop the Core, rebuild against the same DB file and
    // identity. The only thing carrying the group forward is the MLS state
    // persisted in `saro.db`.
    drop(saro);
    let mut saro = build(saro_account, ds.new_consumer(), rs.clone(), &saro_db);

    // The send rehydrates the group via `MlsGroup::load` from durable storage.
    saro.send_content(&convo_id, b"after restart").unwrap();
    assert_eq!(
        drain(&mut raya),
        vec![b"after restart".to_vec()],
        "Raya must receive Saro's post-restart message: the MLS group resumed \
         from durable SQLite storage"
    );
}
