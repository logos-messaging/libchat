use integration_tests_core::TestHarness;
use std::time::Duration;

#[test]
fn create_group() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let raya_id = harness.raya().ident_id().clone();
    let pax_id = harness.pax().ident_id().clone();

    const M_R1: &[u8; 12] = b"Hi From Raya";
    const M_P1: &[u8; 13] = b"Hey it's Pax!";

    // Step: Saro Create Convo with Raya

    let convo_id = harness
        .saro()
        .create_group_convo_v1(&[&raya_id])
        .expect("Saro invite Raya ");
    harness.process_until(|h| h.raya().list_conversations().unwrap().len() == 1);

    // Step: Raya Send Content

    harness
        .raya()
        .send_content(&convo_id, M_R1)
        .expect("Raya send Msg");

    harness.process_until(|h| h.saro().received_messages().len() == 1);

    // Step: Saro add Pax

    harness
        .saro()
        .group_add_member(&convo_id, &[&pax_id])
        .expect("Saro invite pax");
    harness.process_until(|h| h.pax().list_conversations().unwrap().len() == 1);

    // Step: Pax send Content

    harness
        .pax()
        .send_content(&convo_id, M_P1)
        .expect("Pax send");
    harness.process(Duration::from_millis(500));

    assert!(harness.saro().check(&convo_id, M_R1));
    assert!(harness.saro().check(&convo_id, M_P1));

    assert!(!harness.raya().check(&convo_id, M_R1));
    assert!(harness.raya().check(&convo_id, M_P1));

    assert!(!harness.pax().check(&convo_id, M_R1));
    assert!(!harness.pax().check(&convo_id, M_P1));

    // Every delivered message carries a verified sender: both the Account and
    // the LocalIdentity it was sent from. On testnet each identity is its own
    // single-device account, so the two resolve to the same key.
    let raya_sender = harness
        .saro()
        .sender_of(&convo_id, M_R1)
        .expect("Saro should see who sent Raya's message")
        .clone();
    assert_eq!(
        raya_sender.account, raya_sender.local_identity,
        "single-key testnet account resolves Account == LocalIdentity"
    );

    let pax_sender = harness
        .saro()
        .sender_of(&convo_id, M_P1)
        .expect("Saro should see who sent Pax's message")
        .clone();

    // Distinct identities resolve to distinct senders — the basis for telling
    // group members apart and for collapsing an account's devices to one Account.
    assert_ne!(
        raya_sender.account, pax_sender.account,
        "Raya and Pax must resolve to different accounts"
    );
}
