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

    // The sender a recipient resolves each author to — the key-based identity,
    // captured from the account (not the display name in `ident_id`).
    let raya_sender = harness.raya().as_sender();
    let pax_sender = harness.pax().as_sender();

    // Each message must arrive *and* carry the validated sender of its author:
    // M_R1 from Raya, M_P1 from Pax.
    assert!(
        harness
            .saro()
            .check(&convo_id, M_R1, Some(raya_sender.clone()))
    );
    assert!(
        harness
            .saro()
            .check(&convo_id, M_P1, Some(pax_sender.clone()))
    );

    assert!(
        !harness
            .raya()
            .check(&convo_id, M_R1, Some(raya_sender.clone()))
    );
    assert!(
        harness
            .raya()
            .check(&convo_id, M_P1, Some(pax_sender.clone()))
    );

    assert!(
        !harness
            .pax()
            .check(&convo_id, M_R1, Some(raya_sender.clone()))
    );
    assert!(
        !harness
            .pax()
            .check(&convo_id, M_P1, Some(pax_sender.clone()))
    );

    // Single-key testnet account: account and local identity are the same key.
    assert_eq!(
        raya_sender.account, raya_sender.local_identity,
        "single-key testnet account resolves Account == LocalIdentity"
    );
    // Distinct identities resolve to distinct accounts — the basis for telling
    // group members apart and for collapsing an account's devices to one Account.
    assert_ne!(
        raya_sender.account, pax_sender.account,
        "Raya and Pax must resolve to different accounts"
    );
}
