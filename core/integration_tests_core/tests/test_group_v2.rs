use integration_tests_core::TestHarness;
use tracing::info;

#[test]
fn groupv2_2way_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const S_M1: &[u8] = b"aaaaa";
    const R_M1: &[u8] = b"Hello";

    // Initialize TestHarness with 2 clients
    let mut harness = TestHarness::<2>::new(|_, _| {});

    //Saro Create Convo
    let particpants = &[&harness.raya().addr()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(particpants)
        .expect("saro create group");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("Saro Send", |h| h.raya().convo_count() == 1);

    // Saro sends a message; settle until Raya receives it.
    info!(target: "chat", "Saro -> sending: {S_M1:?}");
    harness
        .saro()
        .send_content(&convo_id, S_M1)
        .expect("saro send");

    harness.process_until(|h| h.raya().check(&convo_id, S_M1));

    // Raya replies; settle until Saro receives it.
    info!(target: "chat", "Raya -> sending:{R_M1:?}");
    harness.raya().send_content(&convo_id, R_M1).unwrap();
    harness.process_until(|h| h.saro().check(&convo_id, R_M1));
}

#[test]
fn core_client() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const S_M1: &[u8] = b"HI";
    const R_M1: &[u8] = b"hi back";
    const S_M2: &[u8] = b"EPOCHCHK";

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let particpants = &[&harness.raya().addr()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(particpants)
        .expect("Saro create");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("saro create", |h| h.raya().convo_count() == 1);

    // Saro sends a message; settle until Raya receives it.
    info!(target: "chat", "Saro -> sending: {S_M1:?}");
    harness
        .saro()
        .send_content(&convo_id, S_M1)
        .expect("saro send");

    harness.process_until_label("Recv S_M1", |h| h.raya().check(&convo_id, S_M1));

    // Raya replies; settle until Saro receives it.
    info!(target: "chat", "Raya -> sending: {R_M1:?}");
    harness
        .raya()
        .send_content(&convo_id, R_M1)
        .expect("raya send");

    harness.process_until_label("Recv R_M1", |h| h.saro().check(&convo_id, R_M1));

    // Raya (a non-creator) invites Pax; settle until Pax has joined.
    let particpants = &[&harness.pax().addr()];
    harness
        .raya()
        .group_add_member(&convo_id, particpants)
        .expect("Raya add Pax");

    harness.process_until_label("Raya add Pax", |h| h.pax().convo_count() == 1);

    // Everyone must be at the SAME epoch after Pax joined: a marker Saro sends
    // now decrypts only for members that applied the Add commit.
    info!(target: "chat", "Saro -> sending: EPOCHCHK");
    harness.saro().send_content(&convo_id, S_M2).unwrap();

    harness.process_until_label("epoch check", |h| {
        h.raya().check(&convo_id, S_M2) && h.pax().check(&convo_id, S_M2)
    });
}

#[test]
fn core_client_batch_add() {
    // Saro creates the group and adds BOTH Raya and Pax at the same time: one
    // Add commit producing a single welcome that names both joiners.

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer();

    let mut harness = TestHarness::<3>::new(|_, _| {});

    let particpants = &[&harness.raya().addr(), &harness.pax().addr()];
    harness
        .saro()
        .create_group_convo_v2(particpants)
        .expect("Saro create");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("saro create", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });
}

#[test]
fn core_client_four_members_two_epochs() {
    // Epoch 1: Saro creates and batch-adds Raya + Pax (3 members). Epoch 2: Raya
    // (a non-creator) adds a 4th member, Mira. Afterwards every member must be
    // at the same epoch (each can decrypt a freshly-sent message) and settled
    // back in Working (the >sn_max election that the 4th member triggers must
    // have completed — no one stuck in Freezing/Selection/Reelection).

    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    const MSG: &[u8] = b"CONVERGED";

    let mut harness = TestHarness::<4>::new(|_, _| {});

    let particpants = &[&harness.raya().addr(), &harness.pax().addr()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(particpants)
        .expect("Saro create");

    // Carry the invite through (commit, WelcomeReady, routing to Raya's inbox,
    // accept_welcome); settle until Raya has joined.
    harness.process_until_label("Raya + Pax join", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });

    // Epoch 2: Raya adds the 4th member; settle until Mira has joined and the
    // >sn_max election has returned everyone to Working.
    let members = &[&harness.mira().addr()];
    harness
        .raya()
        .group_add_member(&convo_id, members)
        .expect("Add Mira");

    // TODO: Add State == Working for all clients
    harness.process_until_label("Mira join", |h| h.mira().convo_count() == 1);

    // Same epoch: a message Saro sends now must reach all three peers.
    harness
        .saro()
        .send_content(&convo_id, MSG)
        .expect("Saro send");

    harness.process_until_label("all chats converge", |h| {
        h.raya().check(&convo_id, MSG)
            && h.pax().check(&convo_id, MSG)
            && h.mira().check(&convo_id, MSG)
    });
}

#[test]
fn member_joins_two_groups() {
    // The same installation is invited to two separate groups. Its single
    // registered key package is consumed by the first join, so the second
    // group's welcome must still admit it — otherwise it is rejected with
    // "welcome not addressed to this member" and never joins. Regression for
    // key-package reuse across groups.
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<2>::new(|_, _| {});
    let raya_addr = harness.raya().addr();

    // Group 1: Saro invites Raya.
    harness
        .saro()
        .create_group_convo_v2(&[&raya_addr])
        .expect("saro create group 1");
    harness.process_until_label("raya joins group 1", |h| h.raya().convo_count() == 1);

    // Group 2: Saro invites Raya again, into a fresh group.
    harness
        .saro()
        .create_group_convo_v2(&[&raya_addr])
        .expect("saro create group 2");
    harness.process_until_label("raya joins group 2", |h| h.raya().convo_count() == 2);

    assert_eq!(
        harness.raya().convo_count(),
        2,
        "raya did not join the second group"
    );
}

#[test]
fn direct_v1_then_group_v2_reuses_key_package() {
    // The reported flake: a DirectV1 (pairwise) conversation is opened with a
    // peer first, then the same peer is invited to a GroupV2. Both fetch the
    // peer's single registered key package; the DirectV1 join consumes it, so
    // without a last-resort key package the group welcome finds no key package
    // and is rejected ("welcome not addressed to this member").
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_test_writer()
        .try_init();

    let mut harness = TestHarness::<2>::new(|_, _| {});
    let raya_addr = harness.raya().addr();

    // 1. DirectV1 with Raya.
    harness
        .saro()
        .create_direct_convo_v1(&[&raya_addr])
        .expect("saro create direct");
    harness.process_until_label("raya joins direct", |h| h.raya().convo_count() == 1);

    // 2. GroupV2 inviting the same Raya.
    harness
        .saro()
        .create_group_convo_v2(&[&raya_addr])
        .expect("saro create group");
    harness.process_until_label("raya joins group", |h| h.raya().convo_count() == 2);

    assert_eq!(
        harness.raya().convo_count(),
        2,
        "raya did not join the group after a direct chat"
    );
}
