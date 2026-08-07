//! End-to-end causal-history gap detection on GroupV2.
//!
//! Saro and Raya share a GroupV2 conversation. Saro sends three messages; the
//! second never reaches Raya. The third carries the second in its causal
//! history, so Raya must detect and report the gap.

use integration_tests_core::TestHarness;
use libchat::MissingMessage;

#[test]
fn missing_group_v2_message_is_detected() {
    let mut harness = TestHarness::<2>::new(|_, _| {});

    let participants = &[&harness.raya().addr()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(participants, "", "")
        .expect("saro create group");

    // Carry the invite through (commit, WelcomeReady, inbox routing, welcome
    // accept) until Raya has joined.
    harness.process_until_label("raya joins", |h| h.raya().convo_count() == 1);

    // M1 is delivered normally.
    harness
        .saro()
        .send_content(&convo_id, b"first")
        .expect("saro send m1");
    harness.process_until_label("raya gets m1", |h| h.raya().check(&convo_id, b"first"));
    assert!(
        harness.raya().take_missing_messages().is_empty(),
        "no gap expected while every message is delivered"
    );

    // M2 is published but never reaches Raya. The settle above drained Raya's
    // queue, and `send_content` publishes synchronously, so discarding what is
    // pending now drops that message and nothing of the group protocol.
    harness
        .saro()
        .send_content(&convo_id, b"second")
        .expect("saro send m2");
    harness.raya().drop_pending_payloads();

    // M3 is delivered; its causal history references the dropped M2.
    harness
        .saro()
        .send_content(&convo_id, b"third")
        .expect("saro send m3");
    harness.process_until_label("raya gets m3", |h| h.raya().check(&convo_id, b"third"));

    let missing: Vec<MissingMessage> = harness.raya().take_missing_messages();
    assert_eq!(missing.len(), 1, "exactly one message should be missing");
    assert_eq!(missing[0].conversation_id, convo_id);
    assert!(
        !missing[0].frontier.message_id().is_empty(),
        "the missing message must be identified"
    );
    // The causal sender hint carries the MLS identity id ("saro") — the same
    // value de-mls stamps as the message's authenticated member id — not the
    // signer id the inbox and registry key on.
    assert_eq!(
        missing[0].frontier.sender_id(),
        "saro",
        "missing-message sender hint should attribute to Saro"
    );

    // Draining clears the report; a reported gap is not surfaced again.
    assert!(harness.raya().take_missing_messages().is_empty());
}
