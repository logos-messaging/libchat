//! End-to-end acknowledgement detection on GroupV2.
//!
//! Saro sends a message; Raya and Pax reply. Each reply carries Saro's message
//! in its causal history, so Saro learns both peers hold it — without either
//! sending anything back on purpose.

use integration_tests_core::TestHarness;
use libchat::MessageAck;

#[test]
fn replies_acknowledge_the_message_they_were_sent_after() {
    let mut harness = TestHarness::<3>::new(|_, _| {});

    let participants = &[&harness.raya().addr(), &harness.pax().addr()];
    let convo_id = harness
        .saro()
        .create_group_convo_v2(participants, "", "")
        .expect("saro create group");

    harness.process_until_label("peers join", |h| {
        h.raya().convo_count() == 1 && h.pax().convo_count() == 1
    });

    let message_id = harness
        .saro()
        .send_content(&convo_id, b"anyone there?")
        .expect("saro send");
    harness.process_until_label("peers get the message", |h| {
        h.raya().check(&convo_id, b"anyone there?") && h.pax().check(&convo_id, b"anyone there?")
    });
    assert!(
        harness.saro().take_acks().is_empty(),
        "holding a message is only observable once the peer sends"
    );

    // Each reply names Saro's message in its causal history.
    harness
        .raya()
        .send_content(&convo_id, b"raya here")
        .expect("raya reply");
    harness
        .pax()
        .send_content(&convo_id, b"pax here")
        .expect("pax reply");
    harness.process_until_label("saro gets both replies", |h| {
        h.saro().check(&convo_id, b"raya here") && h.saro().check(&convo_id, b"pax here")
    });

    let acks: Vec<MessageAck> = harness.saro().take_acks();
    let mut ackers: Vec<&str> = acks
        .iter()
        .filter(|a| a.conversation_id == convo_id && a.message_id == message_id)
        .map(|a| a.acker_id.as_str())
        .collect();
    ackers.sort_unstable();
    assert_eq!(
        ackers,
        vec!["pax", "raya"],
        "both peers that replied should be reported as holding the message"
    );

    // Draining clears the reports, and neither peer acknowledges twice.
    assert!(harness.saro().take_acks().is_empty());
    harness
        .raya()
        .send_content(&convo_id, b"raya again")
        .expect("raya second reply");
    harness.process_until_label("saro gets the second reply", |h| {
        h.saro().check(&convo_id, b"raya again")
    });
    assert!(
        harness
            .saro()
            .take_acks()
            .iter()
            .all(|a| a.message_id != message_id),
        "a peer acknowledges one message only once"
    );
}
