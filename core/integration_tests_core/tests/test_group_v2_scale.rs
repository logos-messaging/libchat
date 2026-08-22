//! GroupV2 group growth (regression for libchat#199).
//!
//! One creator grows a group over the loss-free in-process broadcaster, and
//! after every add the group has to converge twice over: every joined member
//! reports the same roster, and every joined member can still read what the
//! others post. The second check is the one that catches a fork, because two
//! branches of a split group can carry the same members while sharing no key
//! material.
//!
//! The last test grows the same group with one commit candidate lost in
//! flight, which is what the broadcaster's loss-free delivery otherwise hides.

use chat_proto::logoschat::encryption::{EncryptedPayload, encrypted_payload};
use chat_proto::logoschat::envelope::EnvelopeV1;
use de_mls::protos::de_mls::messages::v1::{AppMessage, app_message};
use integration_tests_core::TestHarness;
use libchat::{GroupV2Frame, GroupV2Payload};
use prost::Message;
use shared_traits::IdentId;
use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

/// Granularity the virtual clock advances in, and the steps between two checks
/// of a settle condition. Checking queries every client, which costs far more
/// than a step does.
const STEP: Duration = Duration::from_millis(50);
const STEPS_PER_CHECK: usize = 10;

/// Virtual seconds a settle gets before the group is called split. `BUDGET`
/// raises it for a local run, and `LOG=warn|info|debug` turns on the tracing
/// feed, which is off by default because the harness traces every payload.
fn settle_budget() -> Duration {
    let seconds = std::env::var("BUDGET")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    Duration::from_secs(seconds)
}

fn init_tracing() {
    let level = match std::env::var("LOG").as_deref() {
        Ok("debug") => tracing::Level::DEBUG,
        Ok("info") => tracing::Level::INFO,
        Ok("warn") => tracing::Level::WARN,
        _ => tracing::Level::ERROR,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_test_writer()
        .try_init();
}

/// The members each client reports, sorted, `None` while it has not joined.
fn rosters<const N: usize>(h: &mut TestHarness<N>, convo: &str) -> Vec<Option<Vec<Vec<u8>>>> {
    (0..N)
        .map(|i| {
            h.client_mut(i).group_members(convo).ok().map(|mut m| {
                m.sort();
                m
            })
        })
        .collect()
}

/// Every member added so far reports the same roster, and it holds all of them.
fn rosters_agree<const N: usize>(h: &mut TestHarness<N>, convo: &str, joined: usize) -> bool {
    let rosters = rosters(h, convo);
    let Some(creator) = rosters[0].as_ref() else {
        return false;
    };
    creator.len() == joined
        && rosters[..joined]
            .iter()
            .all(|r| r.as_ref() == Some(creator))
}

/// Advances the virtual clock until `ready` holds or the budget runs out.
/// [`TestHarness::process_until`] panics instead of reporting, and a settle
/// that runs out here has to come back with the group's state attached.
fn settle<const N: usize>(
    h: &mut TestHarness<N>,
    ready: impl Fn(&mut TestHarness<N>) -> bool,
) -> bool {
    let mut elapsed = Duration::ZERO;
    let budget = settle_budget();
    while elapsed < budget {
        if ready(h) {
            return true;
        }
        for _ in 0..STEPS_PER_CHECK {
            h.process(STEP);
            elapsed += STEP;
        }
    }
    // A step drains payloads before it advances the clock, so whatever the
    // last wakeups produced is still in flight; one more drain gives the
    // verdict everything the run has already generated.
    h.process(Duration::ZERO);
    ready(h)
}

/// Adds members, retrying while an election in flight has the conversation
/// blocked, and reporting the last refusal when the budget runs out.
fn add_members<const N: usize>(
    h: &mut TestHarness<N>,
    convo: &str,
    invited: &[&IdentId],
) -> Result<(), String> {
    let mut elapsed = Duration::ZERO;
    let budget = settle_budget();
    let mut refusal = String::new();
    while elapsed < budget {
        match h.client_mut(0).group_add_member(convo, invited) {
            Ok(()) => return Ok(()),
            Err(e) => refusal = format!("{e:?}"),
        }
        for _ in 0..STEPS_PER_CHECK {
            h.process(STEP);
            elapsed += STEP;
        }
    }
    Err(refusal)
}

/// Joined members that have not read `content`, its sender aside.
fn unread<const N: usize>(
    h: &mut TestHarness<N>,
    convo: &str,
    sender: usize,
    joined: usize,
    content: &[u8],
) -> Vec<usize> {
    (0..joined)
        .filter(|i| *i != sender && !h.client(*i).check(convo, content))
        .collect()
}

/// Checks a post goes unread before it is posted again: an epoch that turns
/// between a post and its delivery leaves it undecryptable for members that
/// merged the commit, and only a fresh post reaches them.
const CHECKS_PER_POST: usize = 4;

/// Posts a message and waits for every other joined member to read it. A
/// member stranded on a forked branch cannot read it whatever its roster says,
/// and a member whose conversation is frozen for an election cannot post at
/// all, so posting is retried for as long as the settle budget lasts.
fn exchange<const N: usize>(
    h: &mut TestHarness<N>,
    convo: &str,
    sender: usize,
    joined: usize,
    content: &[u8],
) -> Result<(), String> {
    let mut elapsed = Duration::ZERO;
    let budget = settle_budget();
    let mut posts = 0;
    let mut checks_since_post = 0;
    let mut refusal = String::new();
    while elapsed < budget {
        if posts > 0 {
            if unread(h, convo, sender, joined, content).is_empty() {
                return Ok(());
            }
            checks_since_post += 1;
        }
        if posts == 0 || checks_since_post >= CHECKS_PER_POST {
            match h.client_mut(sender).send_content(convo, content) {
                Ok(_) => {
                    posts += 1;
                    checks_since_post = 0;
                }
                Err(e) => refusal = format!("{e:?}"),
            }
        }
        for _ in 0..STEPS_PER_CHECK {
            h.process(STEP);
            elapsed += STEP;
        }
    }
    h.process(Duration::ZERO);
    if posts == 0 {
        return Err(format!("member {sender} could not post: {refusal}"));
    }
    match unread(h, convo, sender, joined, content) {
        missing if missing.is_empty() => Ok(()),
        missing => Err(format!(
            "members {missing:?} never read the post from member {sender}"
        )),
    }
}

/// One line of failure diagnostics: how the group split, and whether anyone
/// rejected an inbound payload on the way.
fn report<const N: usize>(h: &mut TestHarness<N>, convo: &str) -> String {
    let rosters = rosters(h, convo);
    let mut sizes: BTreeMap<usize, usize> = BTreeMap::new();
    let mut not_joined = 0;
    for roster in &rosters {
        match roster {
            Some(members) => *sizes.entry(members.len()).or_default() += 1,
            None => not_joined += 1,
        }
    }
    let distinct: BTreeSet<_> = rosters.into_iter().flatten().collect();
    let pending = h
        .client_mut(0)
        .group_pending_members(convo)
        .map_or("?".to_string(), |p| p.len().to_string());
    let rejections: usize = (0..N).map(|i| h.client(i).inbound_errors().len()).sum();
    let first = (0..N)
        .find_map(|i| {
            h.client(i)
                .inbound_errors()
                .first()
                .map(|e| format!("member {i}: {e}"))
        })
        .unwrap_or_else(|| "none".to_string());
    format!(
        "rosters(size -> clients) {sizes:?} not_joined {not_joined} distinct_rosters {} creator_pending {pending} rejected_payloads {rejections} first {first}",
        distinct.len()
    )
}

fn run<const N: usize>(batch: usize) {
    init_tracing();

    let mut harness = TestHarness::<N>::new(|_, _| {});
    // A member on the far side of a fork rejects everything this side posts.
    // Recording those instead of stopping at the first one lets the run reach
    // the exchange check, which names the members that could not read.
    harness.tolerate_inbound_errors();

    let convo = harness
        .client_mut(0)
        .create_group_convo_v2(&[], "scale", "")
        .expect("create group");

    let mut joined = 1;
    while joined < N {
        let upto = (joined + batch).min(N);
        let addresses: Vec<IdentId> = (joined..upto)
            .map(|i| harness.client_mut(i).addr())
            .collect();
        let invited: Vec<&IdentId> = addresses.iter().collect();
        if let Err(refusal) = add_members(&mut harness, &convo, &invited) {
            panic!(
                "adding members {joined}..{upto} kept being refused: {refusal} :: {}",
                report(&mut harness, &convo)
            );
        }

        assert!(
            settle(&mut harness, |h| rosters_agree(h, &convo, upto)),
            "the group did not converge on {upto} members :: {}",
            report(&mut harness, &convo)
        );

        for sender in [0, upto - 1] {
            let content = format!("post from member {sender} at {upto} members");
            if let Err(split) = exchange(&mut harness, &convo, sender, upto, content.as_bytes()) {
                panic!(
                    "the group of {upto} is no longer one group: {split} :: {}",
                    report(&mut harness, &convo)
                );
            }
        }

        joined = upto;
    }

    // The clients tolerate a rejected payload so that a fork is reported by
    // the exchange rather than by the first undecryptable frame. A group that
    // converged all the way should have handed every client everything it was
    // sent.
    let mut rejected = Vec::new();
    for i in 0..N {
        for error in harness.client(i).inbound_errors() {
            rejected.push(format!("member {i}: {error}"));
        }
    }
    assert!(
        rejected.is_empty(),
        "the group converged but clients rejected payloads on the way: {rejected:?}"
    );
}

/// The flow a person follows: invite, let the group settle, invite the next.
#[test]
fn groupv2_grows_one_member_at_a_time() {
    run::<12>(1);
}

/// Growth past the twenty members the issue reports as the ceiling.
#[test]
fn groupv2_grows_in_batches() {
    run::<26>(5);
}

/// Members the group has before the last add. It elects two stewards
/// (`sn_max` is 2), so the round that follows has two commit candidates in
/// flight: a plain member sees both on the wire, and a steward, minting its
/// own, sees one.
const GROUP: usize = 4;

/// Grows a group of [`GROUP`] members and loses one commit candidate on its way
/// to `receiver`, in the round that adds the last member.
///
/// Every steward mints a commit over the same batch and broadcasts it, and
/// every member applies the best of the candidates it holds once its freeze
/// window closes. Two commits over the same batch are not interchangeable,
/// since each carries its committer's key material, so a member that selects
/// from a strict subset applies a different commit and its MLS state diverges
/// from the group's. Nothing brings it back: no layer retransmits the frame,
/// the delivery node keeps no history to replay, and a `ConversationSync`
/// carries the steward list rather than MLS state.
fn lose_a_commit_candidate(receiver: usize) {
    init_tracing();
    const N: usize = GROUP + 1;

    let mut harness = TestHarness::<N>::new(|_, _| {});
    harness.tolerate_inbound_errors();

    let convo = harness
        .client_mut(0)
        .create_group_convo_v2(&[], "lost-candidate", "")
        .expect("create group");

    for joined in 1..GROUP {
        let next = harness.client_mut(joined).addr();
        if let Err(refusal) = add_members(&mut harness, &convo, &[&next]) {
            panic!("adding member {joined} kept being refused: {refusal}");
        }
        assert!(
            settle(&mut harness, |h| rosters_agree(h, &convo, joined + 1)),
            "the group did not converge on {} members :: {}",
            joined + 1,
            report(&mut harness, &convo)
        );
    }

    harness
        .client_mut(receiver)
        .set_inbound_filter(drop_first_commit_candidate());

    let last = harness.client_mut(N - 1).addr();
    if let Err(refusal) = add_members(&mut harness, &convo, &[&last]) {
        panic!("member {receiver}: adding the last member kept being refused: {refusal}");
    }

    assert!(
        settle(&mut harness, |h| rosters_agree(h, &convo, N)),
        "member {receiver}: the group did not converge on {N} members :: {}",
        report(&mut harness, &convo)
    );

    // Guards the setup rather than the behaviour: a round that delivered every
    // candidate would let the run pass for the wrong reason.
    assert_eq!(
        harness.client(receiver).dropped(),
        1,
        "member {receiver} lost no commit candidate"
    );

    for sender in [0, receiver, N - 1] {
        let content = format!("post from member {sender}, member {receiver} short a candidate");
        if let Err(split) = exchange(&mut harness, &convo, sender, N, content.as_bytes()) {
            panic!(
                "member {receiver}: the group of {N} is no longer one group: {split} :: {}",
                report(&mut harness, &convo)
            );
        }
    }
}

/// Drops the first commit candidate the client it filters would receive, and
/// passes every other frame.
fn drop_first_commit_candidate() -> impl FnMut(&[u8]) -> bool {
    let mut lost = false;
    move |payload| {
        if lost || !is_commit_candidate(payload) {
            return true;
        }
        lost = true;
        false
    }
}

/// Whether a frame carries a commit candidate, read the way its receiver reads
/// it: a GroupV2 frame wrapping a plaintext de-mls `AppMessage`.
fn is_commit_candidate(payload: &[u8]) -> bool {
    let Ok(envelope) = EnvelopeV1::decode(payload) else {
        return false;
    };
    let Ok(encrypted) = EncryptedPayload::decode(envelope.payload.as_ref()) else {
        return false;
    };
    let Some(encrypted_payload::Encryption::Plaintext(plaintext)) = encrypted.encryption else {
        return false;
    };
    let Ok(frame) = GroupV2Frame::decode(plaintext.payload.as_ref()) else {
        return false;
    };
    let Some(GroupV2Payload::DeMlsWrapper(inner)) = frame.payload else {
        return false;
    };
    match AppMessage::decode(inner.as_ref()) {
        Ok(message) => matches!(
            message.payload,
            Some(app_message::Payload::CommitCandidate(_))
        ),
        Err(_) => false,
    }
}

/// Every member in turn, because a steward that loses the other steward's
/// candidate holds one it minted itself and commits a round nobody else has,
/// where a plain member holds the one candidate that reached it.
#[test]
fn groupv2_survives_a_lost_commit_candidate() {
    for receiver in 0..GROUP {
        lose_a_commit_candidate(receiver);
    }
}
