//! Repro for libchat#199: "GroupChats limited to 20 participants".
//!
//! One creator adds members in batches of 5 over the loss-free in-process
//! broadcaster, and after every batch every joined member must agree on the
//! roster. Parameterised by group size so the breaking point is visible.

use integration_tests_core::{TestHarness, fast_group_v2_config};
use shared_traits::IdentId;
use std::time::Duration;

/// Knobs, so one binary can bisect the failure: `BATCH` members per add,
/// `SESSIONS` = de-mls `max_consensus_sessions`, `SN_MAX` = steward-list cap.
fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
/// Virtual time each batch gets to converge before it is called diverged, and
/// the virtual-clock granularity. Both scale with `TIMERS=prod`.
fn settle_budget() -> Duration {
    Duration::from_secs(env_usize("BUDGET", 30) as u64)
}

fn step() -> Duration {
    Duration::from_millis(env_usize("STEP", 50) as u64)
}

/// Roster size each client reports, `None` when it has not joined the group.
fn roster_sizes<const N: usize>(h: &mut TestHarness<N>, convo: &str) -> Vec<Option<usize>> {
    (0..N)
        .map(|i| h.client_mut(i).group_members(convo).ok().map(|m| m.len()))
        .collect()
}

/// `epoch/authenticator` each client reports, `None` when it has not joined.
fn epoch_ids<const N: usize>(h: &mut TestHarness<N>, convo: &str) -> Vec<Option<String>> {
    (0..N)
        .map(|i| h.client_mut(i).group_epoch_id(convo))
        .collect()
}

/// Converged means the expected number of clients agree on the roster size AND
/// on the epoch authenticator. Roster size alone is not enough: two forked
/// branches can hold the same number of members while sharing no key material.
fn converged<const N: usize>(h: &mut TestHarness<N>, convo: &str, expect: usize) -> bool {
    let joined: Vec<usize> = roster_sizes(h, convo)
        .iter()
        .enumerate()
        .filter(|(_, s)| **s == Some(expect))
        .map(|(i, _)| i)
        .collect();
    if joined.len() != expect {
        return false;
    }
    let ids = epoch_ids(h, convo);
    let first = ids[joined[0]].clone();
    joined.iter().all(|i| ids[*i] == first)
}

fn settle<const N: usize>(h: &mut TestHarness<N>, convo: &str, expect: usize) -> bool {
    let (budget, step) = (settle_budget(), step());
    let mut elapsed = Duration::ZERO;
    while elapsed < budget {
        if converged(h, convo, expect) {
            return true;
        }
        h.process(step);
        elapsed += step;
    }
    converged(h, convo, expect)
}

fn report<const N: usize>(h: &mut TestHarness<N>, convo: &str, expect: usize) -> String {
    let sizes = roster_sizes(h, convo);
    let pending = h
        .client_mut(0)
        .group_pending_members(convo)
        .map(|p| p.len())
        .unwrap_or(usize::MAX);
    let mut hist: std::collections::BTreeMap<String, usize> = Default::default();
    for s in &sizes {
        *hist
            .entry(s.map_or("no-convo".to_string(), |n| n.to_string()))
            .or_default() += 1;
    }
    let mut branches: std::collections::BTreeMap<String, usize> = Default::default();
    for id in epoch_ids(h, convo).into_iter().flatten() {
        *branches.entry(id).or_default() += 1;
    }
    let errs: usize = (0..N).map(|i| h.client_mut(i).inbound_errors().len()).sum();
    let first_err = (0..N)
        .find_map(|i| h.client_mut(i).inbound_errors().first().cloned())
        .unwrap_or_default();
    format!(
        "expect {expect}: histogram(size -> clients) {hist:?} branches(epoch/auth -> clients) {branches:?} creator_pending {pending} inbound_errors {errs} first {first_err} rosters {sizes:?}"
    )
}

/// The adder's branch versus everyone else, in consensus terms: de-mls counts
/// every MLS member of the *local* roster as an expected voter and needs
/// ceil(2/3) of them, so members stranded on an older epoch still inflate the
/// bar they can no longer help clear.
fn quorum_line<const N: usize>(h: &mut TestHarness<N>, convo: &str) -> String {
    let sizes = roster_sizes(h, convo);
    let leader = sizes[0];
    let expected = leader.unwrap_or(0);
    let with_leader = sizes.iter().filter(|s| **s == leader).count();
    let required = (2 * expected).div_ceil(3);
    format!(
        "leader_roster={expected} agreeing={with_leader} required_votes={required}          quorum_on_real_votes={}",
        with_leader >= required
    )
}

/// Conversation phase of every joined client, and the adder's own phase.
/// `add_member` is refused outright while a conversation sits in Freezing or
/// Selection, and in Reelection it accepts nothing but elections and
/// emergencies, so a stuck adder is what "cannot add members any more" looks
/// like from the outside.
fn phase_line<const N: usize>(h: &mut TestHarness<N>, convo: &str) -> String {
    let mut census: std::collections::BTreeMap<String, usize> = Default::default();
    for i in 0..N {
        if let Some(state) = h.client_mut(i).group_debug_state(convo) {
            let phase = state
                .split("state=")
                .nth(1)
                .and_then(|t| t.split_whitespace().next())
                .unwrap_or("?")
                .to_string();
            *census.entry(phase).or_default() += 1;
        }
    }
    let adder = h
        .client_mut(0)
        .group_debug_state(convo)
        .and_then(|s| {
            s.split("state=")
                .nth(1)
                .map(|t| t.split_whitespace().next().unwrap_or("?").to_string())
        })
        .unwrap_or_else(|| "none".into());
    format!("census {census:?} adder={adder}")
}

fn run<const N: usize>() {
    let level = match std::env::var("LOG").as_deref() {
        Ok("debug") => tracing::Level::DEBUG,
        Ok("info") => tracing::Level::INFO,
        _ => tracing::Level::WARN,
    };
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_test_writer()
        .try_init();

    let batch = env_usize("BATCH", 5);
    // `TIMERS=prod` runs the de-mls library defaults (60s commit inactivity,
    // 30s consensus timeout) that ship in production, instead of the
    // millisecond test profile.
    let mut config = match std::env::var("TIMERS").as_deref() {
        Ok("prod") => libchat::GroupV2Config::default(),
        _ => fast_group_v2_config(),
    };
    config.max_consensus_sessions = env_usize("SESSIONS", config.max_consensus_sessions);
    config.steward_list.sn_max = env_usize("SN_MAX", config.steward_list.sn_max);
    println!(
        "[N={N}] batch={batch} max_consensus_sessions={} sn_max={}",
        config.max_consensus_sessions, config.steward_list.sn_max
    );

    let mut harness = TestHarness::<N>::new_with_config(config, |_, _| {});
    let convo_id = harness
        .client_mut(0)
        .create_group_convo_v2(&[], "scale", "")
        .expect("create group");

    let mut joined = 1;
    while joined < N {
        let upto = (joined + batch).min(N);
        let addrs: Vec<IdentId> = (joined..upto)
            .map(|i| harness.client_mut(i).addr())
            .collect();
        let refs: Vec<&IdentId> = addrs.iter().collect();

        let started = std::time::Instant::now();
        let mut add = harness.client_mut(0).group_add_member(&convo_id, &refs);
        if let Err(e) = &add {
            println!("[N={N}] ADD REFUSED at {joined}..{upto}: {e:?}");
            // Can the user ever add again? Retry the same batch with a full
            // settle window between attempts.
            for attempt in 1..=5 {
                settle(&mut harness, &convo_id, upto);
                add = harness.client_mut(0).group_add_member(&convo_id, &refs);
                println!(
                    "[N={N}] retry {attempt} at {joined}..{upto}: {:?} :: {}",
                    add.as_ref().err(),
                    phase_line(&mut harness, &convo_id)
                );
                if add.is_ok() {
                    break;
                }
            }
        }

        // PACE models a person clicking "add" every PACE virtual seconds without
        // waiting for the group to settle; unset means wait for convergence.
        let ok = match env_usize("PACE", 0) {
            0 => settle(&mut harness, &convo_id, upto),
            secs => {
                let step = step();
                let mut elapsed = Duration::ZERO;
                while elapsed < Duration::from_secs(secs as u64) {
                    harness.process(step);
                    elapsed += step;
                }
                converged(&mut harness, &convo_id, upto)
            }
        };
        println!(
            "[N={N}] batch {joined}..{upto} add={:?} converged={ok} in {:?} wall :: {}",
            add.err(),
            started.elapsed(),
            report(&mut harness, &convo_id, upto)
        );
        if !ok {
            for i in 0..N {
                if let Some(state) = harness.client_mut(i).group_debug_state(&convo_id) {
                    println!("[N={N}] client {i:>2}: {state}");
                }
            }
            // Keep driving the group: the question is whether it ever
            // reconverges, not just whether this batch was slow.
            for _ in 0..4 {
                let recovered = settle(&mut harness, &convo_id, upto);
                println!(
                    "[N={N}] extra settle recovered={recovered} :: {}",
                    report(&mut harness, &convo_id, upto)
                );
                if recovered {
                    break;
                }
            }
            // CONTINUE=1 keeps growing a group that has already split, to see
            // how the damage accumulates batch after batch.
            if env_usize("CONTINUE", 0) == 0 {
                panic!(
                    "[N={N}] group diverged after growing to {upto} members :: {}",
                    report(&mut harness, &convo_id, upto)
                );
            }
            println!("[N={N}] quorum {}", quorum_line(&mut harness, &convo_id));
            println!("[N={N}] phases {}", phase_line(&mut harness, &convo_id));
        }
        joined = upto;
    }

    for i in 0..N {
        if let Some(state) = harness.client_mut(i).group_debug_state(&convo_id) {
            println!("[N={N}] final client {i:>2}: {state}");
        }
    }
}

#[test]
fn groupv2_scale_06() {
    run::<6>();
}

#[test]
fn groupv2_scale_11() {
    run::<11>();
}

#[test]
fn groupv2_scale_16() {
    run::<16>();
}

#[test]
fn groupv2_scale_21() {
    run::<21>();
}

#[test]
fn groupv2_scale_26() {
    run::<26>();
}

#[test]
fn groupv2_scale_36() {
    run::<36>();
}

#[test]
fn groupv2_scale_46() {
    run::<46>();
}
