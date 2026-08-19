# GroupV2 scale repro (issue #199)

`test_group_v2_scale.rs` reproduces the GroupV2 fork: one creator adds members in batches of
`BATCH` over the loss-free in-process broadcaster, and after every batch every joined member must
agree on the roster **and** on the `epoch_authenticator`. Member counts alone are not checked
against each other for a reason: two forked branches can hold the same count while sharing no key
material, so only the authenticator names a fresh fork.

## Run it

```sh
# whole suite (needs protoc, same as CI: apt-get install protobuf-compiler)
cargo test -p integration_tests_core --test test_group_v2_scale

# one size, with the per-batch trace
cargo test -p integration_tests_core --test test_group_v2_scale groupv2_scale_16 -- --nocapture
```

The clock is virtual: runs take seconds of wall time regardless of the timer profile.

## What to expect with the defaults

| test | result |
|---|---|
| `groupv2_scale_06`, `_11` | pass (every batch lands before a voted steward election is needed) |
| `groupv2_scale_16` .. `_46` | **fail**: the group forks on the first commit after the first voted steward election; the larger sizes additionally trip the `max_consensus_sessions = 10` trim (`SessionNotFound` mid-batch) |

The CI run on PR #216 shows exactly this: 2 passed, 5 failed in ~20 s. On a failure the test
prints each client's `debug_state` (epoch, phase, steward view) and keeps driving the group four
more settle windows to show it never reconverges.

## Knobs (env vars, all optional)

| var | default | meaning |
|---|---|---|
| `BATCH` | 5 | members added per operation; `BATCH=1` moves the first failure down to a group of 6 |
| `SN_MAX` | 2 (library default) | steward-list cap; `SN_MAX=64` makes every size pass, which is the mitigation |
| `SESSIONS` | 10 (library default) | de-mls `max_consensus_sessions`; raising it alone does not fix the fork |
| `TIMERS` | fast test profile | `TIMERS=prod` runs the production 60 s / 30 s timers; the fork reproduces there too |
| `PACE` | 0 (wait for convergence) | virtual seconds between adds, modelling a user who clicks without waiting |
| `BUDGET` | 30 | virtual seconds each batch gets to converge before being called diverged |
| `STEP` | 50 | virtual-clock granularity in milliseconds |
| `CONTINUE` | 0 | `1` keeps growing an already-split group to watch the damage accumulate instead of panicking |
| `LOG` | warn | `info` or `debug` for the tracing feed |

## Useful runs

```sh
# verify the mitigation: everything green
SN_MAX=64 cargo test -p integration_tests_core --test test_group_v2_scale

# the fork under production timers
TIMERS=prod cargo test -p integration_tests_core --test test_group_v2_scale groupv2_scale_16 -- --nocapture

# watch a split group decay into the Reelection stall
LOG=info CONTINUE=1 cargo test -p integration_tests_core --test test_group_v2_scale groupv2_scale_36 -- --nocapture
```

Analysis of the mechanism lives in issue #199 and draft PR #216.
