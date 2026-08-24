# GroupV2 scale tests

`test_group_v2_scale.rs` grows a GroupV2 group over the loss-free in-process broadcaster and, after
every add, requires that every joined member reports the same roster **and** can read what the
others post. The exchange is the check that catches a fork: on the de-mls commit before the fix
(see below), the one-at-a-time test reaches six members that all report the same six-member roster
while one of them can no longer decrypt what the others send, so a roster comparison alone would
have called that group converged. Covers libchat#199.

| test | group | adds |
|---|---|---|
| `groupv2_grows_one_member_at_a_time` | 12 members | one per add |
| `groupv2_grows_in_batches` | 26 members | five per add |
| `groupv2_survives_a_lost_commit_candidate` | 5 members | one per add, one commit candidate lost on the last |

The clock is virtual, and the three together take well under a minute.

## Run them

```sh
# all three (needs protoc, as the rest of the workspace does: apt-get install protobuf-compiler)
cargo test -p integration_tests_core --test test_group_v2_scale

# one of them, with the tracing feed on
LOG=info cargo test -p integration_tests_core --test test_group_v2_scale groupv2_grows_in_batches -- --nocapture
```

## Reading a failure

```
the group of 6 is no longer one group: members [4] never read the post from member 0 ::
rosters(size -> clients) {6: 6} not_joined 6 distinct_rosters 1 creator_pending 0
rejected_payloads 16 first member 4: DeMlsError(Mls(ProcessMessage(ValidationError(UnableToDecrypt(AeadError)))))
```

- `rosters` maps a member count to the number of clients reporting it, and `not_joined` counts the
  clients the test has not added yet. `distinct_rosters` counts how many different rosters those
  clients hold, so `1` means they all agree on the membership and the split is in the key material
  alone.
- `creator_pending` is the invites the creator still has awaiting a commit.
- `rejected_payloads` counts what the clients refused to process, and `first` quotes the earliest
  one held by the lowest-numbered client. `UnableToDecrypt` is the signature of a fork: the payload
  is well formed, it just belongs to another branch of the group.

## The lost-candidate test is red on purpose

`groupv2_survives_a_lost_commit_candidate` grows a group of four and loses one commit candidate on
its way to one member, in the round that adds the fifth.

Both stewards mint a commit over the same batch and broadcast it, and every member applies the best
of the candidates it holds once its freeze window closes, with no retry and no minimum. Two commits
over the same batch are not interchangeable, since each carries its committer's key material, so
the member that receives one of the two applies a different commit and its MLS state diverges from
the group's. Nothing brings it back: no layer retransmits the frame, the delivery node keeps no
history to replay, and a `ConversationSync` carries the steward list rather than MLS state.

The frame is singled out by `TestClient::set_inbound_filter`, which discards it unread, and it is
recognised the way its receiver recognises it: a GroupV2 frame wrapping a plaintext de-mls
`AppMessage` that carries a `CommitCandidate`. Each member takes its turn short a candidate, since
a steward is left holding the one it minted itself and commits a round nobody else has, where a
plain member holds the one that reached it.

```
member 0: the group of 5 is no longer one group: members [1, 2, 3, 4] never read the post from member 0 ::
rosters(size -> clients) {5: 5} not_joined 0 distinct_rosters 1 creator_pending 0
rejected_payloads 74 first member 0: DeMlsError(Mls(ProcessMessage(ValidationError(UnableToDecrypt(AeadError)))))
```

Every client reports the same five members, and the one that lost a candidate is alone on its own
branch of the group.

## Watching the bug the growth tests cover

Point de-mls at the commit before the fix in the workspace `Cargo.toml`:

```toml
de-mls = { git = "https://github.com/vacp2p/de-mls", rev = "5cfce1b97305363466c0e68668fcd85cad4b8996" }
```

Both tests then fail within seconds, on the first add that follows a voted steward election: at six
members when they are added one at a time, at sixteen when they are added five at a time.

## Local overrides

Timing comes from constants at the top of the file; group size is the const generic on `run` and
batch size its argument. Two environment variables cover what a local run usually needs to change:

| var | default | meaning |
|---|---|---|
| `BUDGET` | 30 | virtual seconds a settle gets before the group is called split |
| `LOG` | off | `warn`, `info` or `debug` turns the tracing feed on |
