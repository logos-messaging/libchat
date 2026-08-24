# tools

## `forks.py`

Partitions a GroupV2 run: how many branches it ended in, when each split off,
and which members are on it.

### Why

A GroupV2 group can divide into branches that never converge again, and from
inside any one member the split is invisible. Both halves keep a roster, both
keep an epoch number, and each simply stops being able to read what the other
sends. A member count does not catch it either: a fresh split leaves both
branches carrying the same members and differing only in their key material.

MLS names a value for exactly this comparison. The epoch authenticator is
derived from the key schedule and is meant to be compared out of band, so at one
epoch number, two members holding different authenticators have diverged and two
holding the same one have genuinely converged.

libchat writes that value once per epoch a member applies:

```
epoch reached convo=2a30d6a22f epoch=3 authenticator=3f2a8e11...
```

Given one such log per member, the partition is a group-by. That is all this
tool is, plus a rendering that keeps the answer readable as the group grows.

The distinction it exists to draw is between two failures that look identical in
a log:

| | epoch | authenticator | meaning |
|---|---|---|---|
| forked | same as the group's | different | applied a different commit, unrecoverable |
| stalled | lower than the group's | matches the branch that moved on | stopped applying, still on the same lineage |

Both produce an endless run of `app message ignored (wrong epoch/conversation)`,
so the drop count alone cannot tell you which one you are looking at, and the two
have different causes and different fixes.

### How

One log per member, either a directory each or the logs side by side:

```sh
forks.py path/to/run/
```

```
run/
  peer01/run.log      run/
  peer02/run.log  or    peer01.log
  peer03/run.log        peer02.log
```

`chat-cli --log-file <path>` writes one. The level has to reach `info` on the
`libchat` target for the `epoch reached` line, and `de_mls` at `debug` fills in
the commit rounds behind a split:

```sh
RUST_LOG='warn,libchat=info,de_mls=debug'
```

A single log holding several members, split on the `user_id` span field:

```sh
forks.py --shared trace.log
```

That is what makes the report work on libchat's own group tests, which drive N
clients in one process, so a change can be checked for convergence in seconds
before anyone stands up a farm of real peers:

```sh
LOG=info cargo test -p integration_tests_core --test test_group_v2_scale \
  -- --nocapture --test-threads=1 > trace.log
forks.py --shared trace.log
```

`--json OUT` writes the same report as data, for diffing two runs.

### Reading the report

**LINEAGE** is the tree of group states. Each row is one epoch and one
authenticator, with how many members held it; a row that branches is a split, and
runs of epochs where nothing divided are collapsed into one row. Parentage comes
from membership continuity, so the tree needs no knowledge of the protocol.

**LANES** is one row per member, epochs left to right, each cell lettered by the
branch that member was on. A split is the column where the letters stop agreeing.
`·` marks epochs before a member joined and `╴` marks epochs it never reached, so
a branch that stopped advancing reads as a lane that runs out.

**Per branch** then comes when it diverged, who is on it, what the rest of the
group held instead, and how many frames it has dropped since.

### Limits

A capture from a build without the `epoch reached` line is described rather than
partitioned, and the report says so instead of guessing.

Which commit candidate each member actually held when it chose is the one
question left open. de-mls computes a hash per candidate and logs none, so the
report can say a branch chose differently but not what it chose between.
