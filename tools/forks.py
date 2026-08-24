#!/usr/bin/env python3
"""Partition a GroupV2 run: how many branches it ended in, when each split off,
and which members are on it.

The load-bearing line is `epoch reached`, which libchat writes once per epoch a
member applies, carrying that member's MLS epoch authenticator. Two members at
the same epoch holding different authenticators have forked; a member at a lower
epoch has only fallen behind. Nothing else separates those two, because both drop
everything the group sends as undecryptable.

Input is either one log per member, or a single log holding several members that
is split on the `user_id` span field. A capture from a build without the
`epoch reached` line is described rather than partitioned, and the report says so
instead of guessing.

Usage:
    forks.py RUNDIR [--json OUT]
    forks.py --shared LOG [--json OUT]
"""

import argparse
import collections
import os
import re
import sys

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# `2026-08-21T20:57:08.112841Z  INFO span{..}: target: message field=value ...`
LINE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT[\d:.]+Z)\s+(?P<level>\w+)\s+(?P<rest>.*)$")

EPOCH_REACHED = re.compile(r"epoch reached .*?\bepoch=(\d+).*?\bauthenticator=([0-9a-f]+)")
JOINED = re.compile(r"joined conversation")
MINTED = re.compile(r"commit candidate created .*?\bepoch=(\d+)\s+proposals=(\d+)(?:\s+hash=([0-9a-f]+))?")
# Every way de-mls names a candidate that arrived. Two ingest paths reach
# `receive_commit_candidate`, one straight from the plaintext envelope and one
# from the steward branch, and only the second announces itself, so matching a
# single message undercounts, on the member that creates the group to zero.
CANDIDATE = re.compile(
    r"candidate (received from peer steward|stashed|ignored)[^\s]*"
    r"(?:.*?\bepoch=(\d+))?(?:.*?\bhash=([0-9a-f]+))?"
)
PHASE = re.compile(r'state transition(?: \(recovery retry\))? .*?\bstate="(\w+)"')
DROPPED = re.compile(r"app message ignored \(wrong epoch/conversation\)")
# `user_id=<label>` inside a span, the only per-member key when several members
# share one process. The label is a truncated hex id in a deployed build and a
# plain name in the integration tests, so match neither shape.
USER_ID = re.compile(r"user_id=([^}\s]+)")


class Node:
    def __init__(self, name):
        self.name = name
        self.epochs = {}          # epoch -> (ts, authenticator)
        self.joined_at = None
        self.minted = []          # (ts, epoch, proposals, hash|None)
        self.received = []        # (ts, kind, epoch|None, hash|None)
        self.phases = []          # (ts, phase)
        self.drops = 0
        self.first_ts = None
        self.last_ts = None

    @property
    def last_epoch(self):
        return max(self.epochs) if self.epochs else None

    def auth_at(self, epoch):
        entry = self.epochs.get(epoch)
        return entry[1] if entry else None


def consume(ts, rest, node):
    node.first_ts = node.first_ts or ts
    node.last_ts = ts

    hit = EPOCH_REACHED.search(rest)
    if hit:
        # Keep the first sighting: a conversation rebuilt from storage
        # re-announces an epoch it already reached, and the earlier stamp is
        # when it actually got there.
        node.epochs.setdefault(int(hit.group(1)), (ts, hit.group(2)))
        return
    hit = MINTED.search(rest)
    if hit:
        node.minted.append((ts, int(hit.group(1)), int(hit.group(2)), hit.group(3)))
        return
    hit = CANDIDATE.search(rest)
    if hit:
        epoch = int(hit.group(2)) if hit.group(2) else None
        node.received.append((ts, hit.group(1), epoch, hit.group(3)))
        return
    hit = PHASE.search(rest)
    if hit:
        node.phases.append((ts, hit.group(1)))
        return
    if DROPPED.search(rest):
        node.drops += 1
        return
    if JOINED.search(rest) and node.joined_at is None:
        node.joined_at = ts


def parse_log(path, node):
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            m = LINE.match(ANSI.sub("", raw).rstrip("\n"))
            if m:
                consume(m.group("ts"), m.group("rest"), node)


def member_logs(rundir):
    """(member name, log path) for both layouts a run tends to leave behind:
    a directory per member holding its log, or the logs side by side."""
    found = []
    for entry in sorted(os.listdir(rundir)):
        path = os.path.join(rundir, entry)
        if os.path.isdir(path):
            logs = sorted(f for f in os.listdir(path) if f.endswith(".log"))
            if logs:
                found.append((entry, os.path.join(path, logs[0])))
        elif entry.endswith(".log"):
            found.append((entry[: -len(".log")], path))
    return found


def load_run(rundir):
    nodes = {}
    for name, path in member_logs(rundir):
        node = Node(name)
        parse_log(path, node)
        nodes[name] = node
    return nodes


def load_shared(path):
    """One log holding every member, split on the `user_id` span field.

    libchat's own group tests drive N clients inside one process against a
    loss-free broadcaster, so the same report can say whether a change converges
    in seconds, before anyone spends an hour on a farm of real peers.
    """
    buckets = collections.defaultdict(list)
    orphans = 0
    with open(path, "r", errors="replace") as fh:
        for raw in fh:
            line = ANSI.sub("", raw)
            hit = USER_ID.search(line)
            if hit:
                buckets[hit.group(1)].append(line)
            elif EPOCH_REACHED.search(line):
                # An entry point outside any instrumented span, so the line
                # names no member and cannot be placed on a lane.
                orphans += 1
    if orphans:
        print(f"  {orphans} epoch line(s) carried no user_id and were dropped",
              file=sys.stderr)
    nodes = {}
    for uid, lines in sorted(buckets.items()):
        node = Node(uid)
        for line in lines:
            m = LINE.match(line.rstrip("\n"))
            if m:
                consume(m.group("ts"), m.group("rest"), node)
        nodes[node.name] = node
    return nodes


def branches_by_epoch(nodes):
    """epoch -> {authenticator: [member names]}, in epoch order."""
    table = collections.defaultdict(lambda: collections.defaultdict(list))
    for name, node in nodes.items():
        for epoch, (_, auth) in node.epochs.items():
            table[epoch][auth].append(name)
    return {e: dict(table[e]) for e in sorted(table)}


def lineage(nodes, by_epoch):
    """Vertices are (epoch, authenticator); an edge means some member moved from
    the first to the second. Membership continuity is what makes the tree, so no
    knowledge of the protocol is needed to build it."""
    vertices, edges = {}, collections.defaultdict(set)
    for epoch, groups in by_epoch.items():
        for auth, members in groups.items():
            vertices[(epoch, auth)] = sorted(members)
    for node in nodes.values():
        seen = sorted(node.epochs)
        for prev, cur in zip(seen, seen[1:]):
            edges[(prev, node.auth_at(prev))].add((cur, node.auth_at(cur)))
    return vertices, edges


def classify(nodes, by_epoch):
    """Split the roster into current / forked / stalled / silent.

    A member is forked when a peer held a different authenticator at the same
    epoch. It is stalled when its last authenticator matches the branch that kept
    moving: the same state, just no further epochs.
    """
    verdicts = {}
    if not by_epoch:
        return verdicts
    top = max(by_epoch)
    survivors = set()
    for members in by_epoch[top].values():
        survivors.update(members)

    for name, node in nodes.items():
        last = node.last_epoch
        if last is None:
            verdicts[name] = ("silent", None, None)
            continue
        if name in survivors:
            verdicts[name] = ("current", last, node.auth_at(last))
            continue
        auth = node.auth_at(last)
        peers = by_epoch[last]
        forked = any(other != auth for other in peers)
        shared_with_movers = any(
            other == auth and any(m in survivors or nodes[m].last_epoch > last for m in members)
            for other, members in peers.items()
        )
        verdicts[name] = (
            ("forked" if forked and not shared_with_movers else "stalled"), last, auth
        )
    return verdicts


def tree_lines(vertices, edges, nodes):
    """The lineage as a tree, collapsing runs of epochs where nothing split.

    A group that advances ten epochs without dividing is one line, not ten; the
    rows worth printing are where the group began, where it divided, and where
    each branch came to rest.
    """
    parents = {d for dsts in edges.values() for d in dsts}
    roots = sorted(v for v in vertices if v not in parents)
    out = []

    def label(chain):
        first_epoch, _ = chain[0]
        epoch, auth = chain[-1]
        members = vertices[chain[-1]]
        when = min(nodes[m].epochs[epoch][0] for m in members)
        span = f"{first_epoch}" if len(chain) == 1 else f"{first_epoch}-{epoch}"
        return (f"epoch {span:<5} {short(auth)}  {plural(len(members), 'member'):>10}   "
                f"{clock(when)}")

    def walk(vertex, prefix, is_last, first):
        chain = [vertex]
        while len(edges.get(chain[-1], ())) == 1:
            nxt = next(iter(edges[chain[-1]]))
            if len(vertices[nxt]) != len(vertices[chain[-1]]):
                break
            chain.append(nxt)
        stem = "" if first else ("└── " if is_last else "├── ")
        out.append(prefix + stem + label(chain))
        inner = prefix + ("" if first else ("    " if is_last else "│   "))
        children = sorted(edges.get(chain[-1], ()))
        for i, child in enumerate(children):
            out.append(inner + "│")
            walk(child, inner, i == len(children) - 1, False)

    for root in roots:
        walk(root, "", True, True)
    return out


def plural(n, word):
    return f"{n} {word}" + ("" if n == 1 else "s")


def short(auth, n=8):
    return auth[:n] if auth else "?"


def clock(ts):
    return ts[11:19] if ts else "--:--:--"


def lane_letters(by_epoch):
    """A letter per lineage, not per epoch: a member keeps its letter until it
    diverges from the branch it was on, so a split reads as the column where the
    letters stop agreeing."""
    letters, nxt = {}, [0]

    def letter_for(epoch, auth):
        key = (epoch, auth)
        if key in letters:
            return letters[key]
        prev = [
            letters[(epoch - 1, a)]
            for a in by_epoch.get(epoch - 1, {})
            if (epoch - 1, a) in letters
            and set(by_epoch[epoch][auth]) & set(by_epoch[epoch - 1][a])
        ]
        biggest = max(len(v) for v in by_epoch[epoch].values())
        if prev and (len(by_epoch[epoch]) == 1 or len(by_epoch[epoch][auth]) == biggest):
            letters[key] = prev[0]
        else:
            letters[key] = chr(ord("A") + nxt[0])
            nxt[0] += 1
        return letters[key]

    for epoch in sorted(by_epoch):
        for auth in by_epoch[epoch]:
            letter_for(epoch, auth)
    return letter_for


def render_undetermined(nodes, p):
    p("No `epoch reached` lines. This build predates the fingerprint, so the run")
    p("can be described but not partitioned. What is here:")
    p()
    for name in sorted(nodes):
        n = nodes[name]
        seen = collections.Counter(k for _, k, _, _ in n.received)
        detail = ", ".join(f"{k.split()[0]} {v}" for k, v in sorted(seen.items())) or "none"
        p(f"  {name:<10} wrong-epoch drops {n.drops:>5}   minted {len(n.minted):>2}"
          f"   candidates seen {len(n.received):>2} ({detail})"
          f"   joined {clock(n.joined_at)}")
    p()
    p("A member whose drop count is an order of magnitude above the rest stopped")
    p("being able to read the group. That is a symptom of both a fork and a stall,")
    p("and only the authenticator tells them apart.")


def render(nodes, by_epoch, verdicts, out=sys.stdout):
    p = lambda s="": print(s, file=out)
    epochs = sorted(by_epoch)
    starts = [n.first_ts for n in nodes.values() if n.first_ts]
    ends = [n.last_ts for n in nodes.values() if n.last_ts]

    p()
    p(f"members        {len(nodes)}")
    if starts:
        p(f"window         {clock(min(starts))} → {clock(max(ends))}   (UTC)")
    p()
    if not epochs:
        render_undetermined(nodes, p)
        return

    p(f"epochs         {min(epochs)} → {max(epochs)}")
    p()

    counts = collections.Counter(v[0] for v in verdicts.values())
    branch_count = len(
        {(v[1], v[2]) for v in verdicts.values() if v[0] in ("current", "forked")}
    )
    headline = plural(branch_count, "partition")
    if counts["stalled"]:
        headline += f", {counts['stalled']} stalled"
    if counts["silent"]:
        headline += f", {counts['silent']} silent"
    split_at = next((e for e in epochs if len(by_epoch[e]) > 1), None)
    if split_at is not None:
        first_split = min(nodes[m].epochs[split_at][0]
                          for members in by_epoch[split_at].values() for m in members)
        headline += f".  Whole until {clock(first_split)}"
    p(f"  {headline}")
    p()

    vertices, edges = lineage(nodes, by_epoch)
    p("LINEAGE")
    p()
    for line in tree_lines(vertices, edges, nodes):
        p("  " + line)
    p()

    letter_for = lane_letters(by_epoch)
    p("LANES" + " " * 19 + "epoch →")
    p(f"  {'':<12}" + "".join(f"{e:>4}" for e in epochs))
    rank = {"current": 0, "stalled": 1, "forked": 2, "silent": 3}
    order = sorted(nodes, key=lambda n: (rank[verdicts[n][0]], verdicts[n][1] or 0, n))
    for name in order:
        node = nodes[name]
        cells = ""
        for e in epochs:
            if e in node.epochs:
                cells += f"{letter_for(e, node.auth_at(e)):>4}"
            elif node.last_epoch is not None and e > node.last_epoch:
                cells += "   ╴"
            else:
                cells += "   ·"
        mark = "" if verdicts[name][0] == "current" else f"   {verdicts[name][0]}"
        p(f"  {name:<12}{cells}{mark}")
    p()
    p("    ·  not yet a member    ╴  no epoch applied since")
    p()

    # One block per branch, not per member: everyone who diverged together
    # diverged for the same reason, and repeating it per member buries that.
    groups = collections.defaultdict(list)
    for name in order:
        verdict, last, auth = verdicts[name]
        if verdict in ("forked", "stalled"):
            groups[(verdict, last, auth)].append(name)

    for (verdict, last, auth), members in sorted(groups.items(), key=lambda kv: kv[0][1]):
        when = min(nodes[m].epochs[last][0] for m in members)
        p(f"{verdict.upper()}   epoch {last}, {short(auth)}, since {clock(when)}")
        p(f"  {plural(len(members), 'member')}: {', '.join(members)}")
        if verdict == "forked":
            for other, peers in sorted(by_epoch[last].items(), key=lambda kv: -len(kv[1])):
                if other != auth:
                    p(f"  against {short(other)}, {plural(len(peers), 'member')}"
                      f" incl. {', '.join(sorted(peers)[:3])}"
                      f"{' …' if len(peers) > 3 else ''}")
            seen = [r for m in members for r in nodes[m].received if r[2] in (None, last)]
            hashes = sorted({r[3] for r in seen if r[3]})
            if hashes:
                p(f"  candidates in hand when they chose: {', '.join(h[:6] for h in hashes)}")
            else:
                p("  candidate identities unavailable: receive_commit_candidate"
                  " logs no hash")
        else:
            p("  authenticator matches the branch that kept moving: behind, not forked")
        drops = sum(nodes[m].drops for m in members)
        last_line = max(nodes[m].last_ts for m in members)
        p(f"  {plural(drops, 'wrong-epoch drop')}, last line {clock(last_line)}")
        p()

    silent = sorted(n for n, v in verdicts.items() if v[0] == "silent")
    if silent:
        p("NOT DETERMINED")
        for name in silent:
            p(f"  {name}: no epoch line; log runs"
              f" {clock(nodes[name].first_ts)} → {clock(nodes[name].last_ts)}")
        p()


def to_json(nodes, by_epoch, verdicts):
    return {
        "members": {
            name: {
                "verdict": verdicts[name][0],
                "last_epoch": verdicts[name][1],
                "authenticator": verdicts[name][2],
                "joined_at": node.joined_at,
                "wrong_epoch_drops": node.drops,
                "epochs": {str(e): {"at": ts, "authenticator": a}
                           for e, (ts, a) in sorted(node.epochs.items())},
            }
            for name, node in nodes.items()
        },
        "epochs": {
            str(e): {a: sorted(m) for a, m in groups.items()}
            for e, groups in by_epoch.items()
        },
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("path", help="run directory, or a single log with --shared")
    ap.add_argument("--shared", action="store_true",
                    help="path is one log holding every member, split on user_id")
    ap.add_argument("--json", help="also write the report as JSON")
    args = ap.parse_args()

    nodes = load_shared(args.path) if args.shared else load_run(args.path)
    if not nodes:
        sys.exit(f"no member logs found under {args.path}")
    by_epoch = branches_by_epoch(nodes)
    verdicts = classify(nodes, by_epoch)
    render(nodes, by_epoch, verdicts)

    if args.json:
        import json
        with open(args.json, "w") as fh:
            json.dump(to_json(nodes, by_epoch, verdicts), fh, indent=2)
        print(f"  written {args.json}\n")


if __name__ == "__main__":
    main()
