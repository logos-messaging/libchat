#!/usr/bin/env python3
"""Reproduce the GroupV2 growth stall over the real logos.test network.

Spawns one creator chat-cli plus N peer chat-clis, each on its own pty, has the
creator open a group and invite every peer on a configurable rhythm, and polls
`/members` on the creator and on the peers so the roster is sampled over time.

Everything runs from one chat-cli binary, so every participant shares the MLS
ciphersuite and the libchat revision.

Usage: scale-group.py N --bin PATH [--burst 7,15,3] [--gap 3.5] [--pause 45,90]
"""
import argparse, os, pty, re, select, signal, subprocess, sys, time

ANSI = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]")
ADDR = re.compile(rb"[0-9a-f]{64}")
MEMBERS = re.compile(rb"Members\s*\((\d+)\)")
READY = b"Node connected."
SETTLE_S = 1.5
REASK_S = 15.0


def stamp():
    return time.strftime("%H:%M:%S")


class Node:
    def __init__(self, name, bin_path, data_dir, preset, env):
        self.name = name
        self.buf = bytearray()
        self.address = None
        self.ready_at = None
        self.last_ask = 0.0
        self.members = None
        d = os.path.join(data_dir, name)
        os.makedirs(d, exist_ok=True)
        self.dir = d
        self.raw = open(os.path.join(d, "pty.raw"), "wb")
        self.master, slave = pty.openpty()
        import fcntl, struct, termios
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 60, 200, 0, 0))
        self.proc = subprocess.Popen(
            [bin_path, "--name", name, "--transport", "logos-delivery",
             "--preset", preset, "--data", d,
             "--log-file", os.path.join(d, "run.log")],
            stdin=slave, stdout=slave, stderr=slave,
            start_new_session=True, env=env)
        os.close(slave)

    def pump(self):
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            return
        if not chunk:
            return
        self.raw.write(chunk)
        self.raw.flush()
        self.buf += chunk
        plain = ANSI.sub(b"", bytes(self.buf))
        if self.ready_at is None and READY in plain:
            self.ready_at = time.time()
        if self.address is None:
            m = ADDR.search(plain)
            if m:
                self.address = m.group(0).decode()
        for m in MEMBERS.finditer(plain):
            self.members = int(m.group(1))
        if len(self.buf) > 262144:
            del self.buf[:131072]

    def ask_account(self, now):
        if self.address is not None or self.ready_at is None:
            return
        if now - self.ready_at < SETTLE_S or now - self.last_ask < REASK_S:
            return
        self.last_ask = now
        self.send("/account")

    def send(self, line):
        try:
            os.write(self.master, line.encode() + b"\r")
        except OSError:
            pass

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass


def drain(nodes, timeout):
    fds = [n.master for n in nodes if n.alive()]
    if not fds:
        time.sleep(timeout)
        return
    ready, _, _ = select.select(fds, [], [], timeout)
    now = time.time()
    for n in nodes:
        if n.master in ready:
            n.pump()
        n.ask_account(now)


def wait(nodes, seconds, log=None):
    end = time.time() + seconds
    while time.time() < end:
        drain(nodes, 0.5)
        if log:
            print(f"  {log} {int(end - time.time())}s   ", end="\r", file=sys.stderr)


def _raise_interrupt(_s, _f):
    raise KeyboardInterrupt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("n", type=int)
    ap.add_argument("--bin", default="target/debug/chat-cli")
    ap.add_argument("--data", default="/tmp/chat-scale")
    ap.add_argument("--preset", default="logos.test")
    ap.add_argument("--stagger", type=float, default=2.0)
    ap.add_argument("--boot-timeout", type=float, default=420.0)
    ap.add_argument("--burst", default="7,15,3",
                    help="how many invites per burst")
    ap.add_argument("--gap", type=float, default=3.7,
                    help="seconds between invites inside a burst")
    ap.add_argument("--pause", default="45,90",
                    help="seconds between bursts")
    ap.add_argument("--poll", type=float, default=20.0,
                    help="seconds between /members samples on the creator")
    ap.add_argument("--observe", type=float, default=600.0,
                    help="seconds to keep sampling after the last invite")
    ap.add_argument("--rust-log",
                    default="warn,de_mls=debug,hashgraph_like_consensus=debug,libchat=info")
    args = ap.parse_args()

    signal.signal(signal.SIGTERM, _raise_interrupt)

    bursts = [int(x) for x in args.burst.split(",") if x]
    pauses = [float(x) for x in args.pause.split(",") if x]
    if sum(bursts) != args.n:
        sys.exit(f"bursts {bursts} sum to {sum(bursts)}, not n={args.n}")

    env = dict(os.environ, RUST_LOG=args.rust_log)
    nodes = []
    try:
        print(f"[{stamp()}] launching creator + {args.n} peers on {args.preset}",
              file=sys.stderr)
        creator = Node("creator", args.bin, args.data, args.preset, env)
        nodes.append(creator)
        for i in range(1, args.n + 1):
            wait(nodes, args.stagger)
            nodes.append(Node(f"peer{i:02d}", args.bin, args.data, args.preset, env))
            print(f"  launched {i}/{args.n}      ", end="\r", file=sys.stderr)

        peers = nodes[1:]
        end = time.time() + args.boot_timeout
        while time.time() < end:
            drain(nodes, 0.5)
            got = sum(1 for n in nodes if n.address)
            print(f"  addresses {got}/{len(nodes)}     ", end="\r", file=sys.stderr)
            if got == len(nodes):
                break
        print(file=sys.stderr)

        missing = [n.name for n in nodes if not n.address]
        if missing:
            print(f"[{stamp()}] no address from: {' '.join(missing)}", file=sys.stderr)
        invitees = [p for p in peers if p.address]
        print(f"[{stamp()}] {len(invitees)} peers reachable", file=sys.stderr)

        creator.send("/new scale")
        wait(nodes, 5)
        print(f"[{stamp()}] group created", file=sys.stderr)

        next_poll = time.time()
        i = 0
        for b, count in enumerate(bursts):
            for _ in range(count):
                if i >= len(invitees):
                    break
                creator.send(f"/add {invitees[i].address}")
                print(f"[{stamp()}] invite {i + 1}/{len(invitees)} -> {invitees[i].name}",
                      file=sys.stderr)
                i += 1
                wait(nodes, args.gap)
                if time.time() >= next_poll:
                    creator.send("/members")
                    next_poll = time.time() + args.poll
            if b < len(pauses):
                print(f"[{stamp()}] burst {b + 1} done ({i} invited), pausing {pauses[b]}s",
                      file=sys.stderr)
                end = time.time() + pauses[b]
                while time.time() < end:
                    wait(nodes, min(args.poll, max(1, end - time.time())))
                    creator.send("/members")
                    drain(nodes, 1.0)
                    print(f"[{stamp()}] creator roster: {creator.members}", file=sys.stderr)

        print(f"[{stamp()}] all {i} invites issued; observing {args.observe}s",
              file=sys.stderr)
        end = time.time() + args.observe
        while time.time() < end:
            wait(nodes, args.poll)
            creator.send("/members")
            drain(nodes, 1.5)
            print(f"[{stamp()}] creator roster: {creator.members}", file=sys.stderr)

        print(f"[{stamp()}] final sweep: asking every peer for its roster", file=sys.stderr)
        for p in peers:
            p.send("/members")
        wait(nodes, 15)
        print(f"\n=== rosters at {stamp()} ===")
        print(f"creator\t{creator.members}")
        for p in peers:
            print(f"{p.name}\t{p.members}\t{'alive' if p.alive() else 'DEAD'}")
        sys.stdout.flush()
    except KeyboardInterrupt:
        pass
    finally:
        print(f"\n[{stamp()}] stopping {len(nodes)} nodes", file=sys.stderr)
        for n in nodes:
            n.stop()


if __name__ == "__main__":
    main()
