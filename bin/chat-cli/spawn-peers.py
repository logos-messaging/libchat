#!/usr/bin/env python3
"""Spawn N chat-cli peers on the logos.test network and print their addresses.

chat-cli has no headless mode: it always launches a ratatui TUI, and crossterm
opens /dev/tty when stdin is not a terminal, so a background instance without a
pty dies immediately. Each peer therefore gets its own pty, whose output this
drains and scrapes. Once a peer's delivery node is up, `/account` is typed into
it and the 64-hex account address is read back off the rendered frame.

The peers stay alive until this exits (Ctrl-C), which is the point: paste the
printed addresses into logos-chat-ui's Add member field by hand.

Usage: spawn-peers.py N [--bin PATH] [--data DIR] [--preset logos.test]
"""
import argparse, os, pty, re, select, signal, subprocess, sys, time

ADDR = re.compile(rb"[0-9a-f]{64}")
# The banner chat-cli prints once its embedded delivery node has joined; typing
# into the TUI before it appears goes nowhere.
READY = b"Node connected."
# Give the TUI this long to take over the screen after the banner before typing,
# then re-ask on this period until an address comes back: a keystroke sent while
# the frame is still being set up lands nowhere and there is no reply to detect.
SETTLE_S = 1.5
REASK_S = 15.0


class Peer:
    def __init__(self, idx, bin_path, data_dir, preset):
        self.idx = idx
        self.name = f"peer{idx:02d}"
        self.buf = bytearray()
        self.address = None
        self.ready_at = None
        self.last_ask = 0.0
        d = os.path.join(data_dir, self.name)
        os.makedirs(d, exist_ok=True)
        self.master, slave = pty.openpty()
        # A real window size: ratatui draws nothing into an 0x0 terminal, and the
        # address is read off what it draws.
        import fcntl, struct, termios
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 200, 0, 0))
        self.proc = subprocess.Popen(
            [bin_path, "--name", self.name, "--transport", "logos-delivery",
             "--preset", preset, "--data", d, "--log-file", os.path.join(d, "run.log")],
            stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)

    def pump(self):
        """Drain whatever the pty has and pick the address out of the frame."""
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            return
        if not chunk:
            return
        self.buf += chunk
        if self.address is None:
            if self.ready_at is None and READY in self.buf:
                self.ready_at = time.time()
            m = ADDR.search(self.buf)
            if m:
                self.address = m.group(0).decode()
        # Keep the tail only: a long-running TUI redraws forever.
        if len(self.buf) > 262144:
            del self.buf[:131072]

    def ask(self, now):
        """Type `/account` once the node is up, and again until it answers."""
        if self.address is not None or self.ready_at is None:
            return
        if now - self.ready_at < SETTLE_S or now - self.last_ask < REASK_S:
            return
        self.last_ask = now
        try:
            os.write(self.master, b"/account\r")
        except OSError:
            pass

    def alive(self):
        return self.proc.poll() is None

    def stop(self):
        try:
            os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("n", type=int)
    ap.add_argument("--bin", default="target/debug/chat-cli")
    ap.add_argument("--data", default="/tmp/chat-peers")
    ap.add_argument("--preset", default="logos.test")
    ap.add_argument("--stagger", type=float, default=2.0,
                    help="seconds between launches; the nodes all bootstrap at once otherwise")
    ap.add_argument("--timeout", type=float, default=300.0)
    args = ap.parse_args()

    # An orphaned peer keeps redrawing into a dead pty and costs roughly ten
    # times its idle CPU, so a SIGTERM has to reach the teardown rather than
    # kill this process where it stands.
    signal.signal(signal.SIGTERM, _raise_interrupt)

    peers = []
    try:
        print(f"launching {args.n} peers on {args.preset} ...", file=sys.stderr)
        for i in range(1, args.n + 1):
            peers.append(Peer(i, args.bin, args.data, args.preset))
            deadline = time.time() + args.stagger
            while time.time() < deadline:
                drain(peers, 0.2)
            print(f"  {i}/{args.n} launched", end="\r", file=sys.stderr)

        deadline = time.time() + args.timeout
        while time.time() < deadline:
            drain(peers, 0.5)
            got = sum(1 for p in peers if p.address)
            dead = [p.name for p in peers if not p.alive()]
            print(f"  addresses {got}/{len(peers)}"
                  + (f"  DIED: {','.join(dead)}" if dead else "") + "        ",
                  end="\r", file=sys.stderr)
            if got == len(peers):
                break
        print(file=sys.stderr)

        for p in peers:
            print(f"{p.name}\t{p.address or 'NO ADDRESS'}")
        sys.stdout.flush()

        missing = [p.name for p in peers if not p.address]
        if missing:
            print(f"no address from: {' '.join(missing)}", file=sys.stderr)
        print("\npeers are running; Ctrl-C to stop them all", file=sys.stderr)
        while True:
            drain(peers, 1.0)
    except KeyboardInterrupt:
        pass
    finally:
        for p in peers:
            p.stop()


def _raise_interrupt(_signum, _frame):
    raise KeyboardInterrupt


def drain(peers, timeout):
    fds = [p.master for p in peers if p.alive()]
    if not fds:
        time.sleep(timeout)
        return
    ready, _, _ = select.select(fds, [], [], timeout)
    now = time.time()
    for p in peers:
        if p.master in ready:
            p.pump()
        p.ask(now)


if __name__ == "__main__":
    main()
