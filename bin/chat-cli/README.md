# chat-cli

A terminal chat application built on top of libchat. End-to-end encrypted messaging in your terminal.

## Building

### With logos-delivery transport (recommended)

[logos-delivery](https://github.com/logos-messaging/logos-delivery) is exposed as a Nix package.
Build it once, then point `LOGOS_DELIVERY_LIB_DIR` at the result:

```bash
nix build .#logos-delivery
LOGOS_DELIVERY_LIB_DIR=./result/lib cargo build --release -p chat-cli
```

The binary lands at `target/release/chat-cli`.

### File transport only (no Nix required)

```bash
cargo build --release -p chat-cli
```

## Transports

| Transport | Description |
|-----------|-------------|
| File (default) | Shared directory; no network needed — great for local testing |
| logos-delivery | Embedded Waku node on the logos.dev network |

The transport is selected automatically at compile time: if `LOGOS_DELIVERY_LIB_DIR` is set when building, logos-delivery is used; otherwise the file transport is used.

## Quick start (file transport)

Run two instances in separate terminals, pointing at the same data directory:

```bash
# Terminal 1
cargo run -p chat-cli -- --name alice

# Terminal 2
cargo run -p chat-cli -- --name bob
```

### Establishing a connection

1. In Alice's terminal, type `/intro` — the bundle is copied to your clipboard automatically.
2. In Bob's terminal, type `/connect <paste bundle here>`.
3. Bob's "Hello!" message appears in Alice's terminal. Both can now chat.

## logos-delivery transport

After building with `LOGOS_DELIVERY_LIB_DIR` set, run:

```bash
./target/release/chat-cli --name alice
```

Optional flags:

| Flag | Default | Description |
|------|---------|-------------|
| `--db <path>` | *(ephemeral)* | SQLite file for persistent identity across restarts |
| `--preset <name>` | `logos.dev` | Network preset (`logos.dev` or `twn`) |
| `--port <n>` | `60000` | TCP port for the embedded logos-delivery node |
| `--log-file <path>` | *(stderr, off)* | Write logs to a file instead of stderr |

## Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/intro` | Generate your introduction bundle (copies to clipboard) |
| `/connect <bundle>` | Connect to a user using their introduction bundle |
| `/chats` | List all established chats |
| `/switch <user>` | Switch active chat |
| `/delete <user>` | Delete a chat session |
| `/status` | Show identity and connection info |
| `/clear` | Clear current chat's message history |
| `/quit` · `Esc` · `Ctrl+C` | Exit |

## Storage (file transport)

All data lives under `tmp/chat-cli-data/` by default (override with `--data`):

| Path | Contents |
|------|----------|
| `<name>.db` | SQLite — identity keys, ratchet state, chat metadata (encrypted) |
| `<name>_state.json` | UI state — message history, active chat |
| `transport/<name>/` | Inbox directory watched for incoming messages |

The SQLite database can be inspected with *DB Browser for SQLite*: password `chat-cli`, cipher `SQLCipher 4 defaults`.

## Architecture

```
bin/chat-cli/
├── src/
│   ├── main.rs           entry point, CLI arg parsing, transport selection
│   ├── app.rs            application state and command handling
│   ├── ui.rs             ratatui terminal UI
│   ├── utils.rs          shared helpers
│   ├── transport.rs      module declarations
│   └── transport/
│       ├── file.rs       file-based transport
│       └── logos_delivery.rs   logos-delivery (Waku) transport + FFI
└── build.rs              links liblogosdelivery when LOGOS_DELIVERY_LIB_DIR is set
```
