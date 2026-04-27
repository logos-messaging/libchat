# chat-cli

A terminal chat application built on top of libchat. End-to-end encrypted messaging in your terminal.

## Building

[logos-delivery](https://github.com/logos-messaging/logos-delivery) is exposed as a Nix package.
Build it once, then point `LOGOS_DELIVERY_LIB_DIR` at the result:

```bash
nix build .#logos-delivery
LOGOS_DELIVERY_LIB_DIR=./result/lib cargo build --release -p chat-cli
```

The binary lands at `target/release/chat-cli`.

## Transports

Both transports are compiled into the binary and selected at runtime via `--transport`:

| Value (`--transport`) | Description |
|-----------------------|-------------|
| `logos-delivery` (default) | Embedded Waku node on the logos.dev network |
| `file` | Shared directory; no network needed — great for local testing |

## Quick start

Run two instances in separate terminals:

```bash
# Terminal 1
cargo run -p chat-cli -- --name alice --port 60001

# Terminal 2
cargo run -p chat-cli -- --name bob --port 60002
```

For local-only testing without any network dependency, use the file transport:

```bash
# Terminal 1
cargo run -p chat-cli -- --name alice --transport file

# Terminal 2
cargo run -p chat-cli -- --name bob --transport file
```

### Establishing a connection

1. In Alice's terminal, type `/intro` — the bundle is copied to your clipboard automatically.
2. In Bob's terminal, type `/connect <paste bundle here>`.
3. Bob's "Hello!" message appears in Alice's terminal. Both can now chat.

## Options

| Flag | Default | Description |
|------|---------|-------------|
| `--transport <kind>` | `logos-delivery` | Transport to use (`logos-delivery` or `file`) |
| `--data <dir>` | `tmp/chat-cli-data` | Data directory (UI state and default SQLite path) |
| `--db <path>` | `<data>/<name>.db` | SQLite file for persistent identity |
| `--preset <name>` | `logos.dev` | logos-delivery network preset |
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

## Storage

All data lives under `tmp/chat-cli-data/` by default (override with `--data`):

| Path | Contents |
|------|----------|
| `<name>.db` | SQLite — identity keys, ratchet state, chat metadata (encrypted) |
| `<name>_state.json` | UI state — message history, active chat |
| `transport/<name>/` | Inbox directory watched for incoming messages (file transport only) |

The SQLite database can be inspected with *DB Browser for SQLite*: password `chat-cli`, cipher `SQLCipher 4 defaults`.

## Architecture

```
bin/chat-cli/
├── src/
│   ├── main.rs           entry point, CLI arg parsing, runtime transport dispatch
│   ├── app.rs            application state and command handling
│   ├── ui.rs             ratatui terminal UI
│   ├── utils.rs          shared helpers
│   ├── transport.rs      module declarations
│   └── transport/
│       ├── file.rs       file-based transport
│       └── logos_delivery.rs   logos-delivery (Waku) transport + FFI
└── build.rs              links liblogosdelivery (LOGOS_DELIVERY_LIB_DIR required)
```
