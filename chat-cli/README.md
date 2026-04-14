# Chat CLI

A terminal chat application built with [ratatui](https://ratatui.rs/) using the logos-chat library.

## Features

- 💬 End-to-end encrypted messaging using the Double Ratchet algorithm
- 📁 File-based transport for local simulation (no network required)
- 💾 Persistent storage (SQLite + JSON state)
- 🔄 Multiple chat support with chat switching
- 🖥️ Beautiful terminal UI with ratatui

## Usage

Run two instances with different usernames in separate terminals:

### Terminal 1 (Alice)

```bash
cargo run -p chat-cli -- alice
```

### Terminal 2 (Bob)

```bash
cargo run -p chat-cli -- bob
```

### Establishing a Connection

1. In Alice's terminal, type `/intro` to generate an introduction bundle
2. Copy the bundle string (starts with `Bundle:`)
3. In Bob's terminal, type `/connect alice <bundle>` (paste Alice's bundle)
4. Bob can now send messages to Alice
5. Alice will see Bob's initial "Hello!" message and can reply

### Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/intro` | Generate and display your introduction bundle |
| `/connect <user> <bundle>` | Connect to a user using their introduction bundle |
| `/chats` | List all your established chats |
| `/switch <user>` | Switch to a different chat |
| `/delete <user>` | Delete a chat (removes session and crypto state) |
| `/peers` | List transport-level peers (users with inbox directories) |
| `/status` | Show connection status and your address |
| `/clear` | Clear current chat's message history |
| `/quit` or `Esc` or `Ctrl+C` | Exit the application |

#### `/peers` vs `/chats`

- **`/peers`**: Shows users whose CLI has been started (have inbox directories). These are potential contacts you *could* message.
- **`/chats`**: Shows users you have an **encrypted session** with (via `/connect`). These are active conversations.

### Sending Messages

Simply type your message and press Enter. Messages are automatically encrypted and delivered via file-based transport.

## How It Works

### File-Based Transport

Messages are passed between users via files in a shared directory:

1. Each user has an "inbox" directory at `chat-cli-data/transport/<username>/`
2. When Alice sends a message to Bob, it's written as a JSON file in Bob's inbox
3. Bob's client watches for new files and processes incoming messages
4. Files are deleted after processing

### Storage

Data is stored in the `chat-cli-data/` directory:

| File | Purpose |
|------|---------|
| `<username>.db` | SQLite database for identity keys, inbox keys, chat metadata, and Double Ratchet state |
| `<username>_state.json` | CLI state: username↔chat mappings, message history, active chat |
| `transport/<username>/` | Inbox directory for receiving messages |

### Encryption

All messages are encrypted using:
- X3DH key agreement for initial key exchange
- Double Ratchet algorithm for ongoing message encryption
- ChaCha20-Poly1305 for authenticated encryption

## Example Session

```
# Terminal 1 (Alice)
$ cargo run -p chat-cli -- alice

/intro
# Output: Bundle:abc123...def456

# Terminal 2 (Bob)  
$ cargo run -p chat-cli -- bob

/connect alice Bundle:abc123...def456
# Connected! Bob sends "Hello!" automatically

# Now type messages in either terminal to chat!

# To see your chats:
/chats
# Output: alice (active)

# To switch between chats (if you have multiple):
/switch alice
```

## Architecture

```
chat-cli/
├── src/
│   ├── main.rs       # Entry point
│   ├── app.rs        # Application state and logic
│   ├── transport.rs  # File-based message transport
│   └── ui.rs         # Ratatui terminal UI
```

The CLI uses logos-chat as a library without modifying it:
- `ChatManager` handles all encryption/decryption
- `Introduction` bundles enable key exchange
- `AddressedEnvelope` carries encrypted messages
