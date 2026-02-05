# Chat CLI

A terminal chat application built with [ratatui](https://ratatui.rs/) using the logos-chat library.

## Features

- 💬 End-to-end encrypted messaging using the Double Ratchet algorithm
- 📁 File-based transport for local simulation (no network required)
- 💾 Persistent storage (SQLite)
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
| `/status` | Show connection status and your address |
| `/clear` | Clear message history |
| `/quit` or `Esc` | Exit the application |

### Sending Messages

Simply type your message and press Enter. Messages are automatically encrypted and delivered via the file-based transport.

## How It Works

### File-Based Transport

Since this is a local demo without a real network, messages are passed between users via files:

1. Each user has an "inbox" directory at `~/.local/share/chat-cli/transport/<username>/`
2. When Alice sends a message to Bob, it's written as a JSON file in Bob's inbox
3. Bob's client watches for new files and processes incoming messages
4. Files are deleted after processing

### Storage

User data (identity keys, chat state) is stored in SQLite databases at:
- `~/.local/share/chat-cli/data/<username>.db`

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
