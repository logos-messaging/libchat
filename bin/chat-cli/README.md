# Chat CLI

A terminal chat application based on libchat library.

## Features

- End-to-end encrypted messaging using libchat
- File-based transport for local simulation (no network required)
- Persistent storage (SQLite + JSON state)
- Multiple chat support with chat switching

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
2. Copy the intro string
3. In Bob's terminal, type `/connect alice <intro>` (paste Alice's intro bundle)
4. Bob can now send messages to Alice
5. Alice will see Bob's initial "Hello!" message and can reply

### Commands

| Command | Description |
|---------|-------------|
| `/help` | Show available commands |
| `/intro` | Generate and display your introduction bundle |
| `/connect <user> <intro>` | Connect to a user using their introduction bundle |
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

1. Each user has an "inbox" directory at `tmp/chat-cli-data/transport/<username>/`
2. When Alice sends a message to Bob, it's written as a JSON file in Bob's inbox
3. Bob's client watches for new files and processes incoming messages
4. Files are deleted after processing

### Storage

Data is stored in the `tmp/chat-cli-data/` directory:

| File | Purpose |
|------|---------|
| `<username>.db` | SQLite database for identity keys, inbox keys, chat metadata, and Double Ratchet state |
| `<username>_state.json` | CLI state: username↔chat mappings, message history, active chat |
| `transport/<username>/` | Inbox directory for receiving messages |

The sqlite tables can be viewed with app `DB Browser for SQLite`, password is `123456`, config use `SQLCipher 4 defaults`.

## Example Session

```
# Terminal 1 (Alice)
$ cargo run -p chat-cli -- alice

/intro
# Output: logos_chatintro_abc123

# Terminal 2 (Bob)  
$ cargo run -p chat-cli -- bob

/connect alice logos_chatintro_abc123
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
