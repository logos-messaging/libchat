# channel-chat

A room chat built directly on logos-delivery's **reliable channels** API, via
[`waku-bindings`](../../vendor/logos-delivery-rust-bindings). It is deliberately
small: no MLS, no libchat stack, no encryption of the chat itself — just the
channels API, so the API is the only thing on screen.

For the full encrypted client see [`bin/chat-cli`](../chat-cli), which uses
these same channels underneath as its transport.

## Running

One process per participant, each with its own nick:

```sh
cargo run -p channel-chat -- --nick Alice --room lobby   # terminal 1
cargo run -p channel-chat -- --nick Bob   --room lobby   # terminal 2
```

Type and press Enter to send; Esc quits. The node takes a few seconds to start
and find peers on `logos.dev`, so the first message may need a retry. Each
instance prints its own multiaddr at startup; to wire two local instances
together without waiting on discovery, pass one to the other:

```sh
cargo run -p channel-chat -- --nick Bob --room lobby --peer /ip4/127.0.0.1/tcp/60001/p2p/16Uiu2...
```

| Flag | Default | Meaning |
|---|---|---|
| `--nick` | *(required)* | Display name, and the channel's SDS participant id |
| `--room` | `lobby` | Room to join — everyone in a room shares one channel |
| `--port` | `0` (OS picks) | TCP port for the node |
| `--peer` | *(none)* | Multiaddr to dial directly, instead of waiting on discovery |

## What it does

1. Starts a node on the `logos.dev` preset. The preset is what supplies the
   entry nodes *and* autosharding — a channel's shard is derived from its
   content topic, so a node without autosharding cannot carry one.
2. Registers the three channel listeners — `received`, `sent`, `error` —
   **before** starting the node.
3. Opens channel `{room}` on content topic `/logos-chat-example/1/{room}/proto`.
4. **Subscribes to that content topic.** Creating a channel does not subscribe;
   ingress arrives through the messaging layer, so without this nothing lands.
5. Sends with `channel_send`, and closes the channel on quit.

## Notes

- **Run each participant under a different `--nick`.** The nick is both the
  participant id and (via `./data-channel-chat-{nick}`) the storage root. The
  persistency layer is a process-wide singleton keyed on that root, and SDS rows
  are keyed by channel id, so two participants sharing a root would each load
  the other's causal history and silently drop the other's messages as replays.
  This is also why participants are separate processes rather than tasks.
- Sends are acknowledged asynchronously, so the outcome shows up in the status
  bar (`sent` / `SEND FAILED`) rather than at the call site. That reliability —
  acks, retransmission, causal ordering — is what channels add over a raw relay
  publish.
- A node does not receive its own channel messages, so your own lines are echoed
  locally.
- **The author's nick travels inside the payload, not in `sender_id`.** A
  received event's `sender_id` is filled in from the *receiving* channel's own
  participant id (`reliable_channel.nim`'s `reportReceived` emits
  `self.senderId`), so reading the author off it would attribute every incoming
  message to whoever is reading it. Worth knowing before reaching for that field.
