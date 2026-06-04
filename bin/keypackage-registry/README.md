# keypackage-registry

Testnet KeyPackage Registry — addresses [issue #110](https://github.com/logos-messaging/libchat/issues/110).

Standalone HTTP service that caches MLS KeyPackages keyed by **`device_id`**, so a
client can fetch a contact's keypackage without an out-of-band exchange.
Throwaway by design: scheduled to be replaced by a λLEZ-based service in v0.3, so
it intentionally has no overlap with the rest of libchat (axum + rusqlite only).

`device_id` is the hex-encoded 32-byte Ed25519 verifying key of a device. The
account → device mapping is out of scope here and handled elsewhere.

## Trust model

A bundle is an opaque **payload** plus its **signature**, published under a
**`device_id`** (the hex of the device's 32-byte Ed25519 verifying key).
The signed bytes and the wire bytes are identical, so a verifier checks the
signature over exactly what it received, no reconstruction.

The **server treats `payload` as a black box**: it never decodes it. It only
verifies that `signature` over the payload bytes is valid under `device_id`'s
key, then stores it. A valid signature is proof-of-possession — only the holder
of `device_id`'s key can publish under it — so an adversary can't publish under
a `device_id` it doesn't control, and junk is dropped before storage. The server
is not a trusted authority, so **consumers MUST also verify on retrieve**, and a
valid signature does not prove the device is authorized for any account (that
binding arrives with λLEZ in v0.3).

Consumers define the payload layout. Today it is:

```text
payload = timestamp_ms_le[8] || key_package[..]
```

Fixed-width field first with the variable `key_package` last makes it parse
exactly one way — no delimiter, even though `key_package` is arbitrary bytes.

## Building & running

```bash
cargo build --release -p keypackage-registry
./target/release/keypackage-registry   # binds 0.0.0.0:8080, db ./keypackage-registry.db
```

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <addr>` | `0.0.0.0:8080` | HTTP bind address |
| `--db <path>` | `keypackage-registry.db` | SQLite database path |
| `--max-per-identity <n>` | `5` | Bundles retained per `device_id` |
| `--retention-days <n>` | `30` | Drop bundles older than this |
| `--prune-interval-secs <n>` | `3600` | How often the prune task runs |

Logs via `RUST_LOG` (default `info`).

## API

### `POST /v0/keypackage`

```json
{
  "device_id": "hex(32-byte ed25519 verifying key)",
  "payload":   "base64(opaque signed bytes)",
  "signature": "base64(64-byte ed25519 signature over payload)"
}
```

The server verifies `signature` over the (opaque) `payload` bytes under
`device_id`'s key before storing, keyed by `device_id`. It does not decode
`payload`. Returns `204` on success, `400` on malformed input or a signature
that fails to verify.

### `GET /v0/keypackage/{device_id}`

Returns the most recently submitted bundle for that `device_id`, or `404`:

```json
{
  "payload":   "base64(...)",
  "signature": "base64(64-byte ed25519 signature)"
}
```

Consumers verify `signature` over the `payload` bytes using the key recovered
from `device_id`, then read `key_package` out of the payload. A bundle that
fails verification must be treated as not found.

## Storage & retention

A SQLite table keyed by `device_id`. A background task runs every
`--prune-interval-secs`, dropping bundles older than `--retention-days` and
keeping at most `--max-per-identity` per `device_id`. The schema is an internal
detail and may change.

## Smoke test

End-to-end check with the real `chat-cli` against a running server:

```bash
cargo build -p keypackage-registry -p chat-cli

# 1. start the server on a test port with a fresh db
./target/debug/keypackage-registry --bind 127.0.0.1:18080 --db tmp/registry.db

# 2. register two identities through chat-cli (--smoketest exits after registering)
./target/debug/chat-cli --name alice --transport file --data tmp/alice \
  --registry-url http://127.0.0.1:18080 --smoketest    # exits 0 on success
./target/debug/chat-cli --name bob   --transport file --data tmp/bob \
  --registry-url http://127.0.0.1:18080 --smoketest

# 3. confirm both bundles landed
sqlite3 tmp/registry.db "SELECT substr(device_id,1,12), length(payload) FROM keypackages;"
```

A non-zero exit from `chat-cli` means the server rejected the submission — e.g.
the signature failed verification. `GET /v0/keypackage/{device_id}` returns `200`
for a registered device and `404` otherwise.

## Lifecycle

Exists to unblock contact-by-id flows on testnet; removed once λLEZ-based
discovery lands in v0.3. The seam is the `RegistrationService` trait
(`core/conversations/src/service_traits.rs`) — swapping implementations does not
touch the chat protocol.
