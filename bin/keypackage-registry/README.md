# keypackage-registry

Testnet KeyPackage Registry — addresses [issue #110](https://github.com/logos-messaging/libchat/issues/110).

Standalone HTTP service that holds MLS KeyPackages so clients can add a contact by `account_id` without an out-of-band bundle exchange. Designed as a throwaway: scheduled to be replaced by a λLEZ-based service in v0.3, so it intentionally has no overlap with the rest of libchat (depends only on axum + rusqlite).

The storage schema is multi-device-ready — an `account_id` can have several `device_pubkey`s, each with its own keypackage history. The current chat layer (Scope A) only consumes one device per account, so `GET` returns the single latest bundle across all devices.

**Server is dumb storage.** Submissions are stored without verification. Bundles carry a self-signature by the device key over `(account_id || device_pubkey || key_package || ts_le)`; consumers verify it on retrieve. This catches a replay attack where someone copies a victim's bundle and re-posts it under a different `account_id` — the signature commits to the original `account_id` and won't verify against the new one.

The self-signature does **not** prove that `device_pubkey` is actually authorized for `account_id` (an attacker can mint their own keys and sign anything). That impersonation gap closes once λLEZ provides the on-chain authorization mapping in v0.3.

## Building & running

```bash
# Build
cargo build --release -p keypackage-registry

# Run with defaults (binds 0.0.0.0:8080, db at ./keypackage-registry.db)
./target/release/keypackage-registry
```

| Flag | Default | Description |
|------|---------|-------------|
| `--bind <addr>` | `0.0.0.0:8080` | HTTP bind address |
| `--db <path>` | `keypackage-registry.db` | SQLite database path |
| `--max-per-identity <n>` | `5` | Bundles retained per `(account_id, device_pubkey)` |
| `--retention-days <n>` | `30` | Drop bundles older than this |
| `--prune-interval-secs <n>` | `3600` | How often the prune task runs |

Logs: `RUST_LOG=info,tracing=warn` (default `info`).

## API

### `POST /v0/keypackage`

Submit a bundle.

```json
{
  "account_id":    "string derived from the account",
  "device_pubkey": "base64(32-byte ed25519 verifying key)",
  "key_package":   "base64(MLS KeyPackage bytes)",
  "timestamp_ms":  1717200000000,
  "signature":     "base64(64-byte ed25519 signature)"
}
```

`signature` MUST be Ed25519 by `device_pubkey` over the byte concatenation
`account_id || device_pubkey || key_package || timestamp_ms.to_le_bytes()`.

The server validates only basic shapes (`device_pubkey` 32 bytes, `signature`
64 bytes, valid base64). It does **not** verify the signature — verification
happens client-side on retrieve. Returns `204 No Content` on success, `400`
on shape errors.

### `GET /v0/keypackage/{account_id}`

Returns the most recently submitted bundle for that id, across all devices.

```json
{
  "key_package":   "base64(MLS bytes)",
  "timestamp_ms":  1717200000000,
  "device_pubkey": "base64(32-byte ed25519 verifying key)",
  "signature":     "base64(64-byte ed25519 signature)"
}
```

**Consumers MUST verify** `signature` against `device_pubkey` over
`account_id || device_pubkey || key_package || timestamp_ms.to_le_bytes()`
before using the keypackage. A bundle that fails verification has been
tampered with or replayed under the wrong `account_id`; treat it as
not found.

Returns `404 Not Found` if no bundle exists. When multi-device fanout
arrives (Scope B), this becomes an array.

## Storage

Single SQLite table:

```sql
CREATE TABLE keypackages (
  account_id    TEXT NOT NULL,
  device_pubkey BLOB NOT NULL,
  received_at   INTEGER NOT NULL,   -- unix ms
  timestamp_ms  INTEGER NOT NULL,   -- client-supplied
  key_package   BLOB NOT NULL,
  signature     BLOB NOT NULL,      -- 64-byte ed25519, opaque to server
  PRIMARY KEY (account_id, device_pubkey, received_at)
);
```

A background tokio task runs every `--prune-interval-secs`:
- Deletes rows where `received_at < now - retention_days`.
- Keeps the most recent `--max-per-identity` rows per `(account_id, device_pubkey)` — each device's history is bounded independently.

## Quick smoke

```bash
# Terminal 1 — server
cargo run -p keypackage-registry -- --bind 127.0.0.1:18080

# Terminal 2 — two chat-cli sessions registering against it
mkdir -p tmp/alice tmp/bob
cargo run -p chat-cli -- --name alice --transport file \
  --data tmp/alice --registry-url http://127.0.0.1:18080 --smoketest
cargo run -p chat-cli -- --name bob --transport file \
  --data tmp/bob --registry-url http://127.0.0.1:18080 --smoketest

# Verify both landed
sqlite3 keypackage-registry.db \
  "SELECT account_id, length(key_package) FROM keypackages;"
```

## Lifecycle

This service exists to unblock contact-by-id flows on testnet. It will be removed once λLEZ-based discovery lands in v0.3. The seam is the `RegistrationService` trait (`core/conversations/src/service_traits.rs`); swapping implementations does not touch the chat protocol.
