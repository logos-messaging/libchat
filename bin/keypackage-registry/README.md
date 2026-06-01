# keypackage-registry

Testnet KeyPackage Registry — addresses [issue #110](https://github.com/logos-messaging/libchat/issues/110).

Standalone HTTP service that holds MLS KeyPackages so clients can add a contact by `account_id` without an out-of-band bundle exchange. Designed as a throwaway: scheduled to be replaced by a λLEZ-based service in v0.3, so it intentionally has no overlap with the rest of libchat (depends only on axum + rusqlite).

The storage schema is multi-device-ready — an `account_id` can have several `device_pubkey`s, each with its own keypackage history. The current chat layer (Scope A) only consumes one device per account, so `GET` returns the single latest bundle across all devices.

**No authorization.** Submissions are not signed or authenticated. λLEZ in v0.3 is the identity authority; for testnet we trust callers and rely on MLS validation downstream when the keypackage is actually used.

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

Submit a bundle. No signature required.

```json
{
  "account_id":    "user-chosen label",
  "device_pubkey": "base64(32-byte ed25519 verifying key)",
  "key_package":   "base64(MLS KeyPackage bytes)",
  "timestamp_ms":  1717200000000
}
```

The server validates only that `device_pubkey` decodes to 32 bytes and
`key_package` is valid base64. It does **not** verify any signature or check
that the submitter owns `account_id` — that's λLEZ's job in v0.3.

Returns `204 No Content` on success, `400` on shape errors.

### `GET /v0/keypackage/{account_id}`

Returns the most recently submitted bundle for that id, across all devices.

```json
{
  "key_package":   "base64(MLS bytes)",
  "timestamp_ms":  1717200000000,
  "device_pubkey": "base64(32-byte ed25519 verifying key)"
}
```

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
