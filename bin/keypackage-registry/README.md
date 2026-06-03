# keypackage-registry

Testnet KeyPackage Registry — addresses [issue #110](https://github.com/logos-messaging/libchat/issues/110).

Standalone HTTP service that caches MLS KeyPackages keyed by **`device_id`**, so a
client can fetch a contact's keypackage without an out-of-band exchange.
Throwaway by design: scheduled to be replaced by a λLEZ-based service in v0.3, so
it intentionally has no overlap with the rest of libchat (axum + rusqlite only).

`device_id` is the hex-encoded 32-byte Ed25519 verifying key of a device. The
account → device mapping is out of scope here and handled elsewhere.

## Trust model

The server is dumb storage. Each bundle is signed by the device key over
`device_id || key_package || timestamp_ms_le`. Because `device_id` *is* the
verifying key, a valid signature proves the submitter holds that key — only the
holder of a `device_id` can publish under it.

**Consumers MUST verify the signature on retrieve**; the server currently does
not. A valid signature does not prove the device is authorized for any account —
that binding arrives with λLEZ in v0.3.

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
  "device_id":    "hex(32-byte ed25519 verifying key)",
  "key_package":  "base64(MLS KeyPackage bytes)",
  "timestamp_ms": 1717200000000,
  "signature":    "base64(64-byte ed25519 signature)"
}
```

`signature` is Ed25519 by `device_id`'s key over
`device_id || key_package || timestamp_ms.to_le_bytes()`. The server validates
shapes (hex 32-byte key, base64 key_package, 64-byte signature) and stores.
Returns `204` on success, `400` on malformed input.

### `GET /v0/keypackage/{device_id}`

Returns the most recently submitted bundle for that `device_id`, or `404`:

```json
{
  "key_package":  "base64(MLS bytes)",
  "timestamp_ms": 1717200000000,
  "signature":    "base64(64-byte ed25519 signature)"
}
```

Consumers reconstruct the signed message, recover the key from `device_id`, and
verify before use. A bundle that fails verification must be treated as not found.

## Storage & retention

A SQLite table keyed by `device_id`. A background task runs every
`--prune-interval-secs`, dropping bundles older than `--retention-days` and
keeping at most `--max-per-identity` per `device_id`. The schema is an internal
detail and may change.

## Lifecycle

Exists to unblock contact-by-id flows on testnet; removed once λLEZ-based
discovery lands in v0.3. The seam is the `RegistrationService` trait
(`core/conversations/src/service_traits.rs`) — swapping implementations does not
touch the chat protocol.
