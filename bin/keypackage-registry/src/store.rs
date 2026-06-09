use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct StoredKeyPackageBundle {
    /// The canonical signed payload, stored verbatim and returned as-is so
    /// consumers verify over the exact bytes that were signed.
    pub payload: Vec<u8>,
    /// 64-byte Ed25519 signature over `payload`. Opaque to the server.
    pub signature: Vec<u8>,
}

/// A signed bundle associating an account with its set of device (LocalIdentity)
/// public keys. The server stores exactly one blob per `account_id`; a newer
/// bundle replaces the old one only when its lamport is strictly higher (see
/// [`Store::upsert_account`]). `payload` is otherwise opaque to the server: it
/// encodes a lamport-timestamped list of device pubkeys signed by the account
/// key so that consumers can verify the full device set.
#[derive(Debug, Clone)]
pub struct StoredAccountBundle {
    /// The canonical signed payload, returned verbatim so consumers can verify
    /// the account signature over the exact bytes.
    pub payload: Vec<u8>,
    /// 64-byte Ed25519 signature over `payload` made by the account key.
    pub signature: Vec<u8>,
    /// Unix timestamp (ms) of the last upsert, stored for pruning.
    pub updated_at: i64,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        // Create the db's parent directory if the caller pointed at a nested
        // path (e.g. `tmp/registry.db`); SQLite won't create it and errors with
        // "unable to open database file" otherwise.
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create db directory {}", parent.display()))?;
        }
        let conn = Connection::open(path).context("open sqlite")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS keypackages (
                device_id     TEXT NOT NULL,
                received_at   INTEGER NOT NULL,
                payload       BLOB NOT NULL,
                signature     BLOB NOT NULL,
                PRIMARY KEY (device_id, received_at)
            );
            -- One row per account; newer upserts replace the existing row.
            CREATE TABLE IF NOT EXISTS account_bundles (
                account_id   TEXT    NOT NULL PRIMARY KEY,
                updated_at   INTEGER NOT NULL,
                payload      BLOB    NOT NULL,
                signature    BLOB    NOT NULL
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert(&self, device_id: &str, bundle: &StoredKeyPackageBundle) -> Result<()> {
        let received_at = now_ms() as i64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO keypackages
               (device_id, received_at, payload, signature)
             VALUES (?1, ?2, ?3, ?4)",
            params![device_id, received_at, bundle.payload, bundle.signature],
        )?;
        Ok(())
    }

    /// Returns the most recently received bundle for `device_id`. Scope A: the
    /// chat layer consumes one bundle per device. When multi-keypackage fanout
    /// lands, switch this to return a `Vec<StoredKeyPackageBundle>`.
    pub fn latest(&self, device_id: &str) -> Result<Option<StoredKeyPackageBundle>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT payload, signature FROM keypackages
                 WHERE device_id = ?1
                 ORDER BY received_at DESC
                 LIMIT 1",
                params![device_id],
                |r| {
                    Ok(StoredKeyPackageBundle {
                        payload: r.get::<_, Vec<u8>>(0)?,
                        signature: r.get::<_, Vec<u8>>(1)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Upsert the signed device-list bundle for `account_id`. The server stores
    /// exactly one blob per account.
    ///
    /// Anti-replay: `lamport` is the monotonic version read from `bundle.payload`
    /// (already signature-verified by the handler, so a forged value can't slip
    /// past — the signature wouldn't match). The stored bundle is replaced only
    /// when `lamport` is strictly greater than the one currently on file. A
    /// replayed older-but-still-valid bundle therefore can't downgrade the device
    /// list, and `updated_at` (the retention clock) is only bumped on a real
    /// update so a replay can't keep a stale bundle alive past retention.
    ///
    /// Returns `true` when the bundle was stored, `false` when it was rejected as
    /// stale. The compare-and-swap runs under the connection lock so concurrent
    /// publishes can't interleave a read with a write. The `updated_at` field of
    /// `bundle` is ignored; the store stamps the row with the current time.
    pub fn upsert_account(
        &self,
        account_id: &str,
        lamport: u64,
        bundle: &StoredAccountBundle,
    ) -> Result<bool> {
        let updated_at = now_ms() as i64;
        let conn = self.conn.lock().unwrap();
        let existing_lamport = conn
            .query_row(
                "SELECT payload FROM account_bundles WHERE account_id = ?1",
                params![account_id],
                |r| r.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .and_then(|payload| payload_lamport(&payload));
        if let Some(stored) = existing_lamport
            && lamport <= stored
        {
            return Ok(false);
        }
        conn.execute(
            "INSERT INTO account_bundles (account_id, updated_at, payload, signature)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_id) DO UPDATE SET
               updated_at = excluded.updated_at,
               payload    = excluded.payload,
               signature  = excluded.signature",
            params![account_id, updated_at, bundle.payload, bundle.signature],
        )?;
        Ok(true)
    }

    /// Returns the stored bundle for `account_id`, or `None` if unknown.
    pub fn get_account(&self, account_id: &str) -> Result<Option<StoredAccountBundle>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT payload, signature, updated_at FROM account_bundles
                 WHERE account_id = ?1",
                params![account_id],
                |r| {
                    Ok(StoredAccountBundle {
                        payload: r.get::<_, Vec<u8>>(0)?,
                        signature: r.get::<_, Vec<u8>>(1)?,
                        updated_at: r.get::<_, i64>(2)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Drops account bundles that have not been refreshed within `retention`.
    pub fn prune_accounts(&self, retention: Duration) -> Result<()> {
        let cutoff_ms = now_ms().saturating_sub(retention.as_millis() as u64) as i64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM account_bundles WHERE updated_at < ?1",
            params![cutoff_ms],
        )?;
        Ok(())
    }

    /// Drops bundles older than `retention` and keeps at most
    /// `max_per_identity` per `device_id` — each device's history is bounded
    /// independently.
    pub fn prune_key_packages(&self, max_per_identity: usize, retention: Duration) -> Result<()> {
        let cutoff_ms = now_ms().saturating_sub(retention.as_millis() as u64) as i64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM keypackages WHERE received_at < ?1",
            params![cutoff_ms],
        )?;
        conn.execute(
            "DELETE FROM keypackages
             WHERE rowid IN (
               SELECT rowid FROM (
                 SELECT rowid,
                        ROW_NUMBER() OVER (
                          PARTITION BY device_id
                          ORDER BY received_at DESC
                        ) AS rn
                 FROM keypackages
               )
               WHERE rn > ?1
             )",
            params![max_per_identity as i64],
        )?;
        Ok(())
    }
}

/// Domain-separation prefix on every account-device-bundle payload. Must stay in
/// sync with `account_directory::BUNDLE_DOMAIN` in the conversations crate; this
/// throwaway service deliberately has no libchat-core dependency, so the constant
/// is duplicated here rather than imported.
const BUNDLE_DOMAIN: &[u8] = b"libchat:account-device-bundle\0";

/// Extract the lamport version from a bundle payload without otherwise
/// interpreting it. The canonical layout (owned by the conversations crate's
/// `encode_bundle_payload`) is `domain | version:u8 | lamport:u64 LE | …`, so the
/// lamport sits in the 8 bytes right after the domain prefix and version byte.
/// Returns `None` when the domain prefix is absent or the payload is too short to
/// contain a header — the handler treats either as a malformed request.
pub fn payload_lamport(payload: &[u8]) -> Option<u64> {
    payload
        .strip_prefix(BUNDLE_DOMAIN)?
        .get(1..9)
        .map(|b| u64::from_le_bytes(b.try_into().expect("1..9 is 8 bytes")))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal stand-in for a real bundle payload: the domain prefix plus the
    /// header fields the server reads (`version:u8 | lamport:u64 LE`), no device
    /// keys needed.
    fn payload_with_lamport(lamport: u64) -> Vec<u8> {
        let mut p = BUNDLE_DOMAIN.to_vec();
        p.push(1u8); // version
        p.extend_from_slice(&lamport.to_le_bytes());
        p
    }

    fn bundle(lamport: u64) -> StoredAccountBundle {
        StoredAccountBundle {
            payload: payload_with_lamport(lamport),
            signature: vec![0u8; 64],
            updated_at: 0,
        }
    }

    fn upsert(store: &Store, account: &str, lamport: u64) -> bool {
        store
            .upsert_account(account, lamport, &bundle(lamport))
            .unwrap()
    }

    #[test]
    fn rejects_replayed_or_stale_lamport() {
        let store = Store::open(Path::new(":memory:")).unwrap();

        // First publish is always accepted.
        assert!(upsert(&store, "acct", 5));
        // A strictly higher lamport replaces it.
        assert!(upsert(&store, "acct", 6));
        // Re-publishing the same lamport (a replay) is rejected.
        assert!(!upsert(&store, "acct", 6));
        // An older lamport (a downgrade) is rejected.
        assert!(!upsert(&store, "acct", 4));

        // The stored bundle is still the newest one accepted.
        let stored = store.get_account("acct").unwrap().unwrap();
        assert_eq!(payload_lamport(&stored.payload), Some(6));
    }

    #[test]
    fn stale_publish_does_not_refresh_retention_clock() {
        let store = Store::open(Path::new(":memory:")).unwrap();
        assert!(upsert(&store, "acct", 9));
        let after_first = store.get_account("acct").unwrap().unwrap().updated_at;

        // A rejected (stale) publish must not bump updated_at, so a replay can't
        // keep a stale bundle alive past the retention window.
        assert!(!upsert(&store, "acct", 9));
        let after_replay = store.get_account("acct").unwrap().unwrap().updated_at;
        assert_eq!(after_first, after_replay);
    }

    #[test]
    fn payload_lamport_requires_domain_and_full_header() {
        assert_eq!(payload_lamport(&payload_with_lamport(42)), Some(42));
        // Missing the domain prefix → unparseable.
        assert_eq!(payload_lamport(&[1u8, 0, 0, 0, 0, 0, 0, 0, 0]), None);
        // Has the domain but is too short for version + u64 → unparseable.
        let mut short = BUNDLE_DOMAIN.to_vec();
        short.push(1u8);
        assert_eq!(payload_lamport(&short), None);
    }
}
