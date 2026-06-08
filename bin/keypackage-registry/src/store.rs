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
/// `PUT` replaces the old one. `payload` is opaque to the server — it is
/// expected to encode a lamport-timestamped list of device pubkeys signed by
/// the account key so that consumers can verify freshness.
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
    /// exactly one blob per account; this replaces any previously stored value.
    ///
    /// Note: because `payload` is opaque, the server cannot enforce that a new
    /// bundle is fresher (higher lamport timestamp) than the stored one, so a
    /// still-valid older bundle could be replayed to downgrade the device list.
    /// Acceptable per issue #111 — account-service security is out of scope for
    /// testnet — and the `updated_at` argument is ignored, the store stamps the
    /// row with the current time.
    pub fn upsert_account(&self, account_id: &str, bundle: &StoredAccountBundle) -> Result<()> {
        let updated_at = now_ms() as i64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO account_bundles (account_id, updated_at, payload, signature)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(account_id) DO UPDATE SET
               updated_at = excluded.updated_at,
               payload    = excluded.payload,
               signature  = excluded.signature",
            params![account_id, updated_at, bundle.payload, bundle.signature],
        )?;
        Ok(())
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

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
