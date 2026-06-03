use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, OptionalExtension, params};

pub struct Store {
    conn: Mutex<Connection>,
}

#[derive(Debug, Clone)]
pub struct StoredBundle {
    pub key_package: Vec<u8>,
    pub timestamp_ms: u64,
    /// 64-byte Ed25519 signature by the device key over
    /// `device_id || key_package || timestamp_ms_le`.
    /// Stored as opaque bytes — consumers verify on retrieve.
    pub signature: Vec<u8>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        // Create the db's parent directory if the caller pointed at a nested
        // path (e.g. `tmp/registry.db`); SQLite won't create it and errors with
        // "unable to open database file" otherwise.
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("create db directory {}", parent.display()))?;
            }
        }
        let conn = Connection::open(path).context("open sqlite")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS keypackages (
                device_id     TEXT NOT NULL,
                received_at   INTEGER NOT NULL,
                timestamp_ms  INTEGER NOT NULL,
                key_package   BLOB NOT NULL,
                signature     BLOB NOT NULL,
                PRIMARY KEY (device_id, received_at)
            );",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert(&self, device_id: &str, bundle: &StoredBundle) -> Result<()> {
        let received_at = now_ms() as i64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO keypackages
               (device_id, received_at, timestamp_ms, key_package, signature)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                device_id,
                received_at,
                bundle.timestamp_ms as i64,
                bundle.key_package,
                bundle.signature
            ],
        )?;
        Ok(())
    }

    /// Returns the most recently received bundle for `device_id`. Scope A: the
    /// chat layer consumes one bundle per device. When multi-keypackage fanout
    /// lands, switch this to return a `Vec<StoredBundle>`.
    pub fn latest(&self, device_id: &str) -> Result<Option<StoredBundle>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT key_package, timestamp_ms, signature FROM keypackages
                 WHERE device_id = ?1
                 ORDER BY received_at DESC
                 LIMIT 1",
                params![device_id],
                |r| {
                    Ok(StoredBundle {
                        key_package: r.get::<_, Vec<u8>>(0)?,
                        timestamp_ms: r.get::<_, i64>(1)? as u64,
                        signature: r.get::<_, Vec<u8>>(2)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Drops bundles older than `retention` and keeps at most
    /// `max_per_identity` per `device_id` — each device's history is bounded
    /// independently.
    pub fn prune(&self, max_per_identity: usize, retention: Duration) -> Result<()> {
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
