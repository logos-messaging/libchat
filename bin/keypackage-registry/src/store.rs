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
    /// 32-byte Ed25519 verifying key identifying the submitting device.
    /// An `account_id` may have multiple devices, each with its own key.
    pub device_pubkey: Vec<u8>,
    pub key_package: Vec<u8>,
    pub timestamp_ms: u64,
    /// 64-byte Ed25519 signature by `device_pubkey` over
    /// `account_id || device_pubkey || key_package || timestamp_ms_le`.
    /// Stored as opaque bytes — the server does not verify; consumers do.
    pub signature: Vec<u8>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("open sqlite")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS keypackages (
                account_id    TEXT NOT NULL,
                device_pubkey BLOB NOT NULL,
                received_at   INTEGER NOT NULL,
                timestamp_ms  INTEGER NOT NULL,
                key_package   BLOB NOT NULL,
                signature     BLOB NOT NULL,
                PRIMARY KEY (account_id, device_pubkey, received_at)
            );
            CREATE INDEX IF NOT EXISTS kp_account_recv
                ON keypackages(account_id, received_at DESC);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn insert(&self, account_id: &str, bundle: &StoredBundle) -> Result<()> {
        let received_at = now_ms() as i64;
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO keypackages
               (account_id, device_pubkey, received_at, timestamp_ms, key_package, signature)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                account_id,
                bundle.device_pubkey,
                received_at,
                bundle.timestamp_ms as i64,
                bundle.key_package,
                bundle.signature
            ],
        )?;
        Ok(())
    }

    /// Returns the most recently received bundle for `account_id`, across all
    /// devices. Scope A: chat layer assumes one device per account, so a
    /// single bundle is sufficient. When multi-device fanout lands, switch
    /// this to `latest_per_device` returning a `Vec<StoredBundle>`.
    pub fn latest(&self, account_id: &str) -> Result<Option<StoredBundle>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT device_pubkey, key_package, timestamp_ms, signature FROM keypackages
                 WHERE account_id = ?1
                 ORDER BY received_at DESC
                 LIMIT 1",
                params![account_id],
                |r| {
                    Ok(StoredBundle {
                        device_pubkey: r.get::<_, Vec<u8>>(0)?,
                        key_package: r.get::<_, Vec<u8>>(1)?,
                        timestamp_ms: r.get::<_, i64>(2)? as u64,
                        signature: r.get::<_, Vec<u8>>(3)?,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Drops bundles older than `retention` and keeps at most
    /// `max_per_identity` per (account_id, device_pubkey) — each device's
    /// history is bounded independently.
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
                          PARTITION BY account_id, device_pubkey
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
