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
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).context("open sqlite")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS keypackages (
                account_id   TEXT NOT NULL,
                received_at  INTEGER NOT NULL,
                timestamp_ms INTEGER NOT NULL,
                key_package  BLOB NOT NULL,
                PRIMARY KEY (account_id, received_at)
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
            "INSERT INTO keypackages (account_id, received_at, timestamp_ms, key_package)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                account_id,
                received_at,
                bundle.timestamp_ms as i64,
                bundle.key_package
            ],
        )?;
        Ok(())
    }

    /// Returns the most recently received bundle for `account_id`, if any.
    pub fn latest(&self, account_id: &str) -> Result<Option<StoredBundle>> {
        let conn = self.conn.lock().unwrap();
        let row = conn
            .query_row(
                "SELECT key_package, timestamp_ms FROM keypackages
                 WHERE account_id = ?1
                 ORDER BY received_at DESC
                 LIMIT 1",
                params![account_id],
                |r| {
                    Ok(StoredBundle {
                        key_package: r.get::<_, Vec<u8>>(0)?,
                        timestamp_ms: r.get::<_, i64>(1)? as u64,
                    })
                },
            )
            .optional()?;
        Ok(row)
    }

    /// Drops bundles older than `retention` and keeps at most `max_per_identity`
    /// per account_id.
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
                          PARTITION BY account_id
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
