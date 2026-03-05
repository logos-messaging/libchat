//! Database migrations module.
//!
//! SQL migrations are embedded at compile time and applied in order.
//! Each migration is applied atomically within a transaction.

use storage::{Connection, StorageError};

/// Embeds and returns all migration SQL files in order.
pub fn get_migrations() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "001_initial_schema",
            include_str!("migrations/001_initial_schema.sql"),
        ),
        (
            "002_ephemeral_keys",
            include_str!("migrations/002_ephemeral_keys.sql"),
        ),
    ]
}

/// Applies all migrations to the database.
///
/// Uses a simple version tracking table to avoid re-running migrations.
pub fn apply_migrations(conn: &mut Connection) -> Result<(), StorageError> {
    // Create migrations tracking table if it doesn't exist
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS _migrations (
            name TEXT PRIMARY KEY,
            applied_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
        );",
    )?;

    for (name, sql) in get_migrations() {
        // Check if migration already applied
        let already_applied: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM _migrations WHERE name = ?1)",
            [name],
            |row| row.get(0),
        )?;

        if !already_applied {
            // Apply migration and record it atomically in a transaction
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute("INSERT INTO _migrations (name) VALUES (?1)", [name])?;
            tx.commit()?;
        }
    }

    Ok(())
}
