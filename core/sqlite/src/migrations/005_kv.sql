-- Scoped key-value substrate for state owned by conversation types
-- Migration: 005_kv

-- Protocol-level state takes the empty instance: SQLite never equates two NULLs
-- inside a primary key, so a NULL instance would duplicate rows on upsert.
CREATE TABLE IF NOT EXISTS kv (
    ns TEXT NOT NULL,
    instance BLOB NOT NULL,
    key BLOB NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (ns, instance, key)
);
