-- Ephemeral keys for inbox handshakes
-- Migration: 002_ephemeral_keys

CREATE TABLE IF NOT EXISTS ephemeral_keys (
    public_key_hex TEXT PRIMARY KEY,
    secret_key BLOB NOT NULL
);
