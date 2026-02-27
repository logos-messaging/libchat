-- Initial schema for chat storage
-- Migration: 001_initial_schema

-- Identity table (single row)
CREATE TABLE IF NOT EXISTS identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    secret_key BLOB NOT NULL
);

-- Inbox ephemeral keys for handshakes
CREATE TABLE IF NOT EXISTS inbox_keys (
    public_key_hex TEXT PRIMARY KEY,
    secret_key BLOB NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

-- Chat metadata
CREATE TABLE IF NOT EXISTS chats (
    chat_id TEXT PRIMARY KEY,
    chat_type TEXT NOT NULL,
    remote_public_key BLOB,
    remote_address TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_chats_type ON chats(chat_type);
