-- Conversations metadata
-- Migration: 003_conversations

CREATE TABLE IF NOT EXISTS conversations (
    local_convo_id TEXT PRIMARY KEY,
    remote_convo_id TEXT NOT NULL,
    convo_type TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);
