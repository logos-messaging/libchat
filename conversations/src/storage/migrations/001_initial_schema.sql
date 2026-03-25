-- Initial schema for chat storage
-- Migration: 001_initial_schema

-- Identity table (single row)
CREATE TABLE IF NOT EXISTS identity (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    name TEXT NOT NULL,
    secret_key BLOB NOT NULL
);
