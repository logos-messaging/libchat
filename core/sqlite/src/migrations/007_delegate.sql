-- The delegate signer this installation acts with (single row)
-- Migration: 007_delegate

CREATE TABLE IF NOT EXISTS delegate (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    seed BLOB NOT NULL,
    account_addr TEXT NOT NULL
);
