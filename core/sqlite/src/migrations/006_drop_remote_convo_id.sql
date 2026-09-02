-- A conversation record is its local id and its kind
-- Migration: 006_drop_remote_convo_id

ALTER TABLE conversations DROP COLUMN remote_convo_id;
