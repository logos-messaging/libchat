-- Backing table for the OpenMLS StorageProvider (SqliteMlsStorage).
--
-- A byte-faithful mirror of openmls_memory_storage's HashMap<Vec<u8>, Vec<u8>>:
-- `key` is `label ++ serde_json(logical_key) ++ version_be`, `value` is the
-- serde_json blob (a single value, or a JSON array for the two list labels).
CREATE TABLE IF NOT EXISTS mls_kv (
    key   BLOB PRIMARY KEY,
    value BLOB NOT NULL
);
