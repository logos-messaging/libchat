use std::time::{SystemTime, UNIX_EPOCH};

use rand_core::OsRng;
use x25519_dalek::StaticSecret;

pub fn timestamp_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Generate a unique chat ID using random bytes.
pub fn generate_chat_id() -> String {
    let secret = StaticSecret::random_from_rng(OsRng);
    hex::encode(&secret.as_bytes()[..16])
}
