use std::time::{SystemTime, UNIX_EPOCH};

pub fn timestamp_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

/// Track hash sizes in use across the crate.
pub mod hash_size {
    use blake2::digest::{
        consts::U64,
        generic_array::ArrayLength,
        typenum::{IsLessOrEqual, NonZero},
    };

    pub trait HashLen
    where
        <Self::Size as IsLessOrEqual<U64>>::Output: NonZero,
    {
        type Size: ArrayLength<u8> + IsLessOrEqual<U64>;
    }

    /// This macro generates HashLen for the given typenum::length
    macro_rules! hash_sizes {
        ($($(#[$attr:meta])* $name:ident => $size:ty),* $(,)?) => {
            $(
                $(#[$attr])*
                pub struct $name;
                impl HashLen for $name { type Size = $size; }
            )*
        };
    }

    use blake2::digest::consts::{U4, U8, U18};
    hash_sizes! {
        /// Generic hash size for tests and debug
        Testing  => U4,
        /// Account ID hash length
        AccountId => U8,
        ConversationId => U18,
    }
}

use blake2::{Blake2b, Digest};
/// This establishes an easy to use wrapper for hashes in this crate.
/// The output is formatted string of hex characters
pub fn blake2b_hex<LEN: hash_size::HashLen>(components: &[impl AsRef<[u8]>]) -> String {
    //A
    let mut hash = Blake2b::<LEN::Size>::new();

    for c in components {
        hash.update(c);
    }

    let output = hash.finalize();
    hex::encode(output)
}

pub fn hex_trunc(data: &[u8]) -> String {
    if data.len() <= 8 {
        hex::encode(data)
    } else {
        format!(
            "{}..{}",
            hex::encode(&data[..4]),
            hex::encode(&data[data.len() - 4..])
        )
    }
}
