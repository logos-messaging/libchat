//! Wire format for [`EncodedAccountLog`]: the canonical byte encoding of an
//! [`AccountLog`]. Encoding and decoding live together so they cannot drift
//! apart. The bytes are opaque to the server except for the fixed-offset
//! header the extension check reads.

use crypto::Ed25519VerifyingKey;

use crate::error::AccountLogError;
use crate::account_log::{AccountEntry, AccountLog, EncodedAccountLog, EntryData, SignedAccountLog};

/// Domain-separation tag, prepended to every signed payload:
///
/// ```text
/// logos:accounts:<version>\0
/// ```
///
/// Binds the signature to this exact purpose; bump `<version>` on layout change.
pub const ACCOUNT_LOG_DOMAIN: &[u8] = b"logos:accounts:1\0";

/// [`ACCOUNT_LOG_DOMAIN`] without the version segment.
const DOMAIN_STEM: &[u8] = b"logos:accounts:";

// Entry wire tags. One tag byte determines exactly how many bytes follow, so
// every byte string parses one way.
const TAG_ADD: u8 = 1;
const TAG_REMOVE: u8 = 2;
const DATA_ED25519: u8 = 1;
const DATA_TEXT: u8 = 2;

/// Header bytes after the domain prefix: the entry count (u32 LE). The count
/// doubles as the freshness marker; u32 so no plausible client bug can
/// exhaust it (a u16 could be burned by a publish loop, and the counter has
/// no reset mechanism).
const HEADER: usize = 4;

impl AccountLog {
    /// Canonical binary encoding — the bytes that are both signed and
    /// transmitted:
    ///
    /// ```text
    /// domain  : ACCOUNT_LOG_DOMAIN            (constant prefix incl. version, NUL-terminated)
    /// count   : u32 LE    (4 bytes)   — number of entries that follow
    /// entries : count entries, each:
    ///   0x01 0x01 <32 bytes>              Add(Ed25519Key)
    ///   0x01 0x02 <u16 LE len> <bytes>    Add(Text), UTF-8
    ///   0x02 <u32 LE index>               Remove
    /// ```
    ///
    /// The account key is *not* embedded: the account is identified
    /// out-of-band by the account verifying key the caller requests, and
    /// [`verify_log`] checks the signature under that key — so a log for one
    /// account cannot be passed off as another's.
    pub fn encode(&self) -> EncodedAccountLog {
        let entries = self.entries();
        let mut out = Vec::with_capacity(ACCOUNT_LOG_DOMAIN.len() + HEADER + entries.len() * 34);
        out.extend_from_slice(ACCOUNT_LOG_DOMAIN);
        out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
        for entry in entries {
            match entry {
                AccountEntry::Add(EntryData::Ed25519Key(key)) => {
                    out.push(TAG_ADD);
                    out.push(DATA_ED25519);
                    out.extend_from_slice(key);
                }
                AccountEntry::Add(EntryData::Text(text)) => {
                    out.push(TAG_ADD);
                    out.push(DATA_TEXT);
                    out.extend_from_slice(&(text.len() as u16).to_le_bytes());
                    out.extend_from_slice(text.as_bytes());
                }
                AccountEntry::Remove { index } => {
                    out.push(TAG_REMOVE);
                    out.extend_from_slice(&index.to_le_bytes());
                }
            }
        }
        EncodedAccountLog(out)
    }
}

impl EncodedAccountLog {
    /// Validate received bytes: checks the domain prefix and version, parses
    /// exactly the declared number of entries with no bytes left over, and
    /// validates the log itself via [`AccountLog::new`].
    pub fn parse(bytes: Vec<u8>) -> Result<Self, AccountLogError> {
        AccountLog::new(decode_entries(&bytes)?)?;
        Ok(Self(bytes))
    }

    /// Decode. Cannot fail: construction validated the bytes.
    pub fn decode(&self) -> AccountLog {
        AccountLog::new(decode_entries(&self.0).expect("validated at construction"))
            .expect("validated at construction")
    }

    /// The exact bytes that are signed and transmitted.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The entry count from the header — the freshness marker.
    fn count(&self) -> u32 {
        let at = ACCOUNT_LOG_DOMAIN.len();
        u32::from_le_bytes(self.0[at..at + 4].try_into().expect("4 bytes"))
    }

    /// The entry bytes after the header — the region the extension check
    /// compares.
    fn entry_bytes(&self) -> &[u8] {
        &self.0[ACCOUNT_LOG_DOMAIN.len() + HEADER..]
    }
}

/// Decoder behind [`EncodedAccountLog::parse`] and [`EncodedAccountLog::decode`].
fn decode_entries(payload: &[u8]) -> Result<Vec<AccountEntry>, AccountLogError> {
    let payload = match payload.strip_prefix(ACCOUNT_LOG_DOMAIN) {
        Some(rest) => rest,
        None => return Err(domain_error(payload)),
    };
    if payload.len() < HEADER {
        return Err(AccountLogError::Short);
    }
    let count = u32::from_le_bytes(payload[..4].try_into().expect("4 bytes")) as usize;

    let mut body = &payload[HEADER..];
    let mut entries = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let (entry, rest) = decode_entry(body)?;
        entries.push(entry);
        body = rest;
    }
    if !body.is_empty() {
        return Err(AccountLogError::Trailing);
    }
    Ok(entries)
}

/// Parse one entry off the front of `body`, returning it and the rest.
fn decode_entry(body: &[u8]) -> Result<(AccountEntry, &[u8]), AccountLogError> {
    let (&tag, body) = body.split_first().ok_or(AccountLogError::Short)?;
    match tag {
        TAG_ADD => {
            let (&data_tag, body) = body.split_first().ok_or(AccountLogError::Short)?;
            match data_tag {
                DATA_ED25519 => {
                    let (key, rest) = split_at_checked(body, 32)?;
                    let key = key.try_into().expect("split yields 32 bytes");
                    Ok((AccountEntry::Add(EntryData::Ed25519Key(key)), rest))
                }
                DATA_TEXT => {
                    let (len, body) = split_at_checked(body, 2)?;
                    let len = u16::from_le_bytes(len.try_into().expect("2 bytes")) as usize;
                    let (text, rest) = split_at_checked(body, len)?;
                    let text = String::from_utf8(text.to_vec()).map_err(|_| AccountLogError::Utf8)?;
                    Ok((AccountEntry::Add(EntryData::Text(text)), rest))
                }
                other => Err(AccountLogError::Tag(other)),
            }
        }
        TAG_REMOVE => {
            let (index, rest) = split_at_checked(body, 4)?;
            let index = u32::from_le_bytes(index.try_into().expect("4 bytes"));
            Ok((AccountEntry::Remove { index }, rest))
        }
        other => Err(AccountLogError::Tag(other)),
    }
}

/// Classify a payload that failed the domain check: our stem with a different
/// version segment, or a foreign domain altogether.
fn domain_error(payload: &[u8]) -> AccountLogError {
    let Some(rest) = payload.strip_prefix(DOMAIN_STEM) else {
        return AccountLogError::Domain;
    };
    match rest.iter().take(16).position(|&b| b == 0) {
        Some(end) => AccountLogError::Version(String::from_utf8_lossy(&rest[..end]).into_owned()),
        None => AccountLogError::Domain,
    }
}

/// `split_at` that reports a truncated payload instead of panicking.
fn split_at_checked(body: &[u8], mid: usize) -> Result<(&[u8], &[u8]), AccountLogError> {
    if body.len() < mid {
        return Err(AccountLogError::Short);
    }
    Ok(body.split_at(mid))
}

/// Verify the account signature over the exact payload bytes, returning the
/// decoded log.
///
/// Verifying under the *requested* account key is what binds the log to that
/// account: another account's validly-signed log won't verify under this key,
/// so an untrusted server cannot substitute one.
pub fn verify_log(
    expected_account: &Ed25519VerifyingKey,
    log: &SignedAccountLog,
) -> Result<AccountLog, AccountLogError> {
    expected_account
        .verify(log.payload.as_bytes(), &log.signature)
        .map_err(|_| AccountLogError::SignatureInvalid)?;
    Ok(log.payload.decode())
}

/// Check that `new` strictly extends `old`: strictly more entries, and the old
/// entry bytes are a prefix of the new ones. (The count field itself changes
/// between versions, so the check is over the entry region, not the whole
/// payload.)
///
/// The server runs this on publish to refuse stale or rewritten logs, and
/// consumers run it against the last log they saw as defence in depth. It
/// compares bytes, so the server needs no knowledge of entry semantics.
pub fn verify_extension(old: &EncodedAccountLog, new: &EncodedAccountLog) -> Result<(), AccountLogError> {
    if new.count() <= old.count() {
        return Err(AccountLogError::NotLonger {
            old: old.count(),
            new: new.count(),
        });
    }
    if !new.entry_bytes().starts_with(old.entry_bytes()) {
        return Err(AccountLogError::Forked);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::Ed25519SigningKey;

    fn key(byte: u8) -> AccountEntry {
        AccountEntry::Add(EntryData::Ed25519Key([byte; 32]))
    }

    fn make_log(entries: Vec<AccountEntry>) -> AccountLog {
        AccountLog::new(entries).unwrap()
    }

    /// encode → decode round-trips, and parse accepts encode's bytes,
    /// including the empty log and every variant.
    #[test]
    fn payload_roundtrips() {
        let log = make_log(vec![
            key(1),
            AccountEntry::Add(EntryData::Text("display name".into())),
            AccountEntry::Remove { index: 0 },
            key(2),
        ]);
        let payload = log.encode();
        assert_eq!(payload.decode(), log);
        assert_eq!(
            EncodedAccountLog::parse(payload.as_bytes().to_vec()).unwrap(),
            payload
        );

        // Empty log is valid (an account with no entries yet).
        assert!(make_log(vec![]).encode().decode().entries().is_empty());
    }

    #[test]
    fn parse_rejects_short_and_truncated() {
        // A domain-prefixed payload too short to hold the header.
        let mut short = ACCOUNT_LOG_DOMAIN.to_vec();
        short.extend_from_slice(&[0u8; 3]);
        assert!(matches!(
            EncodedAccountLog::parse(short),
            Err(AccountLogError::Short)
        ));

        // Drop a key byte: the last entry no longer fits.
        let mut bytes = make_log(vec![key(1)]).encode().as_bytes().to_vec();
        bytes.pop();
        assert!(matches!(
            EncodedAccountLog::parse(bytes),
            Err(AccountLogError::Short)
        ));
    }

    #[test]
    fn parse_rejects_trailing_bytes() {
        let mut bytes = make_log(vec![key(1)]).encode().as_bytes().to_vec();
        bytes.push(0);
        assert!(matches!(
            EncodedAccountLog::parse(bytes),
            Err(AccountLogError::Trailing)
        ));
    }

    #[test]
    fn parse_rejects_missing_domain() {
        let payload = make_log(vec![]).encode();
        let without_domain = payload.as_bytes()[ACCOUNT_LOG_DOMAIN.len()..].to_vec();
        assert!(matches!(
            EncodedAccountLog::parse(without_domain),
            Err(AccountLogError::Domain)
        ));
    }

    #[test]
    fn parse_rejects_bad_version_and_tag() {
        let mut bytes = make_log(vec![]).encode().as_bytes().to_vec();
        bytes[ACCOUNT_LOG_DOMAIN.len() - 2] = b'9'; // the version character
        assert!(matches!(
            EncodedAccountLog::parse(bytes),
            Err(AccountLogError::Version(v)) if v == "9"
        ));

        let mut bytes = make_log(vec![key(1)]).encode().as_bytes().to_vec();
        bytes[ACCOUNT_LOG_DOMAIN.len() + HEADER] = 77; // first entry's tag byte
        assert!(matches!(
            EncodedAccountLog::parse(bytes),
            Err(AccountLogError::Tag(77))
        ));
    }

    /// Well-formed bytes carrying an invalid log (a self-referencing remove)
    /// are rejected at parse: broken logs never get past the boundary. Such
    /// bytes cannot be produced through the API, so they are handcrafted.
    #[test]
    fn parse_rejects_invalid_log() {
        let mut bytes = ACCOUNT_LOG_DOMAIN.to_vec();
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(TAG_REMOVE);
        bytes.extend_from_slice(&0u32.to_le_bytes()); // Remove{0} at position 0
        assert!(matches!(
            EncodedAccountLog::parse(bytes),
            Err(AccountLogError::InvalidRemove { .. })
        ));
    }

    /// Full happy path: sign with the account key, verify under the account key.
    #[test]
    fn verify_accepts_well_formed_log() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();
        let log = make_log(vec![key(1), key(2)]);

        let payload = log.encode();
        let signed = SignedAccountLog {
            signature: account_key.sign(payload.as_bytes()),
            payload,
        };

        assert_eq!(verify_log(&account_pub, &signed).unwrap(), log);
    }

    /// A log validly signed by account A, served as the answer to a query for
    /// account B, fails: B's key does not verify A's signature. This is the
    /// anti-substitution guarantee.
    #[test]
    fn verify_rejects_wrong_account() {
        let account_key = Ed25519SigningKey::generate();
        let payload = make_log(vec![]).encode();
        let signed = SignedAccountLog {
            signature: account_key.sign(payload.as_bytes()),
            payload,
        };

        let other = Ed25519SigningKey::generate().verifying_key();
        assert!(matches!(
            verify_log(&other, &signed),
            Err(AccountLogError::SignatureInvalid)
        ));
    }

    /// A signature over one entry list does not verify another.
    #[test]
    fn verify_rejects_swapped_payload() {
        let account_key = Ed25519SigningKey::generate();
        let account_pub = account_key.verifying_key();

        let signature = account_key.sign(make_log(vec![key(1)]).encode().as_bytes());
        let signed = SignedAccountLog {
            payload: make_log(vec![key(2)]).encode(),
            signature,
        };
        assert!(matches!(
            verify_log(&account_pub, &signed),
            Err(AccountLogError::SignatureInvalid)
        ));
    }

    /// Appending entries is an extension; anything else is stale or a fork.
    #[test]
    fn extension_accepts_appends_only() {
        let old = make_log(vec![key(1)]).encode();
        let new = make_log(vec![key(1), key(2)]).encode();
        verify_extension(&old, &new).unwrap();

        // Same length: stale, even with identical contents.
        assert!(matches!(
            verify_extension(&old, &old),
            Err(AccountLogError::NotLonger { old: 1, new: 1 })
        ));

        // Shrinking: stale.
        assert!(matches!(
            verify_extension(&new, &old),
            Err(AccountLogError::NotLonger { old: 2, new: 1 })
        ));

        // Longer but rewrites entry 0: fork.
        let fork = make_log(vec![key(3), key(2)]).encode();
        assert!(matches!(
            verify_extension(&old, &fork),
            Err(AccountLogError::Forked)
        ));
    }
}
