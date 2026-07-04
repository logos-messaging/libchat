//! Signed account operation log: the append-only record of an account's
//! associated key and data.
//!
//! ```text
//! SignedAccountLog          payload + account signature over its exact bytes
//! └── EncodedAccountLog     the log as canonical bytes (wire form — see codec)
//!     └── AccountLog        the log as validated entries (working form)
//!         └── AccountEntry      Add(EntryData) | Remove { index }
//!             └── EntryData     Ed25519Key | Text
//! ```
//!
//! Invariants:
//! - Append-only: a newer log strictly extends the older one
//!   ([`verify_extension`](crate::verify_extension)). There is no version
//!   counter — a longer log is a newer log. A log that is longer but does not
//!   extend the old one has rewritten history: either the signer is showing
//!   different histories to different readers, or the account key is
//!   compromised.
//! - A `Remove` tombstones a strictly earlier, still-live `Add`; anything else
//!   rejects the whole log — fail closed ([`AccountLog::new`]).
//!
//! Replaying ([`AccountLog::live_entries`]) yields the account's current state.

use crypto::Ed25519Signature;

use crate::error::AccountLogError;

/// An [`AccountLog`] in its canonical byte encoding, plus the account's
/// signature over exactly those bytes.
///
/// The account key is not carried: the account address *is* the verifying key,
/// supplied by the caller on verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAccountLog {
    pub payload: EncodedAccountLog,
    pub signature: Ed25519Signature,
}

/// An [`AccountLog`] as canonical bytes — exactly what is signed and
/// transmitted. Holding one proves the bytes decode to a valid log: construct
/// via [`AccountLog::encode`] or [`parse`](Self::parse). Byte layout: see
/// [`AccountLog::encode`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAccountLog(pub(crate) Vec<u8>);

/// The log as a validated entry list. Construction checks every `Remove`, so
/// a held log always replays ([`live_entries`](Self::live_entries) cannot
/// fail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountLog {
    entries: Vec<AccountEntry>,
}

/// One operation in the log. An entry's index is its position — derived, not
/// stored, so an entry cannot lie about where it sits. One enum rather than
/// separate op/data fields: illegal combinations are unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountEntry {
    /// Endorse new data under this account.
    Add(EntryData),
    /// Tombstone the `Add` at position `index`. Must point at a strictly
    /// earlier, still-live `Add`; anything else rejects the whole log —
    /// fail closed, so verifiers can never skip their way to different sets.
    Remove { index: u32 },
}

/// Data an account can endorse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryData {
    /// A device (LocalIdentity) verifying key.
    Ed25519Key([u8; 32]),
    /// An arbitrary UTF-8 record.
    Text(String),
}

impl AccountLog {
    /// Validate `entries` as a log (see [`AccountEntry::Remove`]).
    /// [`EncodedAccountLog::parse`] applies the same gate to received bytes,
    /// so a broken log — un-rewritable once published — never gets published.
    pub fn new(entries: Vec<AccountEntry>) -> Result<Self, AccountLogError> {
        removed_flags(&entries)?;
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[AccountEntry] {
        &self.entries
    }

    /// Replay the log into its live entry set — the account's current state,
    /// in add order.
    pub fn live_entries(&self) -> Vec<EntryData> {
        let removed = removed_flags(&self.entries).expect("validated at construction");
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, entry)| match entry {
                AccountEntry::Add(data) if !removed[i] => Some(data.clone()),
                _ => None,
            })
            .collect()
    }
}

/// Which entries have been tombstoned, or the `Remove` that broke the log.
/// `index < position` means every target was already seen: single-pass.
fn removed_flags(entries: &[AccountEntry]) -> Result<Vec<bool>, AccountLogError> {
    let mut removed = vec![false; entries.len()];
    for (position, entry) in entries.iter().enumerate() {
        let AccountEntry::Remove { index } = entry else {
            continue;
        };
        let target = *index as usize;
        let targets_live_add = target < position
            && !removed[target]
            && matches!(entries[target], AccountEntry::Add(_));
        if !targets_live_add {
            return Err(AccountLogError::InvalidRemove {
                position,
                index: *index,
            });
        }
        removed[target] = true;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> AccountEntry {
        AccountEntry::Add(EntryData::Ed25519Key([byte; 32]))
    }

    /// Replay applies tombstones and preserves add order.
    #[test]
    fn live_entries_applies_removes() {
        let log = AccountLog::new(vec![
            key(1),
            AccountEntry::Add(EntryData::Text("name".into())),
            AccountEntry::Remove { index: 0 },
            key(2),
        ])
        .unwrap();
        assert_eq!(
            log.live_entries(),
            vec![
                EntryData::Text("name".into()),
                EntryData::Ed25519Key([2; 32]),
            ]
        );
    }

    /// Every malformed remove rejects the whole log: forward and self
    /// references, removing a remove, and removing twice.
    #[test]
    fn new_rejects_invalid_removes() {
        let dangling = vec![key(1), AccountEntry::Remove { index: 7 }];
        let self_ref = vec![AccountEntry::Remove { index: 0 }];
        let of_remove = vec![
            key(1),
            AccountEntry::Remove { index: 0 },
            AccountEntry::Remove { index: 1 },
        ];
        let twice = vec![
            key(1),
            AccountEntry::Remove { index: 0 },
            AccountEntry::Remove { index: 0 },
        ];
        for entries in [dangling, self_ref, of_remove, twice] {
            assert!(matches!(
                AccountLog::new(entries),
                Err(AccountLogError::InvalidRemove { .. })
            ));
        }
    }
}
