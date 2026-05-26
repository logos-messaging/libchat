//! Causal-history tracking for group conversations.
//!
//! Implements the *causal history* subset of the Scalable Data Sync (SDS)
//! protocol. Every outbound message carries a Lamport timestamp and the IDs of the
//! messages its sender had most recently seen. A receiver that finds a
//! referenced ID it has never delivered knows a message is missing.
//!
//! Scope:
//!  - assign a deterministic message ID + Lamport timestamp to outbound msgs
//!  - attach a bounded causal-history frontier to each outbound message
//!  - on receive, detect referenced-but-unseen message IDs (gaps)
//!
//! Out of scope here: bloom-filter acknowledgements,
//! resend / outgoing buffer, incoming reorder buffer, Store-based recovery.
//! This is detection only — an out-of-order message is still delivered to
//! the application, but the gap it implies is reported.
//!
//! State is in-memory and session-scoped, matching the crate's current
//! in-memory MLS state.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::rc::Rc;

use crate::errors::ChatError;
use crate::proto::{Bytes, HistoryEntry, ReliablePayload};
use crate::utils::{blake2b_hex, hash_size};

/// `hash_size::MessageId` is U32 (32 bytes) → 64 hex chars.
const MESSAGE_ID_HEX_LEN: usize = 64;

/// Frontier includes the message's metadata which can be referened by other
/// messages inside a conversation.
///
/// Carries the sender's `account_id` alongside a deterministic
/// content/Lamport hash, so receivers can attribute referenced-but-unseen
/// IDs to a peer without consulting local state. The sender component is a
/// **routing hint, not authoritative**: when a missing message is recovered,
/// authorship is verified against the MLS leaf credential.
///
/// Wire form: `sender_id || message_id`. The `message_id` is fixed-width,
/// so [`Frontier::decode`] splits from the end with no separator. The proto
/// field stays a `string`; this type is the internal representation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Frontier {
    sender_id: String,
    message_id: String,
}

impl Frontier {
    /// Derive a fresh `MessageId` for an outbound message.
    pub fn new(sender_id: String, message_id: String) -> Self {
        Self {
            sender_id,
            message_id,
        }
    }

    /// Parse a wire-form `message_id` into its components.
    pub fn decode(s: &str) -> Result<Self, ChatError> {
        if s.len() < MESSAGE_ID_HEX_LEN {
            return Err(ChatError::BadParsing("MessageId"));
        }
        let split = s.len() - MESSAGE_ID_HEX_LEN;
        Ok(Self {
            sender_id: s[..split].to_owned(),
            message_id: s[split..].to_owned(),
        })
    }

    /// Render to the wire-form string used by the `message_id` proto field.
    pub fn encode(&self) -> String {
        self.to_string()
    }

    /// Sender's `account_id`, verbatim. Treat as a routing hint only.
    pub fn sender_id(&self) -> &str {
        &self.sender_id
    }

    /// Deterministic hash of `(channel, sender, lamport, content)`.
    pub fn message_id(&self) -> &str {
        &self.message_id
    }
}

impl fmt::Display for Frontier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.sender_id, self.message_id)
    }
}

/// Number of most-recently-seen message IDs attached to each outbound message.
const CAUSAL_HISTORY_LEN: usize = 10;

/// A message detected as missing: referenced by a delivered message's causal
/// history but never seen locally.
///
/// This is the hook point for the future client event system (issue #97);
/// until that lands, callers drain these via [`CausalHistoryStore::take_missing`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingMessage {
    pub conversation_id: String,
    pub frontier: Frontier,
}

/// Per-conversation causal state.
#[derive(Debug, Default)]
struct ConvoState {
    /// Lamport logical clock.
    lamport_clock: i32,
    /// Every message ID delivered locally (own sends + received).
    seen: HashSet<Frontier>,
    /// Bounded frontier of recently-seen IDs (oldest first) attached to
    /// outbound messages as causal history.
    frontiers: VecDeque<Frontier>,
    /// Missing IDs already reported, so a gap is surfaced exactly once.
    reported_missing: HashSet<Frontier>,
}

impl ConvoState {
    fn record_seen(&mut self, id: Frontier) {
        if self.seen.insert(id.clone()) {
            self.frontiers.push_back(id);
            while self.frontiers.len() > CAUSAL_HISTORY_LEN {
                self.frontiers.pop_front();
            }
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    convos: HashMap<String, ConvoState>,
    /// Detected gaps, drained by the client (future #97 event bus).
    missing: Vec<MissingMessage>,
}

/// Session-scoped causal-history store shared by every `GroupV1Convo`
/// instance.
///
/// Convos are rebuilt from storage on every inbound message, so this state
/// cannot live on the convo struct — it is shared through `InboxV2`, the
/// same way the MLS provider is.
#[derive(Debug, Clone, Default)]
pub struct CausalHistoryStore {
    inner: Rc<RefCell<Inner>>,
}

impl CausalHistoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the reliability envelope for an outbound message: advance the
    /// Lamport clock, derive a deterministic ID, and attach the causal
    /// frontier.
    pub fn on_send(&self, conversation_id: &str, sender: &str, content: &[u8]) -> ReliablePayload {
        let mut inner = self.inner.borrow_mut();
        let state = inner.convos.entry(conversation_id.to_owned()).or_default();

        state.lamport_clock += 1;
        let lamport = state.lamport_clock;
        let message_id = derive_message_id(conversation_id, sender, lamport, content);
        let frontier = Frontier::new(sender.to_string(), message_id);

        let causal_history = state
            .frontiers
            .iter()
            .map(|f| HistoryEntry {
                message_id: f.encode(),
                retrieval_hint: Bytes::new(),
            })
            .collect();

        let wire_id = frontier.encode();
        // Our own message joins the seen-set so it appears in our future
        // causal history (and, later, so we can ack peers' references to it).
        state.record_seen(frontier);

        ReliablePayload {
            message_id: wire_id,
            channel_id: conversation_id.to_owned(),
            lamport_timestamp: lamport,
            causal_history,
            bloom_filter: Bytes::new(),
            content: Bytes::copy_from_slice(content),
        }
    }

    /// Process an inbound reliability envelope. Records the message as seen,
    /// merges the Lamport clock, and returns any referenced message IDs that
    /// were never delivered locally (newly detected gaps).
    pub fn on_receive(
        &self,
        conversation_id: &str,
        payload: &ReliablePayload,
    ) -> Result<Vec<MissingMessage>, ChatError> {
        let mut inner = self.inner.borrow_mut();
        let Inner { convos, missing } = &mut *inner;
        let state = convos.entry(conversation_id.to_owned()).or_default();

        // Lamport merge: the next local send will be strictly greater than
        // anything we have observed.
        state.lamport_clock = state.lamport_clock.max(payload.lamport_timestamp);

        let mut detected = Vec::new();
        for entry in &payload.causal_history {
            let id = Frontier::decode(&entry.message_id)?;
            if !state.seen.contains(&id) && state.reported_missing.insert(id.clone()) {
                let m = MissingMessage {
                    conversation_id: conversation_id.to_owned(),
                    frontier: id,
                };
                detected.push(m.clone());
                missing.push(m);
            }
        }

        state.record_seen(Frontier::decode(&payload.message_id)?);
        Ok(detected)
    }

    /// Drain all gaps detected so far.
    ///
    /// This is the integration point for the client event system (issue
    /// #97); until that lands, callers poll here.
    pub fn take_missing(&self) -> Vec<MissingMessage> {
        std::mem::take(&mut self.inner.borrow_mut().missing)
    }
}

/// Deterministic, collision-resistant message ID.
///
/// A single sender increments its Lamport clock on every send, so
/// `(sender, lamport)` is unique per message; `channel_id` and `content` are
/// folded in as well. Receivers store the field verbatim, so cross-peer
/// agreement does not depend on re-derivation.
fn derive_message_id(channel_id: &str, sender: &str, lamport: i32, content: &[u8]) -> String {
    let lamport_be = lamport.to_be_bytes();
    blake2b_hex::<hash_size::MessageId>(&[
        b"deterministic_frame_id|".as_slice(),
        channel_id.as_bytes(),
        b"|".as_slice(),
        sender.as_bytes(),
        b"|".as_slice(),
        lamport_be.as_slice(),
        b"|".as_slice(),
        content,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(
        store: &CausalHistoryStore,
        convo: &str,
        sender: &str,
        body: &[u8],
    ) -> ReliablePayload {
        store.on_send(convo, sender, body)
    }

    #[test]
    fn lamport_clock_increments_per_send() {
        let s = CausalHistoryStore::new();
        let a = payload(&s, "c", "alice", b"1");
        let b = payload(&s, "c", "alice", b"2");
        assert_eq!(a.lamport_timestamp, 1);
        assert_eq!(b.lamport_timestamp, 2);
        // Second message's causal history references the first.
        assert_eq!(b.causal_history.len(), 1);
        assert_eq!(b.causal_history[0].message_id, a.message_id);
    }

    #[test]
    fn detects_a_gap_when_a_referenced_message_was_never_seen() {
        let sender = CausalHistoryStore::new();
        let m1 = payload(&sender, "c", "alice", b"first");
        let m2 = payload(&sender, "c", "alice", b"second (dropped)");
        let m3 = payload(&sender, "c", "alice", b"third");

        let receiver = CausalHistoryStore::new();
        assert!(receiver.on_receive("c", &m1).unwrap().is_empty());
        // m2 is never delivered to the receiver; m3 references it.
        let missing = receiver.on_receive("c", &m3).unwrap();

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].frontier.encode(), m2.message_id);
        assert_eq!(missing[0].conversation_id, "c");
    }

    #[test]
    fn no_gap_when_all_messages_are_delivered_in_order() {
        let sender = CausalHistoryStore::new();
        let m1 = payload(&sender, "c", "alice", b"a");
        let m2 = payload(&sender, "c", "alice", b"b");

        let receiver = CausalHistoryStore::new();
        receiver.on_receive("c", &m1).unwrap();
        receiver.on_receive("c", &m2).unwrap();
        assert!(receiver.take_missing().is_empty());
    }

    #[test]
    fn message_id_carries_account_id_verbatim() {
        let s = CausalHistoryStore::new();
        let a = payload(&s, "c", "alice", b"1");
        let b = payload(&s, "c", "alice", b"2");
        let c = payload(&s, "c", "bob", b"3");

        assert_eq!(
            Frontier::decode(&a.message_id).unwrap().sender_id(),
            "alice"
        );
        assert_eq!(
            Frontier::decode(&b.message_id).unwrap().sender_id(),
            "alice"
        );
        assert_eq!(Frontier::decode(&c.message_id).unwrap().sender_id(), "bob");
    }

    #[test]
    fn missing_message_carries_sender_id_of_the_original_author() {
        let alice = CausalHistoryStore::new();
        let m1 = payload(&alice, "c", "alice", b"first");
        let _m2 = payload(&alice, "c", "alice", b"second (dropped)");
        let m3 = payload(&alice, "c", "alice", b"third");

        let receiver = CausalHistoryStore::new();
        receiver.on_receive("c", &m1).unwrap();
        let missing = receiver.on_receive("c", &m3).unwrap();

        assert_eq!(missing.len(), 1);
        assert_eq!(missing[0].frontier.sender_id(), "alice");
    }

    #[test]
    fn decode_rejects_input_shorter_than_the_body_hash() {
        assert!(Frontier::decode("too short").is_err());
    }

    #[test]
    fn a_gap_is_reported_only_once() {
        let sender = CausalHistoryStore::new();
        let m1 = payload(&sender, "c", "alice", b"a");
        let m2 = payload(&sender, "c", "alice", b"b");
        let m3 = payload(&sender, "c", "alice", b"c");

        let receiver = CausalHistoryStore::new();
        // Neither m1 nor m2 delivered; both m2 and m3 reference m1.
        receiver.on_receive("c", &m2).unwrap();
        receiver.on_receive("c", &m3).unwrap();
        let missing = receiver.take_missing();
        let m1_hits = missing
            .iter()
            .filter(|m| m.frontier.encode() == m1.message_id)
            .count();
        assert_eq!(m1_hits, 1);
    }
}
