//! What a GroupV2 conversation reports about running itself.
//!
//! de-mls narrates its own commit-and-recovery cycle alongside the messages it
//! decrypts. None of it is content and none of it needs acting on, but it is
//! the only account of why a group is or is not moving, so it is buffered here
//! and drained by the client the same way causal-history observations are.

use std::cell::RefCell;

use crate::core::ConversationId;

/// The phase of a GroupV2 conversation's commit-and-recovery cycle.
pub use de_mls::ConversationState as GroupV2Phase;

/// One report from a GroupV2 conversation.
#[derive(Debug, Clone)]
pub struct GroupV2Status {
    pub convo_id: ConversationId,
    pub kind: GroupV2StatusKind,
}

#[derive(Debug, Clone)]
pub enum GroupV2StatusKind {
    /// The conversation entered a new phase.
    Phase(GroupV2Phase),
    /// `received` of `expected` stewards' commit candidates have arrived for
    /// the round in progress; reported again whenever the count changes. A
    /// round that ends with fewer than it expected is one where the members
    /// chose from different sets of candidates.
    CommitRound { received: usize, expected: usize },
    /// A step the conversation was carrying out on its own, such as submitting
    /// a vote, did not go through. The conversation stays usable.
    Failed { operation: String, message: String },
}

/// Session-scoped buffer for [`GroupV2Status`], shared through
/// `ServiceContext` because conversations are rebuilt from storage on every
/// inbound payload and cannot hold it themselves.
#[derive(Debug, Default)]
pub(crate) struct GroupV2StatusStore {
    reports: RefCell<Vec<GroupV2Status>>,
}

impl GroupV2StatusStore {
    pub(crate) fn record(&self, convo_id: &str, kind: GroupV2StatusKind) {
        self.reports.borrow_mut().push(GroupV2Status {
            convo_id: convo_id.to_owned(),
            kind,
        });
    }

    pub(crate) fn take(&self) -> Vec<GroupV2Status> {
        std::mem::take(&mut self.reports.borrow_mut())
    }
}
