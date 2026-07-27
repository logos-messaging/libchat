//! Bundles the services a conversation operation needs into one [`ServiceContext`].

use std::time::Duration;

use crypto::Identity;
use storage::ChatStore;

use crate::IdentityProvider;
use crate::causal_history::CausalHistoryStore;
use crate::conversation::GroupV2Clock;
use crate::inbox_v2::{MlsEphemeralPqProvider, MlsIdentityProvider};
use crate::service_traits::WakeupService;
use crate::{DeliveryService, RegistrationService};

/// App-owned durations for the GroupV2 liveness policy; the integrator times
/// these itself (see `GroupV2Convo::drive_liveness`). Distinct from the de-mls
/// `ConversationConfig` — the app's to tune, not protocol wire state.
/// `commit_inactivity` must stay above the de-mls `consensus_timeout` so a
/// batch's votes resolve before it is committed.
#[derive(Debug, Clone, Copy)]
pub struct LivenessTimings {
    /// How long the epoch steward collects approved work before committing it.
    pub commit_inactivity: Duration,
    /// The short window a backup waits before covering a silent epoch steward's
    /// in-epoch propose / sync-resend (the work is already visible to all).
    pub silent_steward_window: Duration,
    /// The shorter commit window used while in a recovery posture (a reelection
    /// retry round, or one that just landed) in place of the full
    /// `commit_inactivity` wait, so a recovering group settles faster.
    pub recovery_commit_window: Duration,
}

impl Default for LivenessTimings {
    fn default() -> Self {
        Self {
            commit_inactivity: Duration::from_secs(60),
            silent_steward_window: Duration::from_secs(30),
            recovery_commit_window: Duration::from_secs(30),
        }
    }
}

/// Bundles the external service types (`DS`, `RS`, `CS`) behind one `S`. The
/// `(DS, RS, CS)` tuple impl lets them still be supplied separately.
pub trait ExternalServices {
    type IP: IdentityProvider;
    type DS: DeliveryService;
    type RS: RegistrationService;
    type WS: WakeupService;
    type CS: ChatStore;
}

impl<IP, DS, RS, WS, CS> ExternalServices for (IP, DS, RS, WS, CS)
where
    IP: IdentityProvider,
    DS: DeliveryService,
    RS: RegistrationService,
    WS: WakeupService,
    CS: ChatStore,
{
    type IP = IP;
    type DS = DS;
    type RS = RS;
    type WS = WS;
    type CS = CS;
}

/// Bundles every service a conversation operation may need.
pub(crate) struct ServiceContext<S: ExternalServices> {
    pub(crate) ds: S::DS,
    pub(crate) registry: S::RS,
    pub(crate) store: S::CS,
    pub(crate) mls_identity: MlsIdentityProvider<S::IP>,
    pub(crate) mls_provider: MlsEphemeralPqProvider,
    pub(crate) causal: CausalHistoryStore,
    pub(crate) identity: Identity,
    pub(crate) wakeup_service: S::WS,
    /// Time source for GroupV2 (de-mls) conversations.
    pub(crate) demls_clock: GroupV2Clock,
    /// Timing/policy for GroupV2 (de-mls) conversations, applied at
    /// create/join. The creator's phase durations reach joiners inside the
    /// welcome's `ConversationSync`.
    pub(crate) demls_config: de_mls::ConversationConfig,
    /// App-owned liveness windows the driving loop times itself.
    pub(crate) demls_liveness: LivenessTimings,
}
