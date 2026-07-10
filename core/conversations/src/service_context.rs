//! Bundles the services a conversation operation needs into one [`ServiceContext`].

use crypto::Identity;
use storage::ChatStore;

use crate::IdentityProvider;
use crate::causal_history::CausalHistoryStore;
use crate::conversation::GroupV2Clock;
use crate::inbox_v2::{MlsEphemeralPqProvider, MlsIdentityProvider};
use crate::service_traits::WakeupService;
use crate::{DeliveryService, RegistrationService};

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
}

#[cfg(test)]
mod test_support {
    use super::*;
    use crate::types::AddressedEnvelope;
    use crate::{ChatError, IdentityProvider};

    /// Delivery double that drops every payload.
    #[derive(Debug)]
    pub(crate) struct NoopDelivery;

    impl DeliveryService for NoopDelivery {
        type Error = std::convert::Infallible;

        fn publish(&mut self, _envelope: AddressedEnvelope) -> Result<(), Self::Error> {
            Ok(())
        }

        fn subscribe(&mut self, _delivery_address: &str) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    /// Registration double that holds no key packages.
    #[derive(Debug)]
    pub(crate) struct NoopRegistration;

    impl RegistrationService for NoopRegistration {
        type Error = std::convert::Infallible;

        fn register(
            &mut self,
            _identity: &dyn IdentityProvider,
            _key_bundle: Vec<u8>,
        ) -> Result<(), Self::Error> {
            Ok(())
        }

        fn retrieve(&self, _device_id: &str) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(None)
        }
    }

    #[derive(Debug)]
    pub(crate) struct NoopWakeups;

    impl WakeupService for NoopWakeups {
        fn wakeup_in(&mut self, _: std::time::Duration, _: crate::ConversationId) {}
    }

    impl<IP: IdentityProvider, CS: ChatStore>
        ServiceContext<(IP, NoopDelivery, NoopRegistration, NoopWakeups, CS)>
    {
        /// Builds a context around a real store, stubbing other services.
        pub(crate) fn for_test(ident: IP, store: CS) -> Result<Self, ChatError> {
            let name = ident.id().as_str().to_string();
            Ok(Self {
                ds: NoopDelivery,
                registry: NoopRegistration,
                store,
                mls_identity: MlsIdentityProvider::new(ident),
                mls_provider: MlsEphemeralPqProvider::new().map_err(ChatError::generic)?,
                causal: CausalHistoryStore::new(),
                identity: Identity::new(name),
                wakeup_service: NoopWakeups {},
                demls_clock: GroupV2Clock::default(),
                demls_config: de_mls::ConversationConfig::default(),
            })
        }
    }
}
