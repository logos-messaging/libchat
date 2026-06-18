//! Bundles the services a conversation operation needs into one [`ServiceContext`].

use crypto::Identity;
use storage::ChatStore;

use crate::IdentityProvider;
use crate::causal_history::CausalHistoryStore;
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
}

#[cfg(test)]
mod test_support {
    use super::*;
    use crate::account_service::{AccountService, DeviceSet, SignedDeviceBundle};
    use crate::types::AddressedEnvelope;
    use crate::{ChatError, IdentityProvider};
    use crypto::Ed25519VerifyingKey;

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
        ) -> Result<(), <Self as RegistrationService>::Error> {
            Ok(())
        }

        fn retrieve(
            &self,
            _device_id: &str,
        ) -> Result<Option<Vec<u8>>, <Self as RegistrationService>::Error> {
            Ok(None)
        }
    }

    impl AccountService for NoopRegistration {
        type Error = std::convert::Infallible;

        fn publish(
            &mut self,
            _bundle: &SignedDeviceBundle,
        ) -> Result<(), <Self as AccountService>::Error> {
            Ok(())
        }

        fn fetch(
            &self,
            _account: &Ed25519VerifyingKey,
        ) -> Result<Option<DeviceSet>, <Self as AccountService>::Error> {
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
            })
        }
    }
}
