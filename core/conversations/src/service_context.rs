//! Bundles the services a conversation operation needs into one [`ServiceContext`].

use crypto::Identity;
use storage::ChatStore;

use crate::account::LogosAccount;
use crate::causal_history::CausalHistoryStore;
use crate::inbox_v2::{MlsEphemeralPqProvider, MlsIdentityProvider};
use crate::{DeliveryService, RegistrationService};

/// Bundles the external service types (`DS`, `RS`, `CS`) behind one `S`. The
/// `(DS, RS, CS)` tuple impl lets them still be supplied separately.
pub trait ExternalServices {
    type DS: DeliveryService;
    type RS: RegistrationService;
    type CS: ChatStore;
}

impl<DS, RS, CS> ExternalServices for (DS, RS, CS)
where
    DS: DeliveryService,
    RS: RegistrationService,
    CS: ChatStore,
{
    type DS = DS;
    type RS = RS;
    type CS = CS;
}

/// Bundles every service a conversation operation may need.
pub(crate) struct ServiceContext<S: ExternalServices> {
    pub(crate) ds: S::DS,
    pub(crate) registry: S::RS,
    pub(crate) store: S::CS,
    pub(crate) mls_identity: MlsIdentityProvider<LogosAccount>,
    pub(crate) mls_provider: MlsEphemeralPqProvider,
    pub(crate) causal: CausalHistoryStore,
    pub(crate) identity: Identity,
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

    impl<CS: ChatStore> ServiceContext<(NoopDelivery, NoopRegistration, CS)> {
        /// Builds a context around a real store, stubbing other services.
        pub(crate) fn for_test(name: &str, store: CS) -> Result<Self, ChatError> {
            let account = LogosAccount::new_test(name);
            Ok(Self {
                ds: NoopDelivery,
                registry: NoopRegistration,
                store,
                mls_identity: MlsIdentityProvider::new(account),
                mls_provider: MlsEphemeralPqProvider::new().map_err(ChatError::generic)?,
                causal: CausalHistoryStore::new(),
                identity: Identity::new(name),
            })
        }
    }
}
