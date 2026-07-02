mod account_directory;
mod causal_history;
mod conversation;
mod core;
mod crypto;
mod errors;
mod inbox;
mod inbox_v2;
mod outcomes;
mod proto;
mod service_context;
mod service_traits;
mod types;
mod utils;

pub use account_directory::{
    AccountAuthority, AccountDirectory, BUNDLE_VERSION, BundleError, DecodedBundle, DeviceId,
    DeviceSet, Lamport, SignedDeviceBundle, decode_bundle_payload, encode_bundle_payload,
    resolve_device_ids, verify_bundle,
};
pub use causal_history::{Frontier, MissingMessage};
pub use chat_sqlite::ChatStorage;
pub use chat_sqlite::MlsStorageError;
pub use chat_sqlite::StorageConfig;
pub use core::{ConversationId, Core, Introduction};
pub use errors::ChatError;
pub use outcomes::{
    Content, ConversationClass, ConvoOutcome, InboxOutcome, NewConversation, PayloadOutcome,
};
pub use service_context::ExternalServices;
pub use service_traits::{DeliveryService, RegistrationService, WakeupService};
pub use shared_traits::{IdentId, IdentIdRef, IdentityProvider};
pub use storage::{ChatStore, ConversationKind};
pub use types::AddressedEnvelope;
pub use utils::{hex_trunc, trunc};

/// OpenMLS storage requirements, re-exported so external providers can implement
/// a durable [`StorageProvider`](openmls_traits::storage::StorageProvider)
/// without depending on `openmls_traits` directly. [`ChatStorage`] is libchat's
/// own durable implementation, and [`ChatStore`] folds this surface in so one
/// store type serves both chat and MLS state.
pub mod mls_storage {
    pub use openmls_memory_storage::MemoryStorage;
    pub use openmls_traits::OpenMlsProvider;
    pub use openmls_traits::storage::{CURRENT_VERSION, Entity, Key, StorageProvider, traits};
}
