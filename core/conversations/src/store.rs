mod conversations;
mod ephemeral_keys;
mod identity;

pub use conversations::{ConversationKind, ConversationMeta, ConversationStore};
pub use ephemeral_keys::EphemeralKeyStore;
pub use identity::IdentityStore;

pub trait ChatStore: IdentityStore + EphemeralKeyStore + ConversationStore {}

impl<T> ChatStore for T where T: IdentityStore + EphemeralKeyStore + ConversationStore {}
