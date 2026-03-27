use storage::StorageError;

use crate::{
    hkdf::{DefaultDomain, HkdfInfo},
    state::RatchetState,
};

/// Persistence operations for Double Ratchet conversation state.
pub trait RatchetStore {
    /// Saves the ratchet state for a conversation.
    fn save<D: HkdfInfo>(
        &mut self,
        conversation_id: &str,
        state: &RatchetState<D>,
    ) -> Result<(), StorageError>;

    /// Loads the ratchet state for a conversation.
    fn load<D: HkdfInfo>(&self, conversation_id: &str) -> Result<RatchetState<D>, StorageError>;

    /// Checks whether a ratchet state exists for the conversation.
    fn exists(&self, conversation_id: &str) -> Result<bool, StorageError>;

    /// Deletes the ratchet state and any related skipped keys for the conversation.
    fn delete(&mut self, conversation_id: &str) -> Result<(), StorageError>;
}

/// Object-safe ratchet storage operations for the default HKDF domain.
///
/// This is useful for crates that need dynamic dispatch, such as `conversations`,
/// while still allowing the more general `RatchetStore` trait to stay generic.
pub trait DefaultRatchetStore {
    /// Saves the default-domain ratchet state for a conversation.
    fn save_default(
        &mut self,
        conversation_id: &str,
        state: &RatchetState<DefaultDomain>,
    ) -> Result<(), StorageError>;

    /// Loads the default-domain ratchet state for a conversation.
    fn load_default(
        &self,
        conversation_id: &str,
    ) -> Result<RatchetState<DefaultDomain>, StorageError>;

    /// Checks whether a ratchet state exists for the conversation.
    fn exists_default(&self, conversation_id: &str) -> Result<bool, StorageError>;

    /// Deletes the ratchet state and any related skipped keys for the conversation.
    fn delete_default(&mut self, conversation_id: &str) -> Result<(), StorageError>;
}

impl<T: RatchetStore + ?Sized> DefaultRatchetStore for T {
    fn save_default(
        &mut self,
        conversation_id: &str,
        state: &RatchetState<DefaultDomain>,
    ) -> Result<(), StorageError> {
        self.save(conversation_id, state)
    }

    fn load_default(
        &self,
        conversation_id: &str,
    ) -> Result<RatchetState<DefaultDomain>, StorageError> {
        self.load(conversation_id)
    }

    fn exists_default(&self, conversation_id: &str) -> Result<bool, StorageError> {
        self.exists(conversation_id)
    }

    fn delete_default(&mut self, conversation_id: &str) -> Result<(), StorageError> {
        self.delete(conversation_id)
    }
}
