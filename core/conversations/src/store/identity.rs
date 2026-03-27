use storage::StorageError;

use crate::identity::Identity;

/// Persistence operations for installation identity data.
pub trait IdentityStore {
    /// Loads the stored identity if one exists.
    fn load_identity(&self) -> Result<Option<Identity>, StorageError>;

    /// Persists the installation identity.
    fn save_identity(&mut self, identity: &Identity) -> Result<(), StorageError>;
}
