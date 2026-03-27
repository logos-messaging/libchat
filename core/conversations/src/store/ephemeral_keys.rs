use crypto::PrivateKey;
use storage::StorageError;

pub trait EphemeralKeyStore {
    fn save_ephemeral_key(
        &mut self,
        public_key_hex: &str,
        private_key: &PrivateKey,
    ) -> Result<(), StorageError>;

    fn load_ephemeral_key(&self, public_key_hex: &str) -> Result<Option<PrivateKey>, StorageError>;

    fn remove_ephemeral_key(&mut self, public_key_hex: &str) -> Result<(), StorageError>;
}
