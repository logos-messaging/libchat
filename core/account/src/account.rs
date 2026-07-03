use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};

use crate::directory::{AccountDirectory, SignedDeviceBundle, encode_bundle_payload};

/// Failures updating an account's device bundle in the directory.
#[derive(Debug, thiserror::Error)]
pub enum AddDelegateSignerError {
    #[error("directory: {0}")]
    Directory(String),
    #[error("directory returned a malformed device id")]
    MalformedDeviceId,
    #[error("directory returned a malformed device key")]
    MalformedDeviceKey,
}

/// A Test Focused LogosAccount.
/// The test account is not persisted.
/// This account type should not be used in a production system.
pub struct TestLogosAccount {
    signing_key: Ed25519SigningKey,
    verifying_key: Ed25519VerifyingKey,
}

impl Default for TestLogosAccount {
    fn default() -> Self {
        Self::new()
    }
}

impl TestLogosAccount {
    pub fn new() -> Self {
        let signing_key = Ed25519SigningKey::generate();
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// The account verifying key; its hex is the account address peers share.
    pub fn public_key(&self) -> &Ed25519VerifyingKey {
        &self.verifying_key
    }

    /// The account address peers share: the hex of the verifying key.
    pub fn address(&self) -> String {
        hex::encode(self.verifying_key.as_ref())
    }

    /// Add `signer` (the delegate signer's verifying key) to this account's directory bundle.
    ///
    /// Fetches the current (verified) device set, adds the signer if absent,
    /// bumps the lamport, re-signs, and publishes. Safe to call repeatedly:
    /// an unchanged set is simply re-published, which also refreshes the
    /// server's retention clock. The account signs internally; its key never
    /// leaves this type.
    pub fn add_delegate_signer<D: AccountDirectory>(
        &self,
        directory: &mut D,
        signer: &Ed25519VerifyingKey,
    ) -> Result<(), AddDelegateSignerError> {
        // Start from the devices already registered so the account's other
        // installations are preserved across the upsert.
        let existing = directory
            .fetch(&self.verifying_key)
            .map_err(|e| AddDelegateSignerError::Directory(e.to_string()))?;
        let (mut devices, next_lamport) = match existing {
            Some(set) => {
                let mut keys = Vec::with_capacity(set.devices.len() + 1);
                for hex_id in &set.devices {
                    let bytes: [u8; 32] = hex::decode(hex_id)
                        .ok()
                        .and_then(|b| b.try_into().ok())
                        .ok_or(AddDelegateSignerError::MalformedDeviceId)?;
                    let key = Ed25519VerifyingKey::from_bytes(&bytes)
                        .map_err(|_| AddDelegateSignerError::MalformedDeviceKey)?;
                    keys.push(key);
                }
                (keys, set.lamport + 1)
            }
            None => (Vec::new(), 0),
        };

        if !devices.iter().any(|d| d.as_ref() == signer.as_ref()) {
            devices.push(signer.clone());
        }

        let payload = encode_bundle_payload(next_lamport, &devices);
        let signature = self.signing_key.sign(&payload);
        let bundle = SignedDeviceBundle {
            account_pub: self.verifying_key.clone(),
            payload,
            signature,
        };

        directory
            .publish(&bundle)
            .map_err(|e| AddDelegateSignerError::Directory(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use crate::directory::{DeviceSet, verify_bundle};

    use super::*;

    /// Minimal in-test directory: stores the latest bundle, verifies on fetch.
    #[derive(Debug, Default)]
    struct FakeDir(Option<SignedDeviceBundle>);

    impl AccountDirectory for FakeDir {
        type Error = crate::directory::BundleError;
        fn publish(&mut self, bundle: &SignedDeviceBundle) -> Result<(), Self::Error> {
            self.0 = Some(bundle.clone());
            Ok(())
        }
        fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error> {
            self.0
                .as_ref()
                .map(|b| verify_bundle(account, b))
                .transpose()
        }
    }

    fn device_set(dir: &FakeDir, account: &TestLogosAccount) -> (u64, Vec<String>) {
        let set = dir
            .fetch(account.public_key())
            .unwrap()
            .expect("bundle published");
        (set.lamport, set.devices)
    }

    /// First publish for an account starts at lamport 0 with the one device.
    #[test]
    fn first_add_delegate_signer_lists_the_signer() {
        let mut dir = FakeDir::default();
        let account = TestLogosAccount::new();
        let device = Ed25519SigningKey::generate().verifying_key();

        account.add_delegate_signer(&mut dir, &device).unwrap();

        let (lamport, devices) = device_set(&dir, &account);
        assert_eq!(lamport, 0);
        assert_eq!(devices, vec![hex::encode(device.as_ref())]);
    }

    /// A second device is merged into the existing set with a bumped lamport,
    /// preserving the first device.
    #[test]
    fn add_delegate_signer_merges_and_bumps_lamport() {
        let mut dir = FakeDir::default();
        let account = TestLogosAccount::new();
        let first = Ed25519SigningKey::generate().verifying_key();
        let second = Ed25519SigningKey::generate().verifying_key();

        account.add_delegate_signer(&mut dir, &first).unwrap();
        account.add_delegate_signer(&mut dir, &second).unwrap();

        let (lamport, devices) = device_set(&dir, &account);
        assert_eq!(lamport, 1);
        assert_eq!(
            devices,
            vec![hex::encode(first.as_ref()), hex::encode(second.as_ref())]
        );
    }

    /// Re-adding an already-listed device keeps the set and still bumps the
    /// lamport (a refresh, not a duplicate).
    #[test]
    fn re_adding_a_device_is_idempotent_on_the_set() {
        let mut dir = FakeDir::default();
        let account = TestLogosAccount::new();
        let device = Ed25519SigningKey::generate().verifying_key();

        account.add_delegate_signer(&mut dir, &device).unwrap();
        account.add_delegate_signer(&mut dir, &device).unwrap();

        let (lamport, devices) = device_set(&dir, &account);
        assert_eq!(lamport, 1);
        assert_eq!(devices, vec![hex::encode(device.as_ref())]);
    }
}
