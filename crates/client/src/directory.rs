use crypto::Ed25519VerifyingKey;
use libchat::{AccountAuthority, AccountDirectory, SignedDeviceBundle, encode_bundle_payload};

use crate::errors::ClientError;

/// Add `device` to the account's directory bundle.
///
/// Fetches the current (verified) device set, adds the device if absent, bumps
/// the lamport, re-signs with the account key, and publishes. Safe to call
/// repeatedly — an unchanged set is simply re-published, which also refreshes
/// the server's retention clock. Account key custody stays outside libchat:
/// the injected [`AccountAuthority`] is only ever asked to sign.
pub fn publish_device_bundle<D, A>(
    directory: &mut D,
    authority: &A,
    device: &Ed25519VerifyingKey,
) -> Result<(), ClientError>
where
    D: AccountDirectory,
    A: AccountAuthority,
{
    let account_pub = authority.account_pub().clone();
    let device_hex = hex::encode(device.as_ref());

    // Start from the devices already registered so the account's other
    // installations are preserved across the upsert.
    let existing = directory
        .fetch(&account_pub)
        .map_err(|e| ClientError::BundlePublish(e.to_string()))?;
    let (mut devices, next_lamport) = match existing {
        Some(set) => {
            let mut keys = Vec::with_capacity(set.devices.len() + 1);
            for hex_id in &set.devices {
                let bytes: [u8; 32] = hex::decode(hex_id)
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| {
                        ClientError::BundlePublish(
                            "directory returned a malformed device id".into(),
                        )
                    })?;
                let key = Ed25519VerifyingKey::from_bytes(&bytes).map_err(|_| {
                    ClientError::BundlePublish("directory returned a malformed device key".into())
                })?;
                keys.push(key);
            }
            (keys, set.lamport + 1)
        }
        None => (Vec::new(), 0),
    };

    if !devices
        .iter()
        .any(|d| hex::encode(d.as_ref()) == device_hex)
    {
        devices.push(device.clone());
    }

    let payload = encode_bundle_payload(next_lamport, &devices);
    let signature = authority
        .sign(&payload)
        .map_err(|e| ClientError::BundlePublish(e.to_string()))?;
    let bundle = SignedDeviceBundle {
        account_pub,
        payload,
        signature,
    };

    directory
        .publish(&bundle)
        .map_err(|e| ClientError::BundlePublish(e.to_string()))
}

#[cfg(test)]
mod tests {
    use components::EphemeralRegistry;
    use libchat::IdentityProvider;
    use logos_account::TestLogosAccount;

    use super::*;

    fn device_hexes(dir: &EphemeralRegistry, account: &TestLogosAccount) -> (u64, Vec<String>) {
        let set = dir
            .fetch(IdentityProvider::public_key(account))
            .unwrap()
            .expect("bundle published");
        (set.lamport, set.devices)
    }

    /// First publish for an account starts at lamport 0 with the one device.
    #[test]
    fn first_publish_lists_the_device() {
        let mut dir = EphemeralRegistry::new();
        let account = TestLogosAccount::new("acct");
        let device = crypto::Ed25519SigningKey::generate().verifying_key();

        publish_device_bundle(&mut dir, &account, &device).unwrap();

        let (lamport, devices) = device_hexes(&dir, &account);
        assert_eq!(lamport, 0);
        assert_eq!(devices, vec![hex::encode(device.as_ref())]);
    }

    /// A second device is merged into the existing set with a bumped lamport,
    /// preserving the first device.
    #[test]
    fn upsert_merges_devices_and_bumps_lamport() {
        let mut dir = EphemeralRegistry::new();
        let account = TestLogosAccount::new("acct");
        let first = crypto::Ed25519SigningKey::generate().verifying_key();
        let second = crypto::Ed25519SigningKey::generate().verifying_key();

        publish_device_bundle(&mut dir, &account, &first).unwrap();
        publish_device_bundle(&mut dir, &account, &second).unwrap();

        let (lamport, devices) = device_hexes(&dir, &account);
        assert_eq!(lamport, 1);
        assert_eq!(
            devices,
            vec![hex::encode(first.as_ref()), hex::encode(second.as_ref())]
        );
    }

    /// Re-publishing an already-listed device keeps the set and still bumps the
    /// lamport (a refresh, not a duplicate).
    #[test]
    fn republish_is_idempotent_on_the_set() {
        let mut dir = EphemeralRegistry::new();
        let account = TestLogosAccount::new("acct");
        let device = crypto::Ed25519SigningKey::generate().verifying_key();

        publish_device_bundle(&mut dir, &account, &device).unwrap();
        publish_device_bundle(&mut dir, &account, &device).unwrap();

        let (lamport, devices) = device_hexes(&dir, &account);
        assert_eq!(lamport, 1);
        assert_eq!(devices, vec![hex::encode(device.as_ref())]);
    }
}
