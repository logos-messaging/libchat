use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use crypto::Ed25519VerifyingKey;
use libchat::{AddressedEnvelope, DeliveryService, IdentityProvider, RegistrationService};
use logos_account::{AccountDirectory, DeviceSet, SignedDeviceBundle};

use super::http::{
    HttpRegistry, HttpRegistryError, SubmitAccountRequest, SubmitRequest, encode_payload,
};

/// Delivery address the store listens on for keypackage submissions. The
/// transport maps it to its content topic (e.g.
/// `/logos-chat/1/store-keypackage-v0/proto` on logos-delivery); the store
/// subscribes to the same topic.
pub const KEYPACKAGE_SUBMIT_ADDRESS: &str = "store-keypackage-v0";

/// Delivery address the store listens on for account device-list bundles.
pub const ACCOUNT_SUBMIT_ADDRESS: &str = "store-account-v0";

/// How a [`DeliveryRegistry`] submits bundles to the store. Reads always use
/// the store's HTTP query API; only the write half switches.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum RegistryPublishMode {
    /// Submit via the store's HTTP POST endpoints (synchronous, acknowledged).
    #[default]
    Http,
    /// Publish over the delivery network on the well-known store addresses;
    /// the store subscribes and persists what verifies. Fire-and-forget —
    /// there is no per-submission acknowledgement, which the registry can
    /// afford because consumers verify every bundle on retrieval anyway.
    Delivery,
}

/// Contact registry whose write half can publish over a [`DeliveryService`]
/// instead of HTTP POST, switched by [`RegistryPublishMode`].
///
/// Both write paths carry the same JSON submissions ([`SubmitRequest`] /
/// [`SubmitAccountRequest`]): HTTP POSTs them to the store's endpoints, while
/// delivery publishes them on the well-known store addresses the store
/// subscribes to. Reads (keypackage retrieve, account fetch) always go through
/// the store's HTTP query API via the wrapped [`HttpRegistry`].
#[derive(Clone, Debug)]
pub struct DeliveryRegistry<D> {
    delivery: D,
    http: HttpRegistry,
    publish_mode: RegistryPublishMode,
}

#[derive(Debug, thiserror::Error)]
pub enum DeliveryRegistryError {
    #[error("publish over delivery: {0}")]
    Publish(String),
    #[error("encode submission: {0}")]
    Encode(String),
    #[error("clock before unix epoch")]
    Clock,
    #[error(transparent)]
    Http(#[from] HttpRegistryError),
}

impl<D> DeliveryRegistry<D> {
    /// A registry that queries the store's HTTP API at `base_url` and submits
    /// per `publish_mode` — over `delivery` or over the same HTTP API.
    pub fn new(delivery: D, base_url: impl Into<String>, publish_mode: RegistryPublishMode) -> Self {
        Self {
            delivery,
            http: HttpRegistry::new(base_url),
            publish_mode,
        }
    }
}

impl<D: DeliveryService> DeliveryRegistry<D> {
    /// Serialize `submission` and publish it on `delivery_address`.
    fn publish_submission<S: serde::Serialize>(
        &mut self,
        delivery_address: &str,
        submission: &S,
    ) -> Result<(), DeliveryRegistryError> {
        let data = serde_json::to_vec(submission)
            .map_err(|e| DeliveryRegistryError::Encode(e.to_string()))?;
        self.delivery
            .publish(AddressedEnvelope {
                delivery_address: delivery_address.to_string(),
                data,
            })
            .map_err(|e| DeliveryRegistryError::Publish(e.to_string()))
    }
}

impl<D: DeliveryService> RegistrationService for DeliveryRegistry<D> {
    type Error = DeliveryRegistryError;

    fn register(
        &mut self,
        identity: &dyn IdentityProvider,
        key_bundle: Vec<u8>,
    ) -> Result<(), Self::Error> {
        if self.publish_mode == RegistryPublishMode::Http {
            return Ok(self.http.register(identity, key_bundle)?);
        }
        let device_id = hex::encode(identity.public_key().as_ref());
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DeliveryRegistryError::Clock)?
            .as_millis() as u64;

        // Sign exactly the bytes the store will verify and persist.
        let payload = encode_payload(timestamp_ms, &key_bundle);
        let signature = identity.sign(&payload);

        let req = SubmitRequest {
            device_id,
            payload: BASE64.encode(&payload),
            signature: BASE64.encode(signature.as_ref()),
        };
        self.publish_submission(KEYPACKAGE_SUBMIT_ADDRESS, &req)
    }

    fn retrieve(&self, device_id: &str) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(RegistrationService::retrieve(&self.http, device_id)?)
    }
}

impl<D: DeliveryService> AccountDirectory for DeliveryRegistry<D> {
    type Error = DeliveryRegistryError;

    fn publish(&mut self, bundle: &SignedDeviceBundle) -> Result<(), Self::Error> {
        if self.publish_mode == RegistryPublishMode::Http {
            return Ok(self.http.publish(bundle)?);
        }
        let req = SubmitAccountRequest {
            account_pub: hex::encode(bundle.account_pub.as_ref()),
            payload: BASE64.encode(&bundle.payload),
            signature: BASE64.encode(bundle.signature.as_ref()),
        };
        self.publish_submission(ACCOUNT_SUBMIT_ADDRESS, &req)
    }

    fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error> {
        Ok(self.http.fetch(account)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{Ed25519Signature, Ed25519SigningKey};
    use libchat::{IdentId, IdentIdRef};
    use serde::Deserialize;

    #[derive(Debug, Default)]
    struct CapturingDelivery {
        published: Vec<AddressedEnvelope>,
    }

    impl DeliveryService for CapturingDelivery {
        type Error = std::convert::Infallible;
        fn publish(&mut self, envelope: AddressedEnvelope) -> Result<(), Self::Error> {
            self.published.push(envelope);
            Ok(())
        }
        fn subscribe(&mut self, _delivery_address: &str) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    struct TestIdent {
        id: IdentId,
        key: Ed25519SigningKey,
        verifying: Ed25519VerifyingKey,
    }

    impl TestIdent {
        fn new() -> Self {
            let key = Ed25519SigningKey::generate();
            let verifying = key.verifying_key();
            Self {
                id: IdentId::new("test"),
                key,
                verifying,
            }
        }
    }

    impl IdentityProvider for TestIdent {
        fn id(&self) -> IdentIdRef<'_> {
            &self.id
        }
        fn display_name(&self) -> String {
            self.id.to_string()
        }
        fn sign(&self, payload: &[u8]) -> Ed25519Signature {
            self.key.sign(payload)
        }
        fn public_key(&self) -> &Ed25519VerifyingKey {
            &self.verifying
        }
    }

    /// The JSON body as the store parses it — field names must not drift.
    #[derive(Deserialize)]
    struct WireSubmission {
        device_id: Option<String>,
        account_pub: Option<String>,
        payload: String,
        signature: String,
    }

    #[test]
    fn register_publishes_store_submission_on_keypackage_address() {
        let mut registry = DeliveryRegistry::new(
            CapturingDelivery::default(),
            "http://unused.invalid",
            RegistryPublishMode::Delivery,
        );
        let ident = TestIdent::new();
        let key_bundle = b"kp-bytes".to_vec();
        registry.register(&ident, key_bundle.clone()).unwrap();

        let [envelope] = &registry.delivery.published[..] else {
            panic!("expected exactly one published envelope");
        };
        assert_eq!(envelope.delivery_address, KEYPACKAGE_SUBMIT_ADDRESS);

        let wire: WireSubmission = serde_json::from_slice(&envelope.data).unwrap();
        assert_eq!(
            wire.device_id.as_deref(),
            Some(hex::encode(ident.verifying.as_ref()).as_str())
        );
        // The store verifies the signature over the payload bytes under the
        // device key before persisting — the submission must pass that check.
        let payload = BASE64.decode(wire.payload).unwrap();
        assert!(payload.ends_with(&key_bundle));
        let signature: [u8; 64] = BASE64
            .decode(wire.signature)
            .unwrap()
            .try_into()
            .unwrap();
        ident
            .verifying
            .verify(&payload, &Ed25519Signature::from(signature))
            .expect("store-side verification must succeed");
    }

    #[test]
    fn account_publish_targets_account_address_verbatim() {
        let mut registry = DeliveryRegistry::new(
            CapturingDelivery::default(),
            "http://unused.invalid",
            RegistryPublishMode::Delivery,
        );
        let account = Ed25519SigningKey::generate();
        let payload = b"signed-device-list".to_vec();
        let bundle = SignedDeviceBundle {
            account_pub: account.verifying_key(),
            signature: account.sign(&payload),
            payload: payload.clone(),
        };
        registry.publish(&bundle).unwrap();

        let [envelope] = &registry.delivery.published[..] else {
            panic!("expected exactly one published envelope");
        };
        assert_eq!(envelope.delivery_address, ACCOUNT_SUBMIT_ADDRESS);

        let wire: WireSubmission = serde_json::from_slice(&envelope.data).unwrap();
        assert_eq!(
            wire.account_pub.as_deref(),
            Some(hex::encode(bundle.account_pub.as_ref()).as_str())
        );
        // Payload travels verbatim so the store and consumers verify the exact
        // signed bytes.
        assert_eq!(BASE64.decode(wire.payload).unwrap(), payload);
    }

    #[test]
    fn http_mode_never_touches_the_delivery_service() {
        // Port 9 (discard) refuses immediately; the point is only that the
        // submission goes down the HTTP path, not over delivery.
        let mut registry = DeliveryRegistry::new(
            CapturingDelivery::default(),
            "http://127.0.0.1:9",
            RegistryPublishMode::Http,
        );
        let err = registry
            .register(&TestIdent::new(), vec![1])
            .unwrap_err();
        assert!(matches!(err, DeliveryRegistryError::Http(_)));
        assert!(registry.delivery.published.is_empty());
    }
}
