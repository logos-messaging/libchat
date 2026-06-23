use std::sync::Arc;
use std::thread::{self, JoinHandle};

use components::{ThreadedWakeupService, WakeupEvent};
use crossbeam_channel::{Receiver, Sender, select};
use crypto::Ed25519VerifyingKey;
use libchat::{
    AccountDirectory, ConversationId, ConvoOutcome, Core, DeliveryService, IdentId, IdentIdRef,
    IdentityProvider, InboxOutcome, Introduction, PayloadOutcome, RegistrationService,
};
use parking_lot::Mutex;
use storage::ChatStore;

use crate::delegate::DelegateCredential;
use crate::errors::ClientError;
use crate::event::{Event, MessageSender};

type ClientCore<I, T, R, S> = Core<(I, T, R, ThreadedWakeupService, S)>;
type AccountAddressRef<'a> = &'a str;
type LocalSignerId = IdentId;

/// The transport as the client sees it: a [`DeliveryService`] for outbound
/// publishing plus the inbound payload stream the worker drains. One object owns
/// both directions of the boundary.
pub trait Transport: DeliveryService + Send + 'static {
    /// Hand over the inbound payload stream. Called once, at client construction,
    /// before the [`Core`] takes ownership of the service.
    fn inbound(&mut self) -> Receiver<Vec<u8>>;
}

/// High-level chat client.
///
/// Owns the synchronous [`Core`] behind an `Arc<Mutex<…>>` and a background
/// worker that consumes inbound payloads off the transport's channel, drives
/// the core, and forwards observations as [`Event`]s. Construction returns the
/// handle together with the `Receiver<Event>` the application drains on its own
/// schedule.
///
/// Outbound calls (`send_message`, `create_conversation`, …) run on the
/// caller's thread: they briefly lock the core, invoke it, and return — no
/// message-passing round-trip. The `Arc`/`Mutex`/threads live entirely here;
/// the core never mentions threads.
pub struct ChatClient<I, T, R, S>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
    S: ChatStore + Send + 'static,
{
    /// `parking_lot::Mutex` for its eventual fairness: an inbound burst can't
    /// starve caller operations of the lock.
    core: Arc<Mutex<ClientCore<I, T, R, S>>>,
    /// Dropped on `Drop` to wake the worker's `select!` and shut it down.
    shutdown: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
    address: String,
}

// -- GenericChatClient
impl<I, T, R, S> ChatClient<I, T, R, S>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn new(
        ident: I,
        mut transport: T,
        reg: R,
        storage: S,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let inbound = transport.inbound();

        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let core = Core::new_with_name(ident, transport, reg, wakeup_service, storage)?;
        Ok(Self::spawn(core, inbound, wakeup_rx))
    }

    fn spawn(
        core: ClientCore<I, T, R, S>,
        inbound: Receiver<Vec<u8>>,
        wakeup_events: Receiver<WakeupEvent>,
    ) -> (Self, Receiver<Event>) {
        let address = core.ident_id().to_string();
        let core = Arc::new(Mutex::new(core));
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(0);

        let worker = thread::spawn({
            let core = Arc::clone(&core);
            move || worker_loop(core, inbound, wakeup_events, shutdown_rx, event_tx)
        });

        (
            Self {
                core,
                shutdown: Some(shutdown_tx),
                worker: Some(worker),
                address,
            },
            event_rx,
        )
    }

    pub fn addr(&self) -> AccountAddressRef<'_> {
        &self.address
    }

    /// Returns the installation name (identity label) of this client.
    pub fn installation_name(&self) -> String {
        self.core.lock().installation_name().to_string()
    }

    /// Produce a serialised introduction bundle for sharing out-of-band.
    pub fn create_intro_bundle(&mut self) -> Result<Vec<u8>, ClientError> {
        self.core.lock().create_intro_bundle().map_err(Into::into)
    }

    // Creates a conversation between two Accounts.
    pub fn create_direct_conversation(
        &mut self,
        account: AccountAddressRef,
    ) -> Result<ConversationId, ClientError> {
        let signers = self.signers_from_account(account)?;
        let signer_refs: Vec<IdentIdRef> = signers.iter().collect();

        self.core
            .lock()
            .create_direct_convo(&signer_refs)
            .map_err(Into::into)
    }

    /// Parse intro bundle bytes and initiate a private conversation. Outbound
    /// envelopes are published by the core. Returns this side's conversation ID.
    ///
    /// This function will be deprecated in the future. Use `create_direct_conversation`
    pub fn create_conversation(
        &mut self,
        intro_bundle: &[u8],
        initial_content: &[u8],
    ) -> Result<ConversationId, ClientError> {
        let intro = Introduction::try_from(intro_bundle)?;
        self.core
            .lock()
            .create_private_convo_v1(&intro, initial_content)
            .map_err(Into::into)
    }

    /// List all conversation IDs known to this client.
    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ClientError> {
        self.core.lock().list_conversations().map_err(Into::into)
    }

    /// Encrypt and send `content` to an existing conversation. The core
    /// publishes the outbound envelope.
    pub fn send_message(&mut self, convo_id: &str, content: &[u8]) -> Result<(), ClientError> {
        self.core
            .lock()
            .send_content(convo_id, content)
            .map_err(Into::into)
    }

    // Get signers for a given AccountAddress.
    fn signers_from_account(
        &self,
        account: AccountAddressRef,
    ) -> Result<Vec<LocalSignerId>, ClientError> {
        // Assume Account = LocalSigner until Account is ready
        Ok(vec![IdentId::new(account.to_string())])
    }
}

impl<I, T, R, S> Drop for ChatClient<I, T, R, S>
where
    I: IdentityProvider + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
    S: ChatStore + Send + 'static,
{
    fn drop(&mut self) {
        // Dropping the sender disconnects the worker's shutdown channel, waking
        // its `select!` so it can exit; then we join it.
        self.shutdown.take();
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

/// Background loop: block until an inbound payload or shutdown arrives, drive
/// the core on each payload, and forward events. No polling — `select!` parks
/// the thread until one of the channels is ready.
fn worker_loop<I: IdentityProvider + 'static, T, R, S: ChatStore + 'static>(
    core: Arc<Mutex<ClientCore<I, T, R, S>>>,
    inbound: Receiver<Vec<u8>>,
    wakeup_events: Receiver<WakeupEvent>,
    shutdown: Receiver<()>,
    event_tx: Sender<Event>,
) where
    T: DeliveryService + Send + 'static,
    R: RegistrationService + Send + 'static,
{
    loop {
        select! {
            recv(inbound) -> msg => {
                let Ok(bytes) = msg else {
                    return; // transport's sender dropped
                };
                let events = {
                    let mut core = core.lock();
                    match core.handle_payload(&bytes) {
                        Ok(outcome) => events_from_inbound(outcome, core.account_directory()),
                        Err(e) => {
                            tracing::warn!("inbound handle_payload failed: {e:?}");
                            vec![Event::InboundError {
                                message: e.to_string(),
                            }]
                        }
                    }
                };
                for event in events {
                    if event_tx.send(event).is_err() {
                        return; // application dropped the receiver
                    }
                }
            }
            recv(wakeup_events) -> msg => {
                let Ok(WakeupEvent { convo_id }) = msg else {
                    return; // wakeup service's sender dropped
                };
                if let Err(e) = core.lock().wakeup(&convo_id) {
                    tracing::warn!("wakeup failed: {e:?}");
                }
            }
            recv(shutdown) -> _ => return,
        }
    }
}

/// Walk a [`PayloadOutcome`] in causal order and emit one `Event` per
/// observation. For an `Inbox` outcome, [`Event::ConversationStarted`]
/// precedes the message event. The convo id is wrapped into `Arc<str>` once
/// per outcome and shared across the events it produces.
fn events_from_inbound(result: PayloadOutcome, directory: &impl AccountDirectory) -> Vec<Event> {
    match result {
        PayloadOutcome::Empty => Vec::new(),
        PayloadOutcome::Convo(co) => convo_events(co, directory),
        PayloadOutcome::Inbox(io) => inbox_events(io, directory),
    }
}

/// Interpret a hex account address as an Ed25519 account verifying key.
fn account_key_from_hex(addr: &str) -> Option<Ed25519VerifyingKey> {
    let bytes: [u8; 32] = hex::decode(addr).ok()?.try_into().ok()?;
    Ed25519VerifyingKey::from_bytes(&bytes).ok()
}

/// Why a message's sender could not be accepted, so the message is dropped.
#[derive(Debug, PartialEq, Eq)]
enum SenderError {
    /// Credential bytes were not valid hex.
    NotHex,
    /// Credential bytes did not decode to a delegate credential.
    Malformed,
    /// The claimed account address is not an Ed25519 verifying key.
    AccountNotAKey,
    /// The account → device mapping is wrong or could not be confirmed: the
    /// device is not in the account's published set, the account published none,
    /// or the directory lookup failed.
    Unverified,
}

/// Decode and verify a message's sender from its credential, checked against the
/// account → device directory (our account store).
///
/// `Ok(None)` — deliver, but the sender is unknown (no credential, e.g. a
/// PrivateV1 1:1 message). `Ok(Some(sender))` — deliver with the sender; its
/// `account` is set only when the directory confirmed the device, so it is
/// always verified. `Err` — drop the message.
fn decode_sender(
    directory: &impl AccountDirectory,
    encoded: &[u8],
) -> Result<Option<MessageSender>, SenderError> {
    // No credential (e.g. the PrivateV1 placeholder) asserts no account mapping.
    if encoded.is_empty() {
        return Ok(None);
    }
    let Ok(data) = hex::decode(encoded) else {
        tracing::warn!("sender credential is not valid hex; dropping message");
        return Err(SenderError::NotHex);
    };
    let cred = match DelegateCredential::try_from(data) {
        Ok(cred) => cred,
        Err(_) => {
            tracing::warn!("malformed sender credential; dropping message");
            return Err(SenderError::Malformed);
        }
    };
    let device = hex::encode(cred.delegate_id().as_ref());
    // An unassociated delegate asserts no account → device mapping.
    let Some(account_addr) = cred.account_addr() else {
        return Ok(Some(MessageSender {
            account: None,
            local_identity: IdentId::new(device),
        }));
    };
    let Some(account_key) = account_key_from_hex(account_addr) else {
        tracing::warn!(
            account_addr,
            "sender account address is not a verifying key; dropping message"
        );
        return Err(SenderError::AccountNotAKey);
    };
    match directory.fetch(&account_key) {
        Ok(Some(set)) if set.devices.iter().any(|d| d == &device) => Ok(Some(MessageSender {
            account: Some(IdentId::new(account_addr.to_string())),
            local_identity: IdentId::new(device),
        })),
        _ => {
            tracing::warn!(account_addr, %device, "account → device mapping is wrong or unconfirmable; dropping message");
            Err(SenderError::Unverified)
        }
    }
}

fn convo_events(outcome: ConvoOutcome, directory: &impl AccountDirectory) -> Vec<Event> {
    let ConvoOutcome { convo_id, content } = outcome;
    content
        .and_then(|c| {
            let sender = decode_sender(directory, &c.encoded_credential).ok()?;
            Some(Event::MessageReceived {
                convo_id: Arc::from(convo_id),
                content: c.bytes,
                sender,
            })
        })
        .into_iter()
        .collect()
}

fn inbox_events(outcome: InboxOutcome, directory: &impl AccountDirectory) -> Vec<Event> {
    let InboxOutcome {
        new_conversation,
        initial,
    } = outcome;
    let id: Arc<str> = Arc::from(new_conversation.convo_id);
    let mut events = Vec::with_capacity(2);
    events.push(Event::ConversationStarted {
        convo_id: Arc::clone(&id),
        class: new_conversation.class,
    });
    if let Some(c) = initial.and_then(|co| co.content)
        && let Ok(sender) = decode_sender(directory, &c.encoded_credential)
    {
        events.push(Event::MessageReceived {
            convo_id: Arc::clone(&id),
            content: c.bytes,
            sender,
        });
    }
    events
}

#[cfg(test)]
mod sender_check_tests {
    use std::collections::HashMap;

    use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
    use libchat::{DeviceSet, IdentId, SignedDeviceBundle};

    use super::{MessageSender, SenderError, decode_sender};
    use crate::delegate::DelegateCredential;

    /// In-test account → device directory. Holds device id sets keyed by the hex
    /// account key, and can be made to fail to simulate a directory outage.
    #[derive(Debug, Default)]
    struct FakeDir {
        bundles: HashMap<String, Vec<String>>,
        fail: bool,
    }

    impl FakeDir {
        /// Publish `devices` (verifying keys) as `account`'s device set.
        fn with_devices(account: &Ed25519VerifyingKey, devices: &[&Ed25519VerifyingKey]) -> Self {
            let mut bundles = HashMap::new();
            bundles.insert(
                hex::encode(account.as_ref()),
                devices.iter().map(|d| hex::encode(d.as_ref())).collect(),
            );
            Self {
                bundles,
                fail: false,
            }
        }
    }

    impl libchat::AccountDirectory for FakeDir {
        type Error = &'static str;

        fn publish(&mut self, _: &SignedDeviceBundle) -> Result<(), Self::Error> {
            Ok(())
        }

        fn fetch(&self, account: &Ed25519VerifyingKey) -> Result<Option<DeviceSet>, Self::Error> {
            if self.fail {
                return Err("directory unavailable");
            }
            Ok(self
                .bundles
                .get(&hex::encode(account.as_ref()))
                .map(|devices| DeviceSet {
                    lamport: 1,
                    devices: devices.clone(),
                }))
        }
    }

    fn key() -> Ed25519VerifyingKey {
        Ed25519SigningKey::generate().verifying_key()
    }

    /// Encode a credential exactly as it travels on the wire: the hex of the
    /// serialized TLV, matching the MLS leaf credential's content bytes.
    fn encoded(cred: DelegateCredential) -> Vec<u8> {
        hex::encode(cred.serialize()).into_bytes()
    }

    fn local_id(k: &Ed25519VerifyingKey) -> IdentId {
        IdentId::new(hex::encode(k.as_ref()))
    }

    /// The account published a device set that includes the sending device — the
    /// claim checks out, so the message is delivered with a verified account.
    #[test]
    fn verified_sender_surfaces_account_and_device() {
        let account = key();
        let device = key();
        let dir = FakeDir::with_devices(&account, &[&device]);
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Ok(Some(MessageSender {
                account: Some(local_id(&account)),
                local_identity: local_id(&device),
            }))
        );
    }

    /// The account published a device set that does NOT include the sending
    /// device — a spoofed account claim, so the message is dropped.
    #[test]
    fn contradicted_claim_is_dropped() {
        let account = key();
        let endorsed = key();
        let spoofer = key();
        let dir = FakeDir::with_devices(&account, &[&endorsed]);
        let cred = DelegateCredential::associated(&spoofer, &hex::encode(account.as_ref()));
        assert_eq!(decode_sender(&dir, &encoded(cred)), Err(SenderError::Unverified));
    }

    /// A delegate that claims no account surfaces its device but no account.
    #[test]
    fn unassociated_sender_surfaces_device_only() {
        let dir = FakeDir::default();
        let device = key();
        let cred = DelegateCredential::unassociated(&device);
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Ok(Some(MessageSender {
                account: None,
                local_identity: local_id(&device),
            }))
        );
    }

    /// The claimed account has never published a device set — the mapping is
    /// missing, so the message is dropped.
    #[test]
    fn unpublished_account_is_dropped() {
        let account = key();
        let device = key();
        let dir = FakeDir::default(); // nothing published
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert_eq!(decode_sender(&dir, &encoded(cred)), Err(SenderError::Unverified));
    }

    /// A directory outage leaves the mapping unconfirmed, so the message is
    /// dropped rather than delivered on an unverified claim.
    #[test]
    fn directory_error_is_dropped() {
        let account = key();
        let device = key();
        let dir = FakeDir {
            fail: true,
            ..Default::default()
        };
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert_eq!(decode_sender(&dir, &encoded(cred)), Err(SenderError::Unverified));
    }

    /// No credential at all (e.g. the PrivateV1 placeholder) asserts no account
    /// mapping and is delivered with no sender.
    #[test]
    fn empty_credential_has_no_sender() {
        let dir = FakeDir::default();
        assert_eq!(decode_sender(&dir, b""), Ok(None));
    }

    /// Bytes that aren't a well-formed credential leave the sender's mapping
    /// undeterminable, so the message is dropped.
    #[test]
    fn malformed_credential_is_dropped() {
        let dir = FakeDir::default();
        assert_eq!(decode_sender(&dir, b"not hex"), Err(SenderError::NotHex));
        assert_eq!(
            decode_sender(&dir, hex::encode([0u8; 4]).as_bytes()),
            Err(SenderError::Malformed)
        );
    }

    /// An account address that isn't a verifying key can't be looked up, so the
    /// claim is unconfirmable and the message is dropped.
    #[test]
    fn non_key_account_address_is_dropped() {
        let dir = FakeDir::default();
        let cred = DelegateCredential::associated(&key(), "user@example.com");
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::AccountNotAKey)
        );
    }
}
