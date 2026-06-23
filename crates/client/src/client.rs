use std::sync::Arc;
use std::thread::{self, JoinHandle};

use components::{EphemeralRegistry, ThreadedWakeupService, WakeupEvent};
use crossbeam_channel::{Receiver, Sender, select};
use crypto::Ed25519VerifyingKey;
use libchat::{
    AccountDirectory, ChatError, ChatStorage, ConversationId, ConvoOutcome, Core, DeliveryService,
    IdentId, IdentIdRef, InboxOutcome, Introduction, PayloadOutcome, RegistrationService,
    StorageConfig,
};
use parking_lot::Mutex;

use crate::delegate::{DelegateCredential, DelegateSigner};
use crate::errors::ClientError;
use crate::event::Event;

type ClientCore<T, R> = Core<(DelegateSigner, T, R, ThreadedWakeupService, ChatStorage)>;
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
pub struct ChatClient<T: DeliveryService, R: RegistrationService = EphemeralRegistry> {
    /// `parking_lot::Mutex` for its eventual fairness: an inbound burst can't
    /// starve caller operations of the lock.
    core: Arc<Mutex<ClientCore<T, R>>>,
    /// Dropped on `Drop` to wake the worker's `select!` and shut it down.
    shutdown: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
}

// ── Default-registry constructors ────────────────────────────────────────────

impl<T: Transport> ChatClient<T, EphemeralRegistry> {
    /// Create an in-memory, ephemeral client. Identity is lost on drop.
    pub fn new(_: impl Into<String>, mut transport: T) -> (Self, Receiver<Event>) {
        let inbound = transport.inbound();
        let delegate = DelegateSigner::random();

        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let core = Core::new_with_name(
            delegate,
            transport,
            EphemeralRegistry::new(),
            wakeup_service,
            ChatStorage::in_memory(),
        )
        .unwrap();
        Self::spawn(core, inbound, wakeup_rx)
    }

    /// Open or create a persistent client backed by `StorageConfig`.
    ///
    /// If an identity already exists in storage it is loaded; otherwise a new
    /// one is created and saved.
    pub fn open(
        _: impl Into<String>,
        config: StorageConfig,
        mut transport: T,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let store = ChatStorage::new(config).map_err(ChatError::from)?;
        let inbound = transport.inbound();
        let delegate = DelegateSigner::random();
        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let core = Core::new_from_store(
            delegate,
            transport,
            EphemeralRegistry::new(),
            wakeup_service,
            store,
        )?;
        Ok(Self::spawn(core, inbound, wakeup_rx))
    }
}

// ── Caller-supplied registry + shared methods ────────────────────────────────

impl<T, R> ChatClient<T, R>
where
    T: Transport + Send + 'static,
    R: RegistrationService + Send + 'static,
{
    /// Open or create a persistent client with a caller-supplied registration
    /// service. Use this to swap in a network-backed registry (e.g. the
    /// testnet KeyPackage Registry) in place of the default in-memory store.
    ///
    /// Submits this account's KeyPackage to the registry as the last step of
    /// construction. The default in-memory `open` path skips this call, but
    /// when a real registry is wired in we want each session to publish so
    /// other clients can fetch it.
    pub fn open_with_registry(
        _: impl Into<String>,
        config: StorageConfig,
        mut transport: T,
        registry: R,
    ) -> Result<(Self, Receiver<Event>), ClientError>
    where
        T: Transport,
    {
        let store = ChatStorage::new(config).map_err(ChatError::from)?;
        let inbound = transport.inbound();
        let delegate = DelegateSigner::random();
        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let mut core = Core::new_from_store(delegate, transport, registry, wakeup_service, store)?;
        core.register_keypackage()?;
        Ok(Self::spawn(core, inbound, wakeup_rx))
    }

    /// Create a client with ephemeral storage with the provided Transport and RegistrationService.
    pub fn new_ephemeral(
        delegate: DelegateSigner,
        mut transport: T,
        reg: R,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let inbound = transport.inbound();

        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let core = Core::new_with_name(
            delegate,
            transport,
            reg,
            wakeup_service,
            ChatStorage::in_memory(),
        )?;
        Ok(Self::spawn(core, inbound, wakeup_rx))
    }

    fn spawn(
        core: ClientCore<T, R>,
        inbound: Receiver<Vec<u8>>,
        wakeup_events: Receiver<WakeupEvent>,
    ) -> (Self, Receiver<Event>) {
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
            },
            event_rx,
        )
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

impl<T: DeliveryService, R: RegistrationService> Drop for ChatClient<T, R> {
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
fn worker_loop<T, R>(
    core: Arc<Mutex<ClientCore<T, R>>>,
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

/// Whether to surface a received message, given its sender credential checked
/// against the account → device directory (our account store).
///
/// The credential binds a delegate device key to an optional account address.
/// When it claims an account, that account's published device set must include
/// this device — otherwise the account→device mapping is wrong or unconfirmable
/// and the message is dropped (`false`). A credential that claims no account (or
/// no credential at all) asserts no mapping, so it is delivered (`true`).
fn should_deliver(directory: &impl AccountDirectory, encoded: &[u8]) -> bool {
    // No credential (e.g. the PrivateV1 placeholder) asserts no account mapping.
    if encoded.is_empty() {
        return true;
    }
    let Ok(data) = hex::decode(encoded) else {
        tracing::warn!("sender credential is not valid hex; dropping message");
        return false;
    };
    let cred = match DelegateCredential::try_from(data) {
        Ok(cred) => cred,
        Err(_) => {
            tracing::warn!("malformed sender credential; dropping message");
            return false;
        }
    };
    let device = hex::encode(cred.delegate_id().as_ref());
    // An unassociated delegate asserts no account → device mapping.
    let Some(account_addr) = cred.account_addr() else {
        return true;
    };
    let Some(account_key) = account_key_from_hex(account_addr) else {
        tracing::warn!(
            account_addr,
            "sender account address is not a verifying key; dropping message"
        );
        return false;
    };
    match directory.fetch(&account_key) {
        Ok(Some(set)) if set.devices.iter().any(|d| d == &device) => true,
        _ => {
            tracing::warn!(account_addr, %device, "account → device mapping is wrong or unconfirmable; dropping message");
            false
        }
    }
}

fn convo_events(outcome: ConvoOutcome, directory: &impl AccountDirectory) -> Vec<Event> {
    let ConvoOutcome { convo_id, content } = outcome;
    content
        .filter(|c| should_deliver(directory, &c.encoded_credential))
        .map(|c| Event::MessageReceived {
            convo_id: Arc::from(convo_id),
            content: c.bytes,
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
        && should_deliver(directory, &c.encoded_credential)
    {
        events.push(Event::MessageReceived {
            convo_id: Arc::clone(&id),
            content: c.bytes,
        });
    }
    events
}

#[cfg(test)]
mod sender_check_tests {
    use std::collections::HashMap;

    use crypto::{Ed25519SigningKey, Ed25519VerifyingKey};
    use libchat::{DeviceSet, SignedDeviceBundle};

    use super::should_deliver;
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

    /// The account published a device set that includes the sending device — the
    /// claim checks out, so the message is delivered.
    #[test]
    fn verified_sender_is_delivered() {
        let account = key();
        let device = key();
        let dir = FakeDir::with_devices(&account, &[&device]);
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert!(should_deliver(&dir, &encoded(cred)));
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
        assert!(!should_deliver(&dir, &encoded(cred)));
    }

    /// A delegate that claims no account makes no mapping to contradict.
    #[test]
    fn unassociated_sender_is_delivered() {
        let dir = FakeDir::default();
        let cred = DelegateCredential::unassociated(&key());
        assert!(should_deliver(&dir, &encoded(cred)));
    }

    /// The claimed account has never published a device set — the mapping is
    /// missing, so the message is dropped.
    #[test]
    fn unpublished_account_is_dropped() {
        let account = key();
        let device = key();
        let dir = FakeDir::default(); // nothing published
        let cred = DelegateCredential::associated(&device, &hex::encode(account.as_ref()));
        assert!(!should_deliver(&dir, &encoded(cred)));
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
        assert!(!should_deliver(&dir, &encoded(cred)));
    }

    /// No credential at all (e.g. the PrivateV1 placeholder) asserts no account
    /// mapping and is delivered.
    #[test]
    fn empty_credential_is_delivered() {
        let dir = FakeDir::default();
        assert!(should_deliver(&dir, b""));
    }

    /// Bytes that aren't a well-formed credential leave the sender's mapping
    /// undeterminable, so the message is dropped.
    #[test]
    fn malformed_credential_is_dropped() {
        let dir = FakeDir::default();
        assert!(!should_deliver(&dir, b"not hex"));
        assert!(!should_deliver(&dir, hex::encode([0u8; 4]).as_bytes()));
    }

    /// An account address that isn't a verifying key can't be looked up, so the
    /// claim is unconfirmable and the message is dropped.
    #[test]
    fn non_key_account_address_is_dropped() {
        let dir = FakeDir::default();
        let cred = DelegateCredential::associated(&key(), "user@example.com");
        assert!(!should_deliver(&dir, &encoded(cred)));
    }
}
