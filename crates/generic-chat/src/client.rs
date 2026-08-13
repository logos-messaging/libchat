use std::collections::HashSet;
use std::sync::Arc;
use std::thread::{self, JoinHandle};

use components::{ThreadedWakeupService, WakeupEvent};
use crossbeam_channel::{Receiver, Sender, select};
use libchat::{
    AuthResult, AuthVerifyService, ConversationId, ConvoMetadata, ConvoOutcome, Core,
    DeliveryService, GroupV2Config, IdentId, IdentIdRef, InboxOutcome, PayloadOutcome,
    RegistrationService, SignerId, UnverifiedSender,
};
use logos_account::{AccountAddr, AccountRegistry};
use parking_lot::Mutex;
use storage::ChatStore;

use crate::delegate::{DelegateCredential, DelegateIdentity, DelegateSigner};
use crate::errors::ClientError;
use crate::event::{Event, MessageSender};

#[derive(Debug, Clone, Default)]
pub struct LogosAuthVerifier {}

impl LogosAuthVerifier {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AuthVerifyService for LogosAuthVerifier {
    fn validate(&self, _signer: &[u8], _credential: &[u8]) -> AuthResult {
        AuthResult::Valid
    }
}

type ClientCore<T, R, S> = Core<(DelegateIdentity, T, R, ThreadedWakeupService, S)>;
/// An account address as the client handles it: opaque bytes, interpreted only
/// where they meet the account layer.
type AccountAddressRef<'a> = &'a [u8];
type LocalSignerId = IdentId;

/// A member of a group conversation's roster.
///
/// Shares [`MessageSender`]'s field semantics: `account` is set only when the
/// member's credential claimed an account *and* the registry confirmed the
/// account endorses this device. Unlike a message sender, an unconfirmable claim does
/// not hide the member: a committed member is cryptographically in the group,
/// so it is listed by `local_identity` (its device) with `account: None`.
///
/// `pending` marks a member whose add the group has not committed yet, so it
/// cannot read the conversation. Only invites this client sent are reported;
/// an add another member proposed is invisible until it commits. The flag
/// clears when the commit admitting the member lands, and an invite the group
/// never commits stays pending for the life of the conversation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupMember {
    pub account: Option<Vec<u8>>,
    pub local_identity: IdentId,
    pub pending: bool,
}

/// The raw roster entry verification produces, one per MLS leaf (device): the
/// member's `signer_id`, its `cred` (the credential as MLS reports it,
/// hex-encoded), the `auth_result` of checking that credential against the auth
/// service, and whether its add is still `pending`. [`ChatClient::group_members`]
/// resolves these into [`GroupMember`]s; [`ChatClient::group_members_including_invalid`]
/// exposes them directly so a caller can see members that failed verification.
#[derive(Debug)]
pub struct MemberWithAuthResult {
    pub signer_id: SignerId,
    pub cred: Vec<u8>,
    pub auth_result: AuthResult,
    pub pending: bool,
}

impl MemberWithAuthResult {
    pub fn new(signer: UnverifiedSender, auth_result: AuthResult, pending: bool) -> Self {
        Self {
            signer_id: signer.signer_id,
            cred: signer.cred,
            auth_result,
            pending,
        }
    }

    /// Parse this member's credential, if it is well-formed. A real MLS leaf
    /// always is; `None` marks a credential MLS reported that this client can't
    /// decode.
    fn credential(&self) -> Option<DelegateCredential> {
        let ident = IdentId::new(String::from_utf8(self.cred.clone()).ok()?);
        DelegateCredential::try_from(ident).ok()
    }

    /// The account this member's credential claims, if any. Trustworthy only
    /// when `auth_result` is `Valid`; the credential asserts it, unverified.
    pub fn account_claim(&self) -> Option<Vec<u8>> {
        self.credential()?.account_addr().map(<[u8]>::to_vec)
    }
}

impl From<MemberWithAuthResult> for GroupMember {
    /// Resolve a verified roster entry into its public form: the account is
    /// surfaced only when verification passed, so an unconfirmable member stays
    /// listed by device with `account: None` rather than being hidden.
    fn from(member: MemberWithAuthResult) -> Self {
        let cred = member.credential();
        let local_identity = cred
            .as_ref()
            .map(|c| IdentId::new(hex::encode(c.delegate_id().as_ref())))
            .unwrap_or_else(|| IdentId::new(hex::encode(member.signer_id.as_bytes())));
        let account = (member.auth_result == AuthResult::Valid)
            .then(|| cred.and_then(|c| c.account_addr().map(<[u8]>::to_vec)))
            .flatten();
        GroupMember {
            account,
            local_identity,
            pending: member.pending,
        }
    }
}

/// Metadata a caller supplies when creating a group: its shared name and
/// description. Distinct from [`ConvoMetadata`], the type a conversation
/// reports back — the two carry different concerns and evolve independently
/// (the reported metadata may grow fields a caller cannot set).
#[derive(Debug, Clone)]
pub struct GroupMetadata {
    pub name: String,
    pub desc: String,
}

impl GroupMetadata {
    pub fn new(name: impl Into<String>, desc: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            desc: desc.into(),
        }
    }
}

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
pub struct ChatClient<AS, T, R, S>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + AccountRegistry + Clone + Send + 'static,
    S: ChatStore + Send + 'static,
{
    /// `parking_lot::Mutex` for its eventual fairness: an inbound burst can't
    /// starve caller operations of the lock.
    core: Arc<Mutex<ClientCore<T, R, S>>>,
    account_verify_service: AS,
    /// The account registry. On testnet the registration service doubles as the
    /// account store (one deployed registry serves both roles), so the client
    /// keeps its own clone of `R`; the core sees key packages only.
    accounts: R,
    /// Dropped on `Drop` to wake the worker's `select!` and shut it down.
    shutdown: Option<Sender<()>>,
    worker: Option<JoinHandle<()>>,
    address: Vec<u8>,
}

// -- GenericChatClient
impl<AS, T, R, S> ChatClient<AS, T, R, S>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + AccountRegistry + Clone + Send + 'static,
    S: ChatStore + Send + 'static,
{
    pub fn new(
        ident: DelegateSigner,
        auth: AS,
        account: Vec<u8>,
        mut transport: T,
        reg: R,
        storage: S,
        group_v2: Option<GroupV2Config>,
    ) -> Result<(Self, Receiver<Event>), ClientError> {
        let inbound = transport.inbound();

        let (wakeup_tx, wakeup_rx) = crossbeam_channel::unbounded();
        let wakeup_service = ThreadedWakeupService::new(wakeup_tx);
        let accounts = reg.clone();
        let ident = DelegateIdentity::new(ident, &account);
        let mut core = Core::new_with_name(ident, transport, reg, wakeup_service, storage)?;
        if let Some(config) = group_v2 {
            core.set_group_v2_config(config);
        }
        Ok(Self::spawn(
            core, auth, accounts, account, inbound, wakeup_rx,
        ))
    }

    fn spawn(
        core: ClientCore<T, R, S>,
        auth: AS,
        accounts: R,
        address: Vec<u8>,
        inbound: Receiver<Vec<u8>>,
        wakeup_events: Receiver<WakeupEvent>,
    ) -> (Self, Receiver<Event>) {
        let core = Arc::new(Mutex::new(core));
        let (event_tx, event_rx) = crossbeam_channel::unbounded();
        let (shutdown_tx, shutdown_rx) = crossbeam_channel::bounded::<()>(0);

        let worker = thread::spawn({
            let core = Arc::clone(&core);
            let accounts = accounts.clone();
            move || {
                worker_loop(
                    core,
                    accounts,
                    inbound,
                    wakeup_events,
                    shutdown_rx,
                    event_tx,
                )
            }
        });

        (
            Self {
                core,
                account_verify_service: auth,
                accounts,
                shutdown: Some(shutdown_tx),
                worker: Some(worker),
                address,
            },
            event_rx,
        )
    }

    /// The account address peers use to reach this client.
    pub fn addr(&self) -> &[u8] {
        &self.address
    }

    /// Returns the installation name (identity label) of this client.
    pub fn installation_name(&self) -> String {
        self.core.lock().installation_name().to_string()
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

    /// Create a GroupV2 conversation with the given accounts' devices. Each
    /// account resolves to the signer ids its account log endorses; the
    /// group invite goes to every one of them. An empty slice creates a group
    /// with only this client, to grow via [`Self::add_group_members`].
    /// `metadata` becomes the group's shared name and description, carried to
    /// every joiner in the welcome and readable via [`Self::group_metadata`];
    /// both fields may be empty.
    pub fn create_group_conversation(
        &mut self,
        accounts: &[AccountAddressRef],
        metadata: GroupMetadata,
    ) -> Result<ConversationId, ClientError> {
        let signers = self.signers_from_accounts(accounts)?;
        let signer_refs: Vec<IdentIdRef> = signers.iter().collect();

        self.core
            .lock()
            .create_group_convo_v2(&signer_refs, &metadata.name, &metadata.desc)
            .map_err(Into::into)
    }

    /// Add accounts' devices to an existing group conversation. The add is
    /// staged as an MLS proposal and merged by the group's next commit (driven
    /// asynchronously by the wakeup loop); each joiner's welcome is sent when
    /// that commit lands, not when this call returns.
    pub fn add_group_members(
        &mut self,
        convo_id: &str,
        accounts: &[AccountAddressRef],
    ) -> Result<(), ClientError> {
        let signers = self.signers_from_accounts(accounts)?;
        let signer_refs: Vec<IdentIdRef> = signers.iter().collect();

        self.core
            .lock()
            .group_add_member(convo_id, &signer_refs)
            .map_err(Into::into)
    }

    /// The group's roster as [`GroupMember`]s (self included): one entry per
    /// member device, with the account surfaced only when its credential
    /// verified. Members whose add the group has not committed yet are flagged
    /// `pending`. An unverifiable member is not hidden — it stays listed by
    /// device with `account: None`.
    pub fn group_members(&mut self, convo_id: &str) -> Result<Vec<GroupMember>, ClientError> {
        Ok(self
            .group_members_including_invalid(convo_id)?
            .into_iter()
            .map(GroupMember::from)
            .collect())
    }

    /// The raw roster before resolution: every member device paired with its
    /// verification result, including those that failed to verify (which
    /// [`Self::group_members`] would list without an account). Committed members
    /// come before pending ones; a device present in both collapses to its
    /// committed entry.
    pub fn group_members_including_invalid(
        &mut self,
        convo_id: &str,
    ) -> Result<Vec<MemberWithAuthResult>, ClientError> {
        let (committed, pending) = {
            let mut core = self.core.lock();
            (
                core.group_members(convo_id)?,
                core.group_pending_members(convo_id)?,
            )
        };
        let members = committed
            .into_iter()
            .map(|sender| (sender, false))
            .chain(pending.into_iter().map(|sender| (sender, true)))
            .map(|(sender, pending)| {
                let auth_result = self.verify_member(&sender);
                MemberWithAuthResult::new(sender, auth_result, pending)
            });
        Ok(dedup_members(members))
    }

    /// The group's shared metadata (name and description), set at creation and
    /// carried to every joiner in the welcome. Both fields may be empty. Fails
    /// for a direct conversation and for a legacy group that carries no metadata.
    pub fn group_metadata(&self, convo_id: &str) -> Result<ConvoMetadata, ClientError> {
        self.core
            .lock()
            .convo_metadata(convo_id)
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

    /// Resolve an account address to the signer (device) ids its published log
    /// endorses. A reachable account has published at least one signer;
    /// anything else is an error.
    fn signers_from_account(
        &self,
        account: AccountAddressRef,
    ) -> Result<Vec<LocalSignerId>, ClientError> {
        let addr = AccountAddr::try_from(account)
            .map_err(|_| ClientError::AccountResolution("not an account address".into()))?;
        let keys = self
            .accounts
            .endorsed_ed25519_keys(&addr)
            .map_err(|e| ClientError::AccountResolution(e.to_string()))?
            .filter(|keys| !keys.is_empty())
            .ok_or_else(|| {
                ClientError::AccountResolution("account endorses no signer".to_string())
            })?;
        // A signer id is the hex of its verifying key — what the keypackage
        // registry is keyed by.
        Ok(keys
            .iter()
            .map(|key| IdentId::new(hex::encode(key.as_ref())))
            .collect())
    }

    /// Resolve each account to its signer ids and flatten them, failing on the
    /// first unresolvable account.
    fn signers_from_accounts(
        &self,
        accounts: &[AccountAddressRef],
    ) -> Result<Vec<LocalSignerId>, ClientError> {
        let mut signers = Vec::new();
        for account in accounts {
            signers.extend(self.signers_from_account(account)?);
        }
        Ok(signers)
    }

    fn verify_member(&self, member: &UnverifiedSender) -> AuthResult {
        self.account_verify_service
            .validate(member.signer_id.as_bytes(), member.cred.as_slice())
    }
}

impl<AS, T, R, S> Drop for ChatClient<AS, T, R, S>
where
    AS: AuthVerifyService + Send + 'static,
    T: Transport + Send + 'static,
    R: RegistrationService + AccountRegistry + Clone + Send + 'static,
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
fn worker_loop<T, R, S: ChatStore + 'static>(
    core: Arc<Mutex<ClientCore<T, R, S>>>,
    accounts: R,
    inbound: Receiver<Vec<u8>>,
    wakeup_events: Receiver<WakeupEvent>,
    shutdown: Receiver<()>,
    event_tx: Sender<Event>,
) where
    T: DeliveryService + Send + 'static,
    R: RegistrationService + AccountRegistry + Send + 'static,
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
                        Ok(outcome) => events_from_inbound(outcome, &accounts),
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
                // A wakeup can drive the steward's own commit, so it yields events too.
                let events = match core.lock().wakeup(&convo_id) {
                    Ok(outcome) => events_from_inbound(outcome, &accounts),
                    Err(e) => {
                        tracing::warn!("wakeup failed: {e:?}");
                        Vec::new()
                    }
                };
                for event in events {
                    if event_tx.send(event).is_err() {
                        return; // application dropped the receiver
                    }
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
fn events_from_inbound(result: PayloadOutcome, accounts: &impl AccountRegistry) -> Vec<Event> {
    match result {
        PayloadOutcome::Empty => Vec::new(),
        PayloadOutcome::Convo(co) => convo_events(co, accounts),
        PayloadOutcome::Inbox(io) => inbox_events(io, accounts),
    }
}

/// Why a message's sender could not be accepted, so the message is dropped.
#[derive(Debug, PartialEq, Eq)]
enum SenderError {
    /// No credential at all, so no sender can be attributed. Every delivered
    /// message must carry an explicit sender.
    Missing,
    /// Credential bytes were not valid hex.
    NotHex,
    /// Credential bytes did not decode to a delegate credential.
    Malformed,
    /// The claimed account address is not the bytes of an Ed25519 verifying key.
    AccountNotAKey,
    /// The endorsement is missing or could not be confirmed: the account does
    /// not endorse this device, it published nothing, or the lookup failed.
    Unverified,
}

/// The resolution of a credential's account claim against the registry.
enum AccountClaim {
    /// The credential claimed no account.
    None,
    /// Confirmed: the account endorses this device.
    Verified(Vec<u8>),
    /// An account was claimed but could not be confirmed (see [`SenderError`]).
    Unverified(SenderError),
}

/// Parse a wire credential into the device it names and the resolution of any
/// account claim, checked against the account registry. `Err` only when no
/// device can be attributed at all (missing or unparseable credential).
///
/// The account-claim policy is left to the caller: a message drops on an
/// unconfirmable claim, a roster entry keeps the device and forgoes the account.
fn parse_credential(
    accounts: &impl AccountRegistry,
    encoded: &[u8],
) -> Result<(IdentId, AccountClaim), SenderError> {
    // No credential at all: there is no device to attribute.
    if encoded.is_empty() {
        return Err(SenderError::Missing);
    }
    let Ok(data) = hex::decode(encoded) else {
        tracing::warn!("credential is not valid hex");
        return Err(SenderError::NotHex);
    };
    let Ok(cred) = DelegateCredential::try_from(data) else {
        tracing::warn!("malformed credential");
        return Err(SenderError::Malformed);
    };
    let device = IdentId::new(hex::encode(cred.delegate_id().as_ref()));
    // An unassociated delegate claims no account.
    let Some(account_addr) = cred.account_addr() else {
        return Ok((device, AccountClaim::None));
    };
    let Ok(addr) = AccountAddr::try_from(account_addr) else {
        tracing::warn!(account_addr = %hex::encode(account_addr), "account address is not a verifying key");
        return Ok((
            device,
            AccountClaim::Unverified(SenderError::AccountNotAKey),
        ));
    };
    let claim = match accounts.is_ed25519_endorsed(cred.delegate_id(), &addr) {
        Ok(true) => AccountClaim::Verified(account_addr.to_vec()),
        _ => {
            tracing::warn!(account_addr = %addr, device = %device.as_str(), "account does not endorse this device, or the endorsement is unconfirmable");
            AccountClaim::Unverified(SenderError::Unverified)
        }
    };
    Ok((device, claim))
}

/// Decode and verify a message's sender from its credential, checked against
/// the account registry.
///
/// `Ok(sender)` — deliver with the sender; its `account` is set only when the
/// registry confirmed the endorsement, so it is always verified. `Err` — drop
/// the message (including when no credential is present, since every delivered
/// message must carry an explicit sender).
fn decode_sender(
    accounts: &impl AccountRegistry,
    encoded: &[u8],
) -> Result<MessageSender, SenderError> {
    let (device, claim) = parse_credential(accounts, encoded)?;
    match claim {
        AccountClaim::None => Ok(MessageSender {
            account: None,
            local_identity: device,
        }),
        AccountClaim::Verified(account) => Ok(MessageSender {
            account: Some(account),
            local_identity: device,
        }),
        // An unconfirmable account claim drops the message: every delivered
        // message must carry a verified sender.
        AccountClaim::Unverified(err) => Err(err),
    }
}

/// Collapse a roster to one entry per credential (device), keeping the
/// first-seen entry, order preserved. Callers chain committed members ahead of
/// pending ones, so a device present in both keeps its committed entry.
fn dedup_members(
    members: impl IntoIterator<Item = MemberWithAuthResult>,
) -> Vec<MemberWithAuthResult> {
    let mut seen = HashSet::new();
    members
        .into_iter()
        .filter(|member| seen.insert(member.cred.clone()))
        .collect()
}

fn convo_events(outcome: ConvoOutcome, accounts: &impl AccountRegistry) -> Vec<Event> {
    let ConvoOutcome {
        convo_id,
        content,
        members_changed,
    } = outcome;
    let convo_id: Arc<str> = Arc::from(convo_id);
    let mut events = Vec::new();
    if let Some(c) = content
        && let Ok(sender) = decode_sender(accounts, &c.encoded_credential)
    {
        events.push(Event::MessageReceived {
            convo_id: Arc::clone(&convo_id),
            content: c.bytes,
            sender,
        });
    }
    if members_changed {
        events.push(Event::ConversationMembersChanged { convo_id });
    }
    events
}

fn inbox_events(outcome: InboxOutcome, accounts: &impl AccountRegistry) -> Vec<Event> {
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
        && let Ok(sender) = decode_sender(accounts, &c.encoded_credential)
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
    use libchat::IdentId;
    use logos_account::{AccountAddr, AccountRegistry};

    use libchat::{AuthResult, SignerId};

    use super::{
        GroupMember, MemberWithAuthResult, MessageSender, SenderError, decode_sender, dedup_members,
    };
    use crate::delegate::DelegateCredential;

    /// In-test account registry. Holds the endorsed key set per account, and
    /// can be made to fail to simulate a registry outage.
    #[derive(Debug, Default)]
    struct FakeDir {
        endorsements: HashMap<AccountAddr, Vec<Ed25519VerifyingKey>>,
        fail: bool,
    }

    impl FakeDir {
        /// Endorse `devices` (verifying keys) under `account`.
        fn with_devices(account: &Ed25519VerifyingKey, devices: &[&Ed25519VerifyingKey]) -> Self {
            let mut endorsements = HashMap::new();
            endorsements.insert(
                AccountAddr::from(account),
                devices.iter().map(|d| (*d).clone()).collect(),
            );
            Self {
                endorsements,
                fail: false,
            }
        }
    }

    impl AccountRegistry for FakeDir {
        type Error = &'static str;

        fn endorsed_ed25519_keys(
            &self,
            addr: &AccountAddr,
        ) -> Result<Option<Vec<Ed25519VerifyingKey>>, Self::Error> {
            if self.fail {
                return Err("registry unavailable");
            }
            Ok(self.endorsements.get(addr).cloned())
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

    /// An account address as the client carries it: the raw key bytes.
    fn account_addr(k: &Ed25519VerifyingKey) -> Vec<u8> {
        k.as_ref().to_vec()
    }

    /// The account published a device set that includes the sending device — the
    /// claim checks out, so the message is delivered with a verified account.
    #[test]
    fn verified_sender_surfaces_account_and_device() {
        let account = key();
        let device = key();
        let dir = FakeDir::with_devices(&account, &[&device]);
        let cred = DelegateCredential::associated(&device, account.as_ref());
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Ok(MessageSender {
                account: Some(account_addr(&account)),
                local_identity: local_id(&device),
            })
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
        let cred = DelegateCredential::associated(&spoofer, account.as_ref());
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::Unverified)
        );
    }

    /// A delegate that claims no account surfaces its device but no account.
    #[test]
    fn unassociated_sender_surfaces_device_only() {
        let dir = FakeDir::default();
        let device = key();
        let cred = DelegateCredential::unassociated(&device);
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Ok(MessageSender {
                account: None,
                local_identity: local_id(&device),
            })
        );
    }

    /// The claimed account has never published a device set — the mapping is
    /// missing, so the message is dropped.
    #[test]
    fn unpublished_account_is_dropped() {
        let account = key();
        let device = key();
        let dir = FakeDir::default(); // nothing published
        let cred = DelegateCredential::associated(&device, account.as_ref());
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::Unverified)
        );
    }

    /// A registry outage leaves the endorsement unconfirmed, so the message is
    /// dropped rather than delivered on an unverified claim.
    #[test]
    fn registry_error_is_dropped() {
        let account = key();
        let device = key();
        let dir = FakeDir {
            fail: true,
            ..Default::default()
        };
        let cred = DelegateCredential::associated(&device, account.as_ref());
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::Unverified)
        );
    }

    /// An empty credential leaves no sender to attribute, so the message is dropped.
    #[test]
    fn empty_credential_is_dropped() {
        let dir = FakeDir::default();
        assert_eq!(decode_sender(&dir, b""), Err(SenderError::Missing));
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
        let cred = DelegateCredential::associated(&key(), b"user@example.com");
        assert_eq!(
            decode_sender(&dir, &encoded(cred)),
            Err(SenderError::AccountNotAKey)
        );
    }

    /// Build a raw roster entry from a credential and its verification result,
    /// as `group_members` would before resolving it into a [`GroupMember`].
    fn member_entry(
        cred: DelegateCredential,
        auth_result: AuthResult,
        pending: bool,
    ) -> MemberWithAuthResult {
        let signer_id = SignerId::from(cred.delegate_id().as_ref());
        MemberWithAuthResult {
            signer_id,
            cred: encoded(cred),
            auth_result,
            pending,
        }
    }

    /// A verified member resolves to its account and device — the credential's
    /// account claim, trusted because verification passed.
    #[test]
    fn resolves_verified_member_to_account_and_device() {
        let account = key();
        let device = key();
        let cred = DelegateCredential::associated(&device, account.as_ref());
        assert_eq!(
            GroupMember::from(member_entry(cred, AuthResult::Valid, false)),
            GroupMember {
                account: Some(account_addr(&account)),
                local_identity: local_id(&device),
                pending: false,
            }
        );
    }

    /// A member whose credential failed verification is not hidden: it is listed
    /// by device with no account.
    #[test]
    fn resolves_unverified_member_to_device_without_account() {
        let account = key();
        let device = key();
        let cred = DelegateCredential::associated(&device, account.as_ref());
        assert_eq!(
            GroupMember::from(member_entry(cred, AuthResult::Mismatch, false)),
            GroupMember {
                account: None,
                local_identity: local_id(&device),
                pending: false,
            }
        );
    }

    /// A member whose credential claims no account is listed by device only,
    /// even when verification passed.
    #[test]
    fn resolves_unassociated_member_to_device_without_account() {
        let device = key();
        let cred = DelegateCredential::unassociated(&device);
        assert_eq!(
            GroupMember::from(member_entry(cred, AuthResult::Valid, false)),
            GroupMember {
                account: None,
                local_identity: local_id(&device),
                pending: false,
            }
        );
    }

    /// Resolution carries the pending flag through to the public entry.
    #[test]
    fn resolves_pending_flag_onto_the_public_entry() {
        let device = key();
        let cred = DelegateCredential::unassociated(&device);
        assert!(GroupMember::from(member_entry(cred, AuthResult::Valid, true)).pending);
    }

    /// The roster collapses members that share a credential into one entry
    /// (keeping the first seen) while leaving distinct credentials individual,
    /// order preserved.
    #[test]
    fn dedup_collapses_duplicate_credentials_and_keeps_distinct() {
        let member = |cred: &str| MemberWithAuthResult {
            signer_id: SignerId::from(cred.as_bytes()),
            cred: cred.as_bytes().to_vec(),
            auth_result: AuthResult::Valid,
            pending: false,
        };
        let roster = dedup_members(vec![
            member("alice-dev-1"),
            member("alice-dev-1"),
            member("orphan-x"),
            member("bob-dev-1"),
            member("orphan-y"),
        ]);
        let creds: Vec<&[u8]> = roster.iter().map(|m| m.cred.as_slice()).collect();
        assert_eq!(
            creds,
            [
                b"alice-dev-1".as_slice(),
                b"orphan-x",
                b"bob-dev-1",
                b"orphan-y",
            ]
        );
    }

    /// A device present in both the committed and pending lists collapses to a
    /// single entry: callers chain committed members first, so dedup keeps that
    /// one and the survivor is not flagged pending.
    #[test]
    fn dedup_collapses_a_pending_duplicate_into_the_committed_member() {
        let entry = |pending: bool| MemberWithAuthResult {
            signer_id: SignerId::from(b"alice-dev-1".as_slice()),
            cred: b"alice-dev-1".to_vec(),
            auth_result: AuthResult::Valid,
            pending,
        };
        let roster = dedup_members(vec![entry(false), entry(true)]);
        assert_eq!(roster.len(), 1);
        assert!(!roster[0].pending);
    }
}
