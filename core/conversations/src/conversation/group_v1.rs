/// GroupV1 is a conversationType which provides effecient handling of multiple participants
/// Properties:
///     - Harvest Now Decrypt Later (HNDL) protection provided by XWING
///     - Multiple
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use chat_proto::logoschat::reliability::ReliablePayload;
use shared_traits::IdentIdRef;
use openmls::prelude::tls_codec::Deserialize;
use openmls::prelude::*;
use prost::Message as _;

use crate::inbox_v2::MlsProvider;
use crate::service_context::{ExternalServices, ServiceContext};

use crate::{
    DeliveryService, IdentityProvider,
    conversation::{ChatError, Convo, GroupConvo},
    outcomes::{Content, ConvoOutcome},
    service_traits::KeyPackageProvider,
    types::AddressedEncryptedPayload,
};

pub struct GroupV1Convo {
    mls_group: MlsGroup,
    convo_id: String,
}

impl std::fmt::Debug for GroupV1Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV1Convo")
            .field("convo_id", &self.convo_id)
            .field("mls_epoch", &self.mls_group.epoch())
            .finish_non_exhaustive()
    }
}

impl GroupV1Convo {
    // Create a new conversation with the creator as the only participant.
    pub fn new<S: ExternalServices>(cx: &mut ServiceContext<S>) -> Result<Self, ChatError> {
        let config = Self::mls_create_config();
        let mls_group = MlsGroup::new(
            &cx.mls_provider,
            &cx.mls_identity,
            &config,
            cx.mls_identity.get_credential(),
        )
        .unwrap();
        let convo_id = hex::encode(mls_group.group_id().as_slice());
        Self::subscribe(&mut cx.ds, &convo_id)?;

        Ok(Self {
            mls_group,
            convo_id,
        })
    }

    // Constructs a new conversation upon receiving a MlsWelcome message.
    pub fn new_from_welcome<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        welcome: Welcome,
    ) -> Result<Self, ChatError> {
        let mls_group =
            StagedWelcome::build_from_welcome(&cx.mls_provider, &Self::mls_join_config(), welcome)
                .unwrap()
                .build()
                .unwrap()
                .into_group(&cx.mls_provider)
                .unwrap();

        let convo_id = hex::encode(mls_group.group_id().as_slice());
        Self::subscribe(&mut cx.ds, &convo_id)?;

        Ok(Self {
            mls_group,
            convo_id,
        })
    }

    pub fn load<S: ExternalServices>(
        cx: &mut ServiceContext<S>,
        convo_id: String,
        group_id: GroupId,
    ) -> Result<Self, ChatError> {
        let mls_group = MlsGroup::load(cx.mls_provider.storage(), &group_id)
            .map_err(ChatError::generic)?
            .ok_or_else(|| ChatError::NoConvo("mls group not found".into()))?;

        Self::subscribe(&mut cx.ds, &convo_id)?;

        Ok(GroupV1Convo {
            mls_group,
            convo_id,
        })
    }

    // Configure the delivery service to listen for the required delivery addresses.
    fn subscribe(ds: &mut impl DeliveryService, convo_id: &str) -> Result<(), ChatError> {
        ds.subscribe(&Self::delivery_address_from_id(convo_id))
            .map_err(ChatError::generic)?;
        ds.subscribe(&Self::ctrl_delivery_address_from_id(convo_id))
            .map_err(ChatError::generic)?;

        Ok(())
    }

    fn mls_create_config() -> MlsGroupCreateConfig {
        MlsGroupCreateConfig::builder()
            .ciphersuite(Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519)
            .use_ratchet_tree_extension(true) // This is handy for now, until there is central store for this data
            .build()
    }

    fn mls_join_config() -> MlsGroupJoinConfig {
        MlsGroupJoinConfig::builder().build()
    }

    fn delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    fn delivery_address(&self) -> String {
        Self::delivery_address_from_id(&self.convo_id)
    }

    fn ctrl_delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("ctrl_delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    fn ctrl_delivery_address(&self) -> String {
        Self::ctrl_delivery_address_from_id(&self.convo_id)
    }

    fn key_package_for_account(
        &self,
        ident: IdentIdRef,
        provider: &impl MlsProvider,
        keypkg_provider: &impl KeyPackageProvider,
    ) -> Result<KeyPackage, ChatError> {
        // INTERIM: the key package registry is keyed by `DeviceId`, but resolving an
        // `AccountId` to its device(s) is a future task. For now (single device
        // per account) we use the account-id string directly as the device id.
        // When account->device resolution lands, only this conversion changes.
        let device_id = ident.to_string();
        let retrieved_bytes = keypkg_provider
            .retrieve(&device_id)
            .map_err(|e| ChatError::Generic(e.to_string()))?;

        let Some(keypkg_bytes) = retrieved_bytes else {
            return Err(ChatError::Protocol("Contact Not Found".into()));
        };

        let key_package_in = KeyPackageIn::tls_deserialize(&mut keypkg_bytes.as_slice())?;
        let key_package = key_package_in.validate(provider.crypto(), ProtocolVersion::Mls10)?; //TODO: P3 - Hardcoded Protocol Version
        Ok(key_package)
    }

    pub fn id(&self) -> &str {
        &self.convo_id
    }

    fn send_message<S: ExternalServices>(
        &mut self,
        content: &[u8],
        cx: &ServiceContext<S>,
    ) -> Result<Vec<AddressedEncryptedPayload>, ChatError> {
        let sender_id = cx.mls_identity.id().as_str();
        let reliable = cx.causal.on_send(&self.convo_id, sender_id, content);
        let wire = reliable.encode_to_vec();

        let mls_message_out = self
            .mls_group
            .create_message(&cx.mls_provider, &cx.mls_identity, &wire)
            .unwrap();

        let a = AddressedEncryptedPayload {
            delivery_address: self.delivery_address(),
            data: EncryptedPayload {
                encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                    payload: mls_message_out.to_bytes().unwrap().into(),
                })),
            },
        };

        Ok(vec![a])
    }
}

impl<S: ExternalServices> Convo<S> for GroupV1Convo {
    fn send_content(
        &mut self,
        cx: &mut ServiceContext<S>,
        content: &[u8],
    ) -> Result<(), ChatError> {
        let payloads = self.send_message(content, cx)?;
        for payload in payloads {
            cx.ds
                .publish(payload.into_envelope(self.id().into()))
                .map_err(|e| ChatError::Delivery(e.to_string()))?;
        }
        Ok(())
    }

    fn handle_frame(
        &mut self,
        cx: &mut ServiceContext<S>,
        encoded_payload: EncryptedPayload,
    ) -> Result<ConvoOutcome, ChatError> {
        let bytes = match encoded_payload.encryption {
            Some(encrypted_payload::Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::ProtocolExpectation(
                    "None",
                    "Some(Encryption::Plaintext)".into(),
                ));
            }
        };

        let mls_message =
            MlsMessageIn::tls_deserialize_exact_bytes(&bytes).map_err(ChatError::generic)?;

        let protocol_message: ProtocolMessage = mls_message
            .try_into_protocol_message()
            .map_err(ChatError::generic)?;

        if protocol_message.epoch() < self.mls_group.epoch() {
            // TODO: (P1) Add logging for messages arriving from past epoch.
            return Ok(ConvoOutcome::empty(self.id().to_string()));
        }

        let processed = self
            .mls_group
            .process_message(&cx.mls_provider, protocol_message)
            .map_err(ChatError::generic)?;

        let content = match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(msg) => {
                let reliable = ReliablePayload::decode(msg.into_bytes().as_slice())?;
                cx.causal.on_receive(&self.convo_id, &reliable);
                Some(Content {
                    bytes: reliable.content.to_vec(),
                })
            }
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.mls_group
                    .merge_staged_commit(&cx.mls_provider, *commit)
                    .map_err(ChatError::generic)?;
                None
            }
            _ => {
                // TODO: (P2) Log unknown message type
                None
            }
        };
        Ok(ConvoOutcome {
            convo_id: self.id().to_string(),
            content,
        })
    }
}

impl<S: ExternalServices> GroupConvo<S> for GroupV1Convo {
    // add_members returns:
    //   commit      — the Commit message Alice broadcasts to all members
    //   welcome     — the Welcome message sent privately to each new joiner
    //   _group_info — used for external joins; ignore for now
    fn add_member(
        &mut self,
        cx: &mut ServiceContext<S>,
        members: &[IdentIdRef],
    ) -> Result<(), ChatError> {
        if members.len() > 50 {
            // This is a temporary limit that originates from the the De-MLS epoch time.
            return Err(ChatError::Protocol(
                "Cannot add more than 50 Members at a time".into(),
            ));
        }

        // Get the Keypacakages and transpose any errors.
        // The account_id is kept so invites can be addressed properly
        let keypkgs = members
            .iter()
            .map(|ident| self.key_package_for_account(ident, &cx.mls_provider, &cx.registry))
            .collect::<Result<Vec<_>, ChatError>>()?;

        let (commit, welcome, _group_info) = self
            .mls_group
            .add_members(
                &cx.mls_provider,
                &cx.mls_identity,
                keypkgs.iter().as_slice(),
            )
            .unwrap();

        self.mls_group
            .merge_pending_commit(&cx.mls_provider)
            .unwrap();

        // TODO: (P3) Evaluate privacy/performance implications of an aggregated Welcome for multiple users
        for account_id in members {
            cx.mls_provider
                .invite_user(&mut cx.ds, account_id, &welcome)?;
        }

        let encrypted_payload = EncryptedPayload {
            encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                payload: commit.to_bytes()?.into(),
            })),
        };

        let addr_enc_payload = AddressedEncryptedPayload {
            delivery_address: self.ctrl_delivery_address(),
            data: encrypted_payload,
        };
        // Prepare commit message
        // TODO: (P1) Make GroupConvos agnostic to framing so its less error prone and more
        let env = addr_enc_payload.into_envelope(self.convo_id.clone());

        cx.ds
            .publish(env)
            .map_err(|e| ChatError::Generic(format!("Publish: {e}")))
    }
}
