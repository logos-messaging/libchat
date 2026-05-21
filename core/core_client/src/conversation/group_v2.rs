// This Implementation is a Quick and Dirty Integration of DeMLS into libchat.
// DeMLS and Libchat have different execution models, trait definitions and ownership/lifetimes of objects.
// The easies path is to do a Spike to see what it would take, gather the friction points and then iterate.
//
// Since de-mls::user contains the state-machine and is Async the easiest path is to generate async runtimes
// for each call. This is inefficient but requres the lease amount of effort.
// Expect this branch to not be merged.

macro_rules! run_async {
    ($expr:expr) => {
        tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(async { $expr })
    };
}

use alloy::signers::local::PrivateKeySigner;
use blake2::{Blake2b, Digest, digest::consts::U6};
use chat_proto::logoschat::encryption::{EncryptedPayload, Plaintext, encrypted_payload};
use de_mls::app::{ConsensusContext, ConversationConfig, User, UserPlugins};
use de_mls::core::{ScoringConfig, StewardListConfig};
use de_mls::defaults::{
    DefaultConsensusPlugin, DefaultConversationPluginsFactory, MemoryDeMlsStorage,
};
use de_mls::ds::{APP_MSG_SUBTOPIC, DeliveryServiceError, InboundPacket, OutboundPacket};
use de_mls::identity::Identity;
use de_mls::mls_crypto::MlsCredentials;
use hashgraph_like_consensus::signing::EthereumConsensusSigner;
use prost::Message;
use rand::{self, Rng};
use std::sync::{Arc, Mutex};

use crate::AccountId;
use crate::conversation::{ConversationIdRef, ExternalServices, ServiceContext};
use crate::inbox_v2::MlsIdentityProvider;
use crate::{
    AddressedEncryptedPayload, ContentData, DeliveryService, RegistrationService,
    conversation::{BaseConvo, BaseGroupConvo, ChatError, Id},
};

const APP_NAME: &str = "sdkchat";

/// This is a Test Wrapper of Demls Identitity Trait
/// Linchat has its own trait that will need to be intergrated at somepoint.
pub struct LocalDemlsIdent {
    name: String,
}

impl LocalDemlsIdent {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

impl Identity for LocalDemlsIdent {
    fn identity_bytes(&self) -> &[u8] {
        self.name.as_bytes()
    }

    fn identity_display(&self) -> &str {
        &self.name
    }
}

#[derive(Debug)]
// This Maps a Demls::DeliveryService to a crate::service_traits::DeliveryService
// It works by caching outbound messages to a Vec which is eventually drained when
// The ServiceContext is available.
//
// All methods in Convo must call drain, to ensure that messages go out.
pub struct BufferDs {
    queue: Vec<OutboundPacket>,
}

impl BufferDs {
    pub fn new() -> Self {
        Self { queue: vec![] }
    }

    // Warn: Messages are not sent untill drain is called, which is after the return from User.
    // If de-mls relies on interactive sends, this will not work.
    pub fn drain<S: ExternalServices>(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<(), ChatError> {
        // Swap the Vec out; Own then existing and replace with a new empty vec.
        for pkt in self.queue.drain(..) {
            let delivery_address = pkt.delivery_address().to_string();
            // All Payloads leaving GroupV2 are a GroupV2Frame
            let frame = GroupV2Frame {
                payload: Some(GroupV2Payload::DeMlsWrapper(pkt.payload.into())),
            };

            // Wrap in EncryptedPayload
            let payload = AddressedEncryptedPayload {
                // Note: Likely a mismatch herem as de-mls is expecting a specific topic.
                delivery_address,
                data: EncryptedPayload {
                    encryption: Some(encrypted_payload::Encryption::Plaintext(Plaintext {
                        payload: frame.encode_to_vec().into(),
                    })),
                },
            };

            let env = payload.into_envelope(pkt.conversation_id.clone());

            service_ctx.ds.publish(env).map_err(ChatError::generic)?;
        }

        Ok(())
    }
}

impl de_mls::ds::DeliveryService for BufferDs {
    type Error = DeliveryServiceError;

    fn publish(&mut self, packet: de_mls::ds::OutboundPacket) -> Result<(), Self::Error> {
        self.queue.push(packet);
        Ok(())
    }

    fn subscribe(&mut self, _delivery_address: &str) -> Result<(), Self::Error> {
        todo!()
    }
}

pub struct GroupV2Convo {
    convo_id: String,
    user: User<DefaultConsensusPlugin, DefaultConversationPluginsFactory>,
    // DeMLS takes shared ownership over the DS, so its incompatible with the &mut ServiceContext
    // Use a wrapper for now, and then look at refactoring.
    buffer_ds: Arc<Mutex<BufferDs>>,
}

impl std::fmt::Debug for GroupV2Convo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GroupV2Convo")
            .field("convo_id", &self.convo_id)
            .finish_non_exhaustive()
    }
}

fn rand_string(n: usize) -> String {
    rand::rng()
        .sample_iter(rand::distr::Alphanumeric)
        .take(n)
        .map(char::from)
        .collect()
}

impl GroupV2Convo {
    pub fn new<S: ExternalServices>(
        service_ctx: &mut ServiceContext<S>,
    ) -> Result<Self, ChatError> {
        // Create new instances of all the dependencies that User needs.
        // Once working, these can be moved to be shared across different convo instances.
        let convo_id = rand_string(5);
        let signer = PrivateKeySigner::random();
        // let identity = WalletIdentity::from_wallet(signer.address());
        let identity = LocalDemlsIdent::new(signer.address().to_string());

        let credentials =
            Arc::new(MlsCredentials::from_identity(&identity).map_err(ChatError::generic)?);
        let storage = Arc::new(MemoryDeMlsStorage::new());
        let conversation_plugins = DefaultConversationPluginsFactory::new(storage, credentials);

        let consensus_signer = EthereumConsensusSigner::new(signer);
        let consensus = ConsensusContext::<DefaultConsensusPlugin>::new(consensus_signer);

        let plugins = UserPlugins {
            conversation_plugins,
            consensus,
            default_conversation_config: ConversationConfig::default(),
            default_scoring_config: ScoringConfig::default(),
            default_steward_list_config: StewardListConfig::default(),
        };

        let ds = BufferDs::new();
        let transport = Arc::new(Mutex::new(ds));

        let mut user = User::new_with_plugins(Box::new(identity), plugins, transport.clone());

        run_async!(
            user.start_conversation(convo_id.as_str(), true)
                .await
                .unwrap()
        );

        // Ensure that the BufferDs gets drained
        transport.lock().unwrap().drain(service_ctx)?;

        Ok(Self {
            convo_id,
            user,
            buffer_ds: transport,
        })
    }

    fn delivery_address_from_id(convo_id: &str) -> String {
        let hash = Blake2b::<U6>::new()
            .chain_update("delivery_addr|")
            .chain_update(convo_id)
            .finalize();
        hex::encode(hash)
    }

    #[allow(unused)]
    fn delivery_address(&self) -> String {
        Self::delivery_address_from_id(&self.convo_id)
    }

    fn ctrl_delivery_address_from_id(convo_id: &str) -> String {
        Self::delivery_address_from_id(convo_id)
    }
    #[allow(unused)]
    fn ctrl_delivery_address(&self) -> String {
        Self::ctrl_delivery_address_from_id(&self.convo_id)
    }

    // Needed by Demls
    fn app_id(&self) -> &str {
        APP_NAME
    }
}

impl Id for GroupV2Convo {
    fn id(&self) -> ConversationIdRef<'_> {
        &self.convo_id
    }
}

impl<S> BaseConvo<S> for GroupV2Convo
where
    S: ExternalServices,
{
    fn init(&self, service_ctx: &mut super::ServiceContext<S>) -> Result<(), ChatError> {
        // Configure the delivery service to listen for the required delivery addresses.

        service_ctx
            .ds
            .subscribe(&Self::delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;
        service_ctx
            .ds
            .subscribe(&Self::ctrl_delivery_address_from_id(&self.convo_id))
            .map_err(ChatError::generic)?;

        // Ensure that the BufferDs gets drained
        self.buffer_ds.lock().unwrap().drain(service_ctx)?;
        Ok(())
    }

    fn send_content(
        &mut self,
        service_ctx: &mut super::ServiceContext<S>,
        _content: &[u8],
    ) -> Result<(), ChatError> {
        let _signer = MlsIdentityProvider(&service_ctx.identity_provider);

        // TODO: Send content
        // Ensure that the BufferDs gets drained
        self.buffer_ds.lock().unwrap().drain(service_ctx)?;
        Ok(())
    }

    fn handle_frame(
        &mut self,
        service_ctx: &mut super::ServiceContext<S>,
        encoded_payload: EncryptedPayload,
    ) -> Result<Option<ContentData>, ChatError> {
        let bytes = match encoded_payload.encryption {
            Some(encrypted_payload::Encryption::Plaintext(pt)) => pt.payload,
            _ => {
                return Err(ChatError::generic("Expected plaintext"));
            }
        };

        // Fake a InboundPacket
        let packet = InboundPacket {
            payload: bytes.to_vec(),
            subtopic: APP_MSG_SUBTOPIC.to_string(), // Assume APP TOPIC, Welcome Messages go to InboxV2
            conversation_id: self.convo_id.to_string(),
            app_id: self.app_id().as_bytes().to_vec(),
            timestamp: 0,
        };

        run_async!(self.user.process_inbound_packet(packet).await.unwrap());

        // TODO: Return Content types; This is moving towards an event system soon, so ignore if getting
        // the concrete Content is difficult

        // Ensure that the BufferDs gets drained
        self.buffer_ds.lock().unwrap().drain(service_ctx)?;

        Ok(None)
    }

    fn wakeup(&mut self, _service_ctx: &mut ServiceContext<S>) -> Result<(), ChatError> {
        // todo!()
        Ok(())
    }
}

impl<S> BaseGroupConvo<S> for GroupV2Convo
where
    S: ExternalServices,
{
    fn add_member(
        &mut self,
        service_ctx: &mut ServiceContext<S>,
        members: &[&AccountId],
    ) -> Result<(), ChatError> {
        for member in members {
            let key_package_opt = service_ctx
                .rs
                .retrieve(member)
                .map_err(ChatError::generic)?;

            let Some(_key_package_bytes) = key_package_opt else {
                return Err(ChatError::generic("No Keypackage"));
            };

            // todo!("Implement function which adds member via Keypackage");
        }

        // Ensure that the BufferDs gets drained
        self.buffer_ds.lock().unwrap().drain(service_ctx)?;

        Ok(())
    }
}

use prost::{Oneof, bytes::Bytes};

#[derive(Clone, PartialEq, Message)]
pub struct GroupV2Frame {
    #[prost(oneof = "GroupV2Payload", tags = "1")]
    pub payload: Option<GroupV2Payload>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum GroupV2Payload {
    #[prost(message, tag = "2")]
    DeMlsWrapper(Bytes),
}
