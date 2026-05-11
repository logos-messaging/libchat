use std::cell::RefMut;
use std::collections::HashMap;
use std::{cell::RefCell, rc::Rc};

use crate::conversation::{BaseGroupConvo, ConversationId, ConversationIdRef, Id, ServiceContext};

use crate::inbox_v2::InboxV2;
use crate::{AccountId, errors::ChatError};
use crate::{DeliveryService, IdentityProvider, RegistrationService};
use chat_proto::logoschat::encryption::EncryptedPayload;
use chat_proto::logoschat::envelope::EnvelopeV1;
use libchat::ContentData;
use prost::Message;
use storage::ChatStore;

#[derive(Debug)]
enum ConvoTypeOwned<IP: IdentityProvider, DS: DeliveryService, RS: RegistrationService> {
    // Pairwise(Box<dyn BaseConvo<IP, DS, RS>>),
    Group(Box<dyn BaseGroupConvo<IP, DS, RS>>),
}

impl<IP, DS, RS> Id for ConvoTypeOwned<IP, DS, RS>
where
    IP: IdentityProvider,
    DS: DeliveryService,
    RS: RegistrationService,
{
    fn id(&self) -> crate::conversation::ConversationIdRef<'_> {
        match self {
            // ConvoTypeOwned::Pairwise(convo) => convo.id(),
            ConvoTypeOwned::Group(convo) => convo.id(),
        }
    }
}

pub struct GroupConvo<
    IP: IdentityProvider,
    DS: DeliveryService,
    RS: RegistrationService,
    CS: ChatStore,
> {
    client: Rc<RefCell<InnerClient<IP, DS, RS, CS>>>,
    convo_id: ConversationId,
}

impl<IP, DS, RS, CS> GroupConvo<IP, DS, RS, CS>
where
    IP: IdentityProvider + 'static,
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
    CS: ChatStore + 'static,
{
    pub fn send_content(&self, content: &[u8]) -> Result<(), ChatError> {
        let mut client = self.client.borrow_mut();
        client.send_content(self.convo_id.as_str(), content)
    }
}

pub struct CoreClient<
    IP: IdentityProvider,
    DS: DeliveryService,
    RS: RegistrationService,
    CS: ChatStore,
> {
    inner: Rc<RefCell<InnerClient<IP, DS, RS, CS>>>,
}

impl<IP, DS, RS, CS> CoreClient<IP, DS, RS, CS>
where
    IP: IdentityProvider + 'static,
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
    CS: ChatStore + 'static,
{
    pub fn new(account: IP, delivery: DS, registration: RS, store: CS) -> Result<Self, ChatError> {
        let c = InnerClient::new(account, delivery, registration, store)?;
        Ok(Self {
            inner: Rc::new(RefCell::new(c)),
        })
    }

    pub fn account_id(&self) -> AccountId {
        self.inner.borrow().account_id().clone()
    }

    pub fn ds(&self) -> RefMut<'_, DS> {
        RefMut::map(self.inner.borrow_mut(), |c| c.ds())
    }

    pub fn create_group_convo(
        &self,
        participants: &[&AccountId],
    ) -> Result<GroupConvo<IP, DS, RS, CS>, ChatError> {
        let convo_id = self.inner.borrow_mut().create_group_convo(participants)?;
        Ok(GroupConvo {
            client: self.inner.clone(),
            convo_id,
        })
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ChatError> {
        self.inner.borrow().list_conversations()
    }

    pub fn send_content(
        &self,
        convo_id: ConversationIdRef,
        content: &[u8],
    ) -> Result<(), ChatError> {
        self.inner.borrow_mut().send_content(convo_id, content)
    }

    pub fn handle_payload(&self, payload: &[u8]) -> Result<Option<ContentData>, ChatError> {
        self.inner.borrow_mut().handle_payload(payload)
    }

    pub fn convo(&self, convo_id: ConversationIdRef) -> Option<GroupConvo<IP, DS, RS, CS>> {
        let client = self.inner.clone();

        if !client.borrow().has_conversation(convo_id) {
            return None;
        }

        Some(GroupConvo {
            client,
            convo_id: convo_id.to_string(),
        })
    }
}

struct InnerClient<
    IP: IdentityProvider,
    DS: DeliveryService,
    RS: RegistrationService,
    CS: ChatStore,
> {
    service_ctx: ServiceContext<IP, DS, RS>,
    _store: Rc<RefCell<CS>>,

    pq_inbox: InboxV2<CS>,

    // Cache of loaded conversations
    cached_convos: HashMap<String, ConvoTypeOwned<IP, DS, RS>>,
}

impl<IP, DS, RS, CS> InnerClient<IP, DS, RS, CS>
where
    IP: IdentityProvider + 'static,
    DS: DeliveryService + 'static,
    RS: RegistrationService + 'static,
    CS: ChatStore + 'static,
{
    pub fn new(account: IP, delivery: DS, registration: RS, store: CS) -> Result<Self, ChatError> {
        // Services for sharing with Converastions/Inboxes

        let mut service_ctx = ServiceContext {
            identity_provider: account,
            ds: delivery,
            rs: registration,
        };

        // let contact_registry = Rc::new(RefCell::new(registration));
        let _store = Rc::new(RefCell::new(store));

        let pq_inbox = InboxV2::new(&mut service_ctx, _store.clone());
        pq_inbox.register(&mut service_ctx)?;

        // Subscribe
        service_ctx
            .ds
            .subscribe(&pq_inbox.delivery_address())
            .map_err(ChatError::generic)?;

        Ok(Self {
            service_ctx,
            _store,
            pq_inbox,
            cached_convos: HashMap::new(),
        })
    }

    pub fn ds(&mut self) -> &mut DS {
        &mut self.service_ctx.ds
    }

    /// Returns the unique identifier associated with the account
    pub fn account_id(&self) -> &AccountId {
        self.pq_inbox.account_id()
    }

    pub fn create_group_convo(&mut self, participants: &[&AccountId]) -> Result<String, ChatError> {
        let convo = self.pq_inbox.create_group_v1(&mut self.service_ctx)?;
        let mut convo: Box<dyn BaseGroupConvo<IP, DS, RS>> = Box::new(convo);
        convo.init(&mut self.service_ctx)?;
        convo.add_member(&mut self.service_ctx, participants)?;

        let convo_id = convo.id().to_string();

        self.register_convo(ConvoTypeOwned::Group(convo))?;

        Ok(convo_id)
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationId>, ChatError> {
        Ok(self.cached_convos.keys().cloned().collect())
    }

    pub fn has_conversation(&self, convo_id: ConversationIdRef) -> bool {
        self.cached_convos.contains_key(convo_id)
    }

    pub fn send_content(
        &mut self,
        convo_id: ConversationIdRef,
        content: &[u8],
    ) -> Result<(), ChatError> {
        let Some(convo) = self.cached_convos.get_mut(convo_id) else {
            return Err(ChatError::generic("No Convo Found"));
        };
        let convo = match convo {
            // ConvoTypeOwned::Pairwise(_) => todo!(),
            ConvoTypeOwned::Group(c) => c.as_mut(),
        };
        convo.send_content(&mut self.service_ctx, content)
    }

    // Decode bytes and send to protocol for processing.
    pub fn handle_payload(&mut self, payload: &[u8]) -> Result<Option<ContentData>, ChatError> {
        let env = EnvelopeV1::decode(payload)?;

        // TODO: Impl Conversation hinting
        let convo_id = env.conversation_hint;
        match convo_id {
            c if c == self.pq_inbox.id() => self.dispatch_to_inbox2(&env.payload),
            c if self.cached_convos.contains_key(c.as_str()) => {
                self.dispatch_to_convo(c, &env.payload)
            }
            _ => Ok(None),
        }
    }

    // Dispatch encrypted payload to Inbox, and register the created Conversation
    fn dispatch_to_inbox2(&mut self, payload: &[u8]) -> Result<Option<ContentData>, ChatError> {
        if let Some(convo) = self.pq_inbox.handle_frame(&mut self.service_ctx, payload)? {
            let convo: Box<dyn BaseGroupConvo<IP, DS, RS>> = Box::new(convo);
            self.register_convo(ConvoTypeOwned::Group(convo))?;
        }
        Ok(None)
    }

    // Dispatch encrypted payload to its corresponding conversation
    fn dispatch_to_convo(
        &mut self,
        convo_id: ConversationId,
        enc_payload_bytes: &[u8],
    ) -> Result<Option<ContentData>, ChatError> {
        let enc_payload = EncryptedPayload::decode(enc_payload_bytes)?;

        let Some(convo) = self.cached_convos.get_mut(&convo_id) else {
            return Err(ChatError::generic("No Convo Found"));
        };
        let convo = match convo {
            // ConvoTypeOwned::Pairwise(_) => todo!(),
            ConvoTypeOwned::Group(c) => c.as_mut(),
        };

        convo.handle_frame(&mut self.service_ctx, enc_payload)
    }

    fn register_convo(&mut self, convo: ConvoTypeOwned<IP, DS, RS>) -> Result<(), ChatError> {
        let res = self.cached_convos.insert(convo.id().to_string(), convo);

        match res {
            Some(_) => Err(ChatError::generic("Convo already exists. Cannot save")),
            None => Ok(()),
        }
    }
}
