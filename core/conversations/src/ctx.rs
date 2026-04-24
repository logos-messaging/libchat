use std::{
    cell::{RefCell, RefMut},
    rc::Rc,
};

use storage::ChatStore;

use crate::{DeliveryService, RegistrationService};
use crate::service_traits::KeyPackageProvider;

pub struct ClientCtx<DS: DeliveryService, RS: KeyPackageProvider, CS: ChatStore> {
    ds: DS,
    contact_registry: RS,
    convo_store: Rc<RefCell<CS>>, // TODO: (P2) Remove Rc/Refcell
}

impl<'a, DS: DeliveryService, RS: KeyPackageProvider, CS: ChatStore> ClientCtx<DS, RS, CS> {
    pub fn new(ds: DS, contact_registry: RS, convo_store: Rc<RefCell<CS>>) -> Self {
        Self {
            ds,
            contact_registry,
            convo_store,
        }
    }

    pub fn ds(&'a mut self) -> &'a mut DS {
        &mut self.ds
    }

    pub fn contact_registry(&'a self) -> &'a RS {
        &self.contact_registry
    }

    pub fn store(&'a self) -> RefMut<'a, CS> {
        self.convo_store.borrow_mut()
    }
}

impl<'a, DS: DeliveryService, RS: RegistrationService, CS: ChatStore> ClientCtx<DS, RS, CS> {
    pub fn contact_registry_mut(&'a mut self) -> &'a mut RS {
        &mut self.contact_registry
    }
}
