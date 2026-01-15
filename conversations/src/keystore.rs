use crate::identity::Identity;

pub trait IdentityProvider {
    fn identity(&self) -> &Identity;
}

pub struct InMemKeyStore {
    ident: Identity,
}

impl InMemKeyStore {
    pub fn new() -> Self {
        Self {
            ident: Identity::new(),
        }
    }
}

impl IdentityProvider for InMemKeyStore {
    fn identity(&self) -> &Identity {
        &self.ident
    }
}
