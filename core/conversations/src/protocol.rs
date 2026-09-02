use storage::Namespace;

/// The protocol that owns a piece of state; gains a variant when a protocol ships.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    GroupV1,
    DirectV1,
    GroupV2,
    InboxV2,
}

impl From<Protocol> for Namespace {
    fn from(protocol: Protocol) -> Self {
        Namespace::new(match protocol {
            Protocol::GroupV1 => "group_v1",
            Protocol::DirectV1 => "direct_v1",
            Protocol::GroupV2 => "group_v2",
            Protocol::InboxV2 => "inbox_v2",
        })
    }
}
