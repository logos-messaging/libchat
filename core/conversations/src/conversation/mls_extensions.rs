use openmls::{
    extensions::ExtensionType,
    prelude::{
        Capabilities,
        tls_codec::{Deserialize, Error as TlsError, Serialize, Size, VLByteSlice, VLBytes},
    },
};
use shared_traits::{IdentId, IdentIdRef};
use std::io::{Read, Write};

use crate::types::ConvoMetadata;

pub const GROUP_METADATA_EXTENSION_TYPE: u16 = 0xFF01;

pub fn capabilities_with_group_metadata() -> Capabilities {
    Capabilities::new(
        None, // default protocol versions
        None, // default ciphersuites
        Some(&[ExtensionType::Unknown(GROUP_METADATA_EXTENSION_TYPE)]),
        None, // default proposal types
        None, // default credential types
    )
}

#[derive(Debug, Clone)]
pub struct ConvoMetaInfo {
    version: u16,
    name: String,
    owner: IdentId,
    desc: String,
}

impl ConvoMetaInfo {
    pub fn new(name: impl Into<String>, owner: IdentIdRef, desc: impl Into<String>) -> Self {
        Self {
            version: 1,
            name: name.into(),
            owner: owner.clone(),
            desc: desc.into(),
        }
    }

    pub fn to_extension_bytes(&self) -> Vec<u8> {
        // TLS presentation-language encoding — matches the wire format used by
        // the rest of the MLS stack, so no extra serializer is pulled in.
        self.tls_serialize_detached().expect("serialization failed")
    }

    pub fn from_extension_bytes(bytes: &[u8]) -> Result<Self, TlsError> {
        Self::tls_deserialize(&mut &bytes[..])
    }
}

// Each field is encoded as a variable-length opaque (`opaque <V>`); `IdentId`
// and `String` aren't `tls_codec` types, so we encode/decode their UTF-8 bytes.
impl Size for ConvoMetaInfo {
    fn tls_serialized_len(&self) -> usize {
        self.version.tls_serialized_len()
            + VLByteSlice(self.name.as_bytes()).tls_serialized_len()
            + VLByteSlice(self.owner.as_str().as_bytes()).tls_serialized_len()
            + VLByteSlice(self.desc.as_bytes()).tls_serialized_len()
    }
}

impl Serialize for ConvoMetaInfo {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, TlsError> {
        let mut written = self.version.tls_serialize(writer)?;
        written += VLByteSlice(self.name.as_bytes()).tls_serialize(writer)?;
        written += VLByteSlice(self.owner.as_str().as_bytes()).tls_serialize(writer)?;
        written += VLByteSlice(self.desc.as_bytes()).tls_serialize(writer)?;
        Ok(written)
    }
}

impl Deserialize for ConvoMetaInfo {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, TlsError> {
        let version = u16::tls_deserialize(bytes)?;
        let name = vl_string(bytes)?;
        let owner = IdentId::new(vl_string(bytes)?);
        let desc = vl_string(bytes)?;
        Ok(Self {
            version,
            name,
            owner,
            desc,
        })
    }
}

fn vl_string<R: Read>(bytes: &mut R) -> Result<String, TlsError> {
    let raw = VLBytes::tls_deserialize(bytes)?;
    String::from_utf8(raw.into())
        .map_err(|_| TlsError::DecodingError("invalid utf-8 in ConvoMetaInfo".into()))
}

impl From<ConvoMetaInfo> for ConvoMetadata {
    fn from(value: ConvoMetaInfo) -> Self {
        Self {
            owner: value.owner.to_string(),
            name: value.name,
            desc: value.desc,
        }
    }
}
