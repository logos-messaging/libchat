use prost::Message;
use prost::Oneof;

#[derive(Clone, PartialEq, Message)]
pub struct GroupV1Frame {
    #[prost(string, tag = "1")]
    pub sender: String,

    #[prost(uint64, tag = "2")]
    pub timestamp: u64,

    // oneof field — optional, holds one variant
    #[prost(oneof = "FrameType", tags = "3, 4, 5")]
    pub payload: Option<FrameType>,
}

#[derive(Clone, PartialEq, Oneof)]
pub enum FrameType {
    #[prost(bytes, tag = "3")]
    Welcome(Vec<u8>),
}
