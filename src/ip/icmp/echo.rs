use super::IpAddress;
use map_struct::Mappable;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EchoPacketWithoutData {
    pub identifier: u16,
    pub sequence_id: u16,
}

unsafe impl Mappable for EchoPacketWithoutData {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct EchoReply {
    pub src: IpAddress,
    pub sequence_id: u16,
    pub data: Vec<u8>,
}
