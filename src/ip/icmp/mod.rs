pub mod header;

use map_struct::Mappable;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EchoPacketWithoutData {
    identifier: u16,
    sequence_id: u16,
}

unsafe impl Mappable for EchoPacketWithoutData {}

pub const ICMP_PROTOCOL_NUMBER: u8 = 1;

pub const ECHO_REPLY_TYPE: u8 = 0;
pub const ECHO_TYPE: u8 = 8;
pub const ECHO_CODE: u8 = 0;
