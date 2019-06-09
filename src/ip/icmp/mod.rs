pub mod header;

use map_struct::Mappable;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EchoPacketWithoutData {
    identifier: u16,
    sequence_id: u16,
}

unsafe impl Mappable for EchoPacketWithoutData {}