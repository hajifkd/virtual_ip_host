use super::MACAddress;
use map_struct::Mappable;

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq)]
pub struct MACHeader {
    pub dst_mac: MACAddress,
    pub src_mac: MACAddress,
    pub ether_type: [u8; 2],
}

unsafe impl Mappable for MACHeader {}

pub const ETHERTYPE_IP: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
