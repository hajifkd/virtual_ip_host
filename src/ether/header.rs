use super::MacAddress;
use map_struct::Mappable;

#[repr(C, packed)]
#[derive(Debug, PartialEq, Eq)]
pub struct MacHeader {
    pub dst_mac: MacAddress,
    pub src_mac: MacAddress,
    pub ether_type: [u8; 2],
}

unsafe impl Mappable for MacHeader {}

pub const ETHERTYPE_IP: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
