use super::ether::MACAddress;
use super::ip::IPAddress;
use map_struct::Mappable;

pub mod headers;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EtherIPPayload {
    pub sender_mac_addr: MACAddress,
    pub sender_ip_addr: IPAddress,
    pub target_mac_addr: MACAddress,
    pub target_ip_addr: IPAddress,
}

unsafe impl Mappable for EtherIPPayload {}
