use super::ether::MACAddress;
use super::ip::IPAddress;
use map_struct::Mappable;
use std::collections::HashMap;
use std::hash::Hash;

use error::ARPError;
use header::*;

pub mod error;
pub mod header;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EtherIPPayload {
    pub sender_mac_addr: MACAddress,
    pub sender_ip_addr: IPAddress,
    pub target_mac_addr: MACAddress,
    pub target_ip_addr: IPAddress,
}

unsafe impl Mappable for EtherIPPayload {}

pub trait ARPResolve<S: Hash, T: Hash> {
    // fn resolve(&mut self, key: T) -> impl Future<S>;
    fn parse(&mut self, data: &[u8]) -> Result<(), ARPError>;
}

pub struct EtherIPResolver {
    mac_addr: MACAddress,
    arp_table: HashMap<IPAddress, MACAddress>,
}

impl EtherIPResolver {
    pub fn new(mac_addr: MACAddress) -> Self {
        EtherIPResolver {
            mac_addr,
            arp_table: HashMap::new(),
        }
    }
}

impl ARPResolve<MACAddress, IPAddress> for EtherIPResolver {
    fn parse(&mut self, data: &[u8]) -> Result<(), ARPError> {
        println!("Received ARP packet",);
        let (header, payload) = ARPHeader::mapped(&data).ok_or(ARPError::InvalidARPPacket)?;
        println!("- {:?}", &header);

        let has = u16::from_be(header.hard_addr_space);
        if has != ARPHRD_ETHER {
            return Err(ARPError::UnsupportedHardwareAddressSpace(has));
        }

        let pas = u16::from_be(header.proto_addr_space);
        if pas != ETHERTYPE_IP {
            return Err(ARPError::UnsupportedProtocolAddressSpace(pas));
        }

        match u16::from_be(header.op_code) {
            ARPOP_REPLY => {
                let (payload, _) =
                    EtherIPPayload::mapped(payload).ok_or(ARPError::InvalidARPPacket)?;
                if payload.target_mac_addr == self.mac_addr {
                    let ip_addr = { payload.sender_ip_addr }.from_network_endian();
                    println!("- Registered IP Address: {:?}", ip_addr);
                    self.arp_table.insert(ip_addr, payload.sender_mac_addr);
                    Ok(())
                } else {
                    Err(ARPError::InvalidARPPacket)
                }
            }
            op_code => Err(ARPError::UnsupportedOperationCode(op_code)),
        }
    }
}
