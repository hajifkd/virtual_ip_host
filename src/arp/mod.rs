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
    fn parse(&mut self, data: &[u8], my_addr: &S) -> Result<(), ARPError>;
}

pub struct EtherIPResolver {
    arp_table: HashMap<IPAddress, MACAddress>,
}

impl Default for EtherIPResolver {
    fn default() -> Self {
        EtherIPResolver {
            arp_table: HashMap::new(),
        }
    }
}

impl ARPResolve<MACAddress, IPAddress> for EtherIPResolver {
    fn parse(&mut self, data: &[u8], mac_addr: &MACAddress) -> Result<(), ARPError> {
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

                println!(
                    "- ARP Reply from {sender_ip:?} ({sender_mac:?}) to {target_ip:?} ({target_mac:?})",
                    sender_ip = { payload.sender_ip_addr }.from_network_endian(),
                    sender_mac = payload.sender_mac_addr,
                    target_ip = { payload.target_ip_addr }.from_network_endian(),
                    target_mac = payload.target_mac_addr
                );

                if payload.target_mac_addr == *mac_addr {
                    let ip_addr = { payload.sender_ip_addr }.from_network_endian();
                    println!("- Registered IP Address: {:?}", ip_addr);
                    self.arp_table.insert(ip_addr, payload.sender_mac_addr);
                }

                Ok(())
            }
            op_code => Err(ARPError::UnsupportedOperationCode(op_code)),
        }
    }
}
