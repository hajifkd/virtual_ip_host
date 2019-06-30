use super::ether::MACAddress;
use super::ip::IPAddress;
use map_struct::Mappable;
use std::collections::HashMap;

use crate::Destination;
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

pub trait ARPResolve {
    type InternetAddress;
    type LinkAddress;
    fn new(my_addr: Self::LinkAddress) -> Self;
    // fn resolve(&mut self, key: &Self::InternetAddress) -> impl Future<Self::LinkAddress>;
    fn parse(&mut self, data: &[u8], dst: Destination) -> Result<(), ARPError>;
}

pub struct EtherIPResolver {
    arp_table: HashMap<IPAddress, MACAddress>,
    my_addr: MACAddress,
}

impl ARPResolve for EtherIPResolver {
    type InternetAddress = IPAddress;
    type LinkAddress = MACAddress;

    fn new(mac_addr: MACAddress) -> Self {
        EtherIPResolver {
            arp_table: HashMap::new(),
            my_addr: mac_addr,
        }
    }

    fn parse(&mut self, data: &[u8], dst: Destination) -> Result<(), ARPError> {
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

                if payload.target_mac_addr == self.my_addr {
                    let ip_addr = { payload.sender_ip_addr }.from_network_endian();
                    println!("- Registered IP Address: {:?}", ip_addr);
                    self.arp_table.insert(ip_addr, payload.sender_mac_addr);
                } else if dst != Destination::Promisc {
                    return Err(ARPError::InvalidARPPacket);
                }

                println!(
                    "- ARP Reply from {sender_ip:?} ({sender_mac:?}) to {target_ip:?} ({target_mac:?})",
                    sender_ip = { payload.sender_ip_addr }.from_network_endian(),
                    sender_mac = payload.sender_mac_addr,
                    target_ip = { payload.target_ip_addr }.from_network_endian(),
                    target_mac = payload.target_mac_addr
                );

                Ok(())
            }
            op_code => Err(ARPError::UnsupportedOperationCode(op_code)),
        }
    }
}
