use crate::ether::MacAddress;
use crate::ip::IpAddress;
use map_struct::Mappable;
use std::collections::HashMap;

use crate::Destination;
use error::ArpError;
use header::*;

pub mod error;
pub mod header;

pub enum ArpReply<T> {
    Reply { dst: T, data: Vec<u8> },
    Nop,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct EtherIpPayload {
    pub sender_mac_addr: MacAddress,
    pub sender_ip_addr: IpAddress,
    pub target_mac_addr: MacAddress,
    pub target_ip_addr: IpAddress,
}

unsafe impl Mappable for EtherIpPayload {}

pub trait ArpResolve {
    type InternetAddress;
    type LinkAddress;
    fn new(my_addr: Self::LinkAddress) -> Self;
    // fn resolve(&mut self, key: &Self::InternetAddress) -> impl Future<Self::LinkAddress>;
    fn parse(&mut self, data: &[u8], dst: Destination) -> Result<ArpReply<Self::LinkAddress>, ArpError>;
}

pub struct EtherIpResolver {
    arp_table: HashMap<IpAddress, MacAddress>,
    my_addr: MacAddress,
}

impl ArpResolve for EtherIpResolver {
    type InternetAddress = IpAddress;
    type LinkAddress = MacAddress;

    fn new(mac_addr: MacAddress) -> Self {
        EtherIpResolver {
            arp_table: HashMap::new(),
            my_addr: mac_addr,
        }
    }

    fn parse(&mut self, data: &[u8], dst: Destination) -> Result<ArpReply<Self::LinkAddress>, ArpError> {
        println!("Received ARP packet",);
        let (header, payload) = ArpHeader::mapped(&data).ok_or(ArpError::InvalidArpPacket)?;
        println!("- {:?}", &header);

        let has = u16::from_be(header.hard_addr_space);
        if has != ARPHRD_ETHER {
            return Err(ArpError::UnsupportedHardwareAddressSpace(has));
        }

        let pas = u16::from_be(header.proto_addr_space);
        if pas != ETHERTYPE_IP {
            return Err(ArpError::UnsupportedProtocolAddressSpace(pas));
        }

        match u16::from_be(header.op_code) {
            ARPOP_REPLY => {
                let (payload, _) =
                    EtherIpPayload::mapped(payload).ok_or(ArpError::InvalidArpPacket)?;

                if payload.target_mac_addr == self.my_addr {
                    let ip_addr = { payload.sender_ip_addr };
                    println!("- Registered IP Address: {:?}", ip_addr);
                    self.arp_table.insert(ip_addr, payload.sender_mac_addr);
                } else if dst != Destination::Promisc {
                    return Err(ArpError::InvalidArpPacket);
                }

                println!(
                    "- ARP Reply from {sender_ip:?} ({sender_mac:?}) to {target_ip:?} ({target_mac:?})",
                    sender_ip = { payload.sender_ip_addr },
                    sender_mac = payload.sender_mac_addr,
                    target_ip = { payload.target_ip_addr },
                    target_mac = payload.target_mac_addr
                );

                Ok(ArpReply::Nop)
            }
            op_code => Err(ArpError::UnsupportedOperationCode(op_code)),
        }
    }
}
