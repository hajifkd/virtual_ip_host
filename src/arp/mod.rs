use crate::ether::MacAddress;
use crate::ip::IpAddress;
use map_struct::Mappable;
use std::collections::HashMap;
use std::mem;

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
    fn new(my_hard_addr: Self::LinkAddress, my_inet_addr: Self::InternetAddress) -> Self;
    // fn resolve(&mut self, key: &Self::InternetAddress) -> impl Future<Self::LinkAddress>;
    fn parse(
        &mut self,
        data: &[u8],
        dst: Destination,
    ) -> Result<ArpReply<Self::LinkAddress>, ArpError>;
}

pub struct EtherIpResolver {
    arp_table: HashMap<IpAddress, MacAddress>,
    my_mac_addr: MacAddress,
    my_ip_addr: IpAddress,
}

impl EtherIpResolver {
    fn set_header(arp_header: &mut ArpHeader, op_code: u16) {
        arp_header.hard_addr_space = u16::to_be(ARPHRD_ETHER);
        arp_header.proto_addr_space = u16::to_be(ETHERTYPE_IP);
        arp_header.hard_addr_len = u8::to_be(6);
        arp_header.proto_addr_len = u8::to_be(4);
        arp_header.op_code = u16::to_be(op_code);
    }
}

impl ArpResolve for EtherIpResolver {
    type InternetAddress = IpAddress;
    type LinkAddress = MacAddress;

    fn new(mac_addr: MacAddress, ip_addr: IpAddress) -> Self {
        EtherIpResolver {
            arp_table: HashMap::new(),
            my_mac_addr: mac_addr,
            my_ip_addr: ip_addr,
        }
    }

    fn parse(
        &mut self,
        data: &[u8],
        dst: Destination,
    ) -> Result<ArpReply<Self::LinkAddress>, ArpError> {
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

                if payload.target_mac_addr == self.my_mac_addr
                    && IpAddress::from_be(payload.target_ip_addr) == self.my_ip_addr
                {
                    let ip_addr = IpAddress::from_be(payload.sender_ip_addr);
                    println!("- Registered IP Address: {:?}", ip_addr);
                    self.arp_table.insert(ip_addr, payload.sender_mac_addr);
                } else if dst != Destination::Promisc {
                    return Err(ArpError::InvalidArpPacket);
                }

                println!(
                    "- ARP Reply from {sender_ip:?} ({sender_mac:?}) to {target_ip:?} ({target_mac:?})",
                    sender_ip = IpAddress::from_be(payload.sender_ip_addr),
                    sender_mac = payload.sender_mac_addr,
                    target_ip = IpAddress::from_be(payload.target_ip_addr),
                    target_mac = payload.target_mac_addr
                );

                Ok(ArpReply::Nop)
            }
            ARPOP_REQUEST => {
                let (payload, _) =
                    EtherIpPayload::mapped(payload).ok_or(ArpError::InvalidArpPacket)?;

                let mut reply = true;

                if IpAddress::from_be(payload.target_ip_addr) != self.my_ip_addr {
                    if dst != Destination::Promisc {
                        return Err(ArpError::InvalidArpPacket);
                    }

                    reply = false;
                }

                println!(
                    "- ARP Request from {sender_ip:?} ({sender_mac:?}) to {target_ip:?} ({target_mac:?})",
                    sender_ip = IpAddress::from_be(payload.sender_ip_addr),
                    sender_mac = payload.sender_mac_addr,
                    target_ip = IpAddress::from_be(payload.target_ip_addr),
                    target_mac = payload.target_mac_addr
                );

                if !reply {
                    return Ok(ArpReply::Nop);
                }

                let mut result =
                    vec![0u8; mem::size_of::<ArpHeader>() + mem::size_of::<EtherIpPayload>()];

                {
                    let (arp_header, mut payload2) = ArpHeader::mapped_mut(&mut result).unwrap();
                    let (ether_ip_payload, _) = EtherIpPayload::mapped_mut(&mut payload2).unwrap();

                    EtherIpResolver::set_header(arp_header, ARPOP_REPLY);
                    ether_ip_payload.sender_mac_addr = self.my_mac_addr;
                    ether_ip_payload.sender_ip_addr = IpAddress::to_be(self.my_ip_addr);
                    ether_ip_payload.target_mac_addr = payload.sender_mac_addr;
                    ether_ip_payload.target_ip_addr = payload.sender_ip_addr;
                }

                Ok(ArpReply::Reply {
                    dst: payload.sender_mac_addr,
                    data: result,
                })
            }
            op_code => Err(ArpError::UnsupportedOperationCode(op_code)),
        }
    }
}
