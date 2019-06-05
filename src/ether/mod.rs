use crate::arp::headers::{ARPHeader, ARPHRD_ETHER, ARPOP_REPLY, ETHERTYPE_IP};
use crate::arp::EtherIPPayload;
use crate::ip::headers::IPHeaderWithoutOptions;
use crate::ip::IPAddress;
use map_struct::Mappable;
use std::collections::HashMap;
use std::fmt;

pub mod headers;

#[repr(C, packed)]
#[derive(PartialEq, Eq, Copy, Clone)]
pub struct MACAddress {
    pub address: [u8; 6],
}

impl MACAddress {
    pub fn new(address: [u8; 6]) -> Self {
        MACAddress { address }
    }
}

unsafe impl Mappable for MACAddress {}

pub const BROADCAST_MAC_ADDR: MACAddress = MACAddress {
    address: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
};

impl fmt::Debug for MACAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, n) in self.address.iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }
            write!(f, "{:02X}", n)?;
        }
        Ok(())
    }
}

pub struct EthernetDriver {
    mac_addr: MACAddress,
    promisc: bool,
    arp_table: HashMap<IPAddress, MACAddress>,
}

impl EthernetDriver {
    pub fn new(mac_addr: MACAddress, promisc: bool) -> Self {
        EthernetDriver {
            mac_addr,
            promisc,
            arp_table: HashMap::new(),
        }
    }

    fn analyze_arp(&mut self, data: &[u8], sent_to_me: bool) {
        println!("Received ARP packet",);
        if let Some((header, payload)) = ARPHeader::mapped(&data) {
            println!("- {:?}", &header);
            if sent_to_me {
                if u16::from_be(header.hard_addr_space) != ARPHRD_ETHER {
                    println!(
                        "- Unsupported Hardware Address Space: 0x{:04X}",
                        u16::from_be(header.hard_addr_space)
                    );

                    return;
                }

                if u16::from_be(header.proto_addr_space) != ETHERTYPE_IP {
                    println!(
                        "- Unsupported Protocol Address Space: 0x{:04X}",
                        u16::from_be(header.proto_addr_space)
                    );

                    return;
                }

                match u16::from_be(header.op_code) {
                    ARPOP_REPLY => {
                        if let Some((payload, _)) = EtherIPPayload::mapped(payload) {
                            if payload.target_mac_addr == self.mac_addr {
                                println!("- Registered IP Address: {:?}", {
                                    payload.sender_ip_addr
                                });
                                self.arp_table
                                    .insert(payload.sender_ip_addr, payload.sender_mac_addr);
                            } else {
                                println!("- Invalid ARP packet",);
                            }
                        } else {
                            println!("- Invalid ARP packet",);
                        }
                    }
                    _ => {
                        println!(
                            "- Unsupported Operation Code: 0x{:04X}",
                            u16::from_be(header.op_code)
                        );

                        return;
                    }
                }
            }
        } else {
            println!("- Invalid ARP packet",);
        }
    }

    fn analyze_ipv4(&self, data: &[u8], sent_to_me: bool) {
        println!("Received IPv4 packet",);
        if let Some((header, payload)) = IPHeaderWithoutOptions::mapped(&data) {
            print!("    Checking checksum:",);
            if header.is_valid(&data) {
                println!(" ok",);
            } else {
                println!(" ng",);
            }
        } else {
            println!("    Invalid packet: length too short",);
        }
    }

    fn unknown_type(&self, ether_type: u16) {
        println!("Unknown ethertype: {:02X}", ether_type);
    }

    pub fn analyze(&mut self, mac_header: &headers::MACHeader, data: &[u8]) {
        let sent_to_me =
            mac_header.dst_mac == self.mac_addr || mac_header.dst_mac == BROADCAST_MAC_ADDR;
        if !self.promisc && !sent_to_me {
            return;
        }

        let ether_type = u16::from_be_bytes(mac_header.ether_type);

        match ether_type {
            headers::ETHERTYPE_IP => self.analyze_ipv4(data, sent_to_me),
            headers::ETHERTYPE_ARP => self.analyze_arp(data, sent_to_me),
            _ => self.unknown_type(ether_type),
        }
    }
}
