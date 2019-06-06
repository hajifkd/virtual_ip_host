use super::{header, MACAddress, BROADCAST_MAC_ADDR};
use crate::arp::header::{ARPHeader, ARPHRD_ETHER, ARPOP_REPLY, ETHERTYPE_IP};
use crate::arp::EtherIPPayload;
use crate::ip::header::IPHeaderWithoutOptions;
use crate::ip::IPAddress;
use map_struct::Mappable;
use std::collections::HashMap;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum FrameDestination {
    ToMyself,
    Broadcast,
    Promisc,
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

    fn analyze_arp(&mut self, data: &[u8], frame_dst: FrameDestination) {
        println!("Received ARP packet",);
        if let Some((header, payload)) = ARPHeader::mapped(&data) {
            println!("- {:?}", &header);
            if frame_dst != FrameDestination::Promisc {
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

    fn analyze_ipv4(&self, data: &[u8], frame_dst: FrameDestination) {
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

    pub fn analyze(&mut self, mac_header: &header::MACHeader, data: &[u8]) {
        /*match mac_header.dst_mac {
            BROADCAST_MAC_ADDR => FrameDestination::Broadcast,
            //self.mac_addr => FrameDestination::ToMyself,
            _ => FrameDestination::Promisc,
        };*/

        let frame_dst = if mac_header.dst_mac == self.mac_addr {
            FrameDestination::ToMyself
        } else if mac_header.dst_mac == BROADCAST_MAC_ADDR {
            FrameDestination::Broadcast
        } else {
            FrameDestination::Promisc
        };

        if !self.promisc && frame_dst == FrameDestination::Promisc {
            return;
        }

        let ether_type = u16::from_be_bytes(mac_header.ether_type);

        match ether_type {
            header::ETHERTYPE_IP => self.analyze_ipv4(data, frame_dst),
            header::ETHERTYPE_ARP => self.analyze_arp(data, frame_dst),
            _ => self.unknown_type(ether_type),
        }
    }
}
