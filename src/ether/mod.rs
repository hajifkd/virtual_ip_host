use crate::arp::headers::ARPHeader;
use crate::ip::headers::IPHeaderWithoutOptions;
use map_struct::Mappable;
use std::fmt;

pub mod headers;

#[repr(C, packed)]
#[derive(PartialEq, Eq)]
pub struct MACAddress {
    pub address: [u8; 6],
}

impl MACAddress {
    pub fn new(address: [u8; 6]) -> Self {
        MACAddress { address }
    }
}

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
}

impl EthernetDriver {
    pub fn new(mac_addr: MACAddress, promisc: bool) -> Self {
        EthernetDriver { mac_addr, promisc }
    }
    fn analyze_arp(&self, data: &[u8]) {
        println!("Received ARP packet",);
        if let Some((header, payload)) = ARPHeader::mapped(&data) {
            println!("    {:?}", &header);
        } else {
            println!("    Invalid ARP packet",);
        }
    }

    fn analyze_ipv4(&self, data: &[u8]) {
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

    pub fn analyze(&self, mac_header: &headers::MACHeader, data: &[u8]) {
        let sent_to_me =
            mac_header.dst_mac == self.mac_addr || mac_header.dst_mac == BROADCAST_MAC_ADDR;
        if !self.promisc && !sent_to_me {
            return;
        }

        let ether_type = u16::from_be_bytes(mac_header.ether_type);

        match ether_type {
            headers::ETHERTYPE_IP => self.analyze_ipv4(data),
            headers::ETHERTYPE_ARP => self.analyze_arp(data),
            _ => self.unknown_type(ether_type),
        }
    }
}
