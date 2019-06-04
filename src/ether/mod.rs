use crate::arp::headers::ARPHeader;
use crate::ip::headers::IPHeaderWithoutOptions;
use map_struct::Mappable;

pub mod headers;

pub struct EthernetAnalyzer {}

impl EthernetAnalyzer {
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
        let ether_type = u16::from_be_bytes(mac_header.ether_type);

        match ether_type {
            headers::ETHERTYPE_IP => self.analyze_ipv4(data),
            headers::ETHERTYPE_ARP => self.analyze_arp(data),
            _ => self.unknown_type(ether_type),
        }
    }
}
