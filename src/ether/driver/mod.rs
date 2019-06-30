use super::{header, MACAddress, BROADCAST_MAC_ADDR};
use crate::arp::error::ARPError;
use crate::arp::ARPResolve;
use crate::ip::header::IPHeaderWithoutOptions;
use crate::ip::icmp;
use crate::ip::IPAddress;
use crate::Destination;
use map_struct::Mappable;

mod errors;
use errors::IPError;

pub struct EthernetDriver<T: ARPResolve<LinkAddress = MACAddress, InternetAddress = IPAddress>> {
    promisc: bool,
    mac_addr: MACAddress,
    arp_resolver: T,
}

impl<T: ARPResolve<LinkAddress = MACAddress, InternetAddress = IPAddress>> EthernetDriver<T> {
    pub fn new(mac_addr: MACAddress, promisc: bool) -> Self {
        EthernetDriver {
            promisc,
            mac_addr,
            arp_resolver: T::new(mac_addr.clone()),
        }
    }

    fn analyze_arp(&mut self, data: &[u8], frame_dst: Destination) -> Result<(), ARPError> {
        println!("Received ARP packet",);
        self.arp_resolver.parse(data, frame_dst)
    }

    fn analyze_ipv4(&self, data: &[u8], frame_dst: Destination) -> Result<(), IPError> {
        println!("Received IPv4 packet",);
        let (header, _) = IPHeaderWithoutOptions::mapped(&data).ok_or(IPError::InvalidIPPacket)?;

        if header.version() != 4 {
            return Err(IPError::Unimplemented);
        }

        if !header.is_valid(&data) {
            return Err(IPError::InvalidChecksum);
        }

        // TODO flagmentation

        let header_length_in_byte = (header.ihl() * 4) as usize;
        if header_length_in_byte >= data.len() {
            return Err(IPError::InvalidIPPacket);
        }

        let payload = &data[header_length_in_byte..];

        if frame_dst == Destination::Promisc {
            return Ok(());
        }

        match header.protocol {
            icmp::ICMP_PROTOCOL_NUMBER => Err(IPError::Unimplemented),
            _ => Err(IPError::Unimplemented),
        }
    }

    fn unknown_type(&self, ether_type: u16) {
        println!("Unknown ethertype: {:02X}", ether_type);
    }

    pub fn analyze(&mut self, mac_header: &header::MACHeader, data: &[u8]) {
        let frame_dst = if mac_header.dst_mac == self.mac_addr {
            Destination::ToMyself
        } else if mac_header.dst_mac == BROADCAST_MAC_ADDR {
            Destination::Broadcast
        } else {
            Destination::Promisc
        };

        if !self.promisc && frame_dst == Destination::Promisc {
            return;
        }

        let ether_type = u16::from_be_bytes(mac_header.ether_type);

        match ether_type {
            header::ETHERTYPE_IP => self
                .analyze_ipv4(data, frame_dst)
                .unwrap_or_else(|e| println!("- {}", e)),
            header::ETHERTYPE_ARP => self
                .analyze_arp(data, frame_dst)
                .unwrap_or_else(|e| println!("- {}", e)),
            _ => self.unknown_type(ether_type),
        }
    }
}