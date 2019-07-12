use super::{header, MacAddress, BROADCAST_MAC_ADDR};
use crate::arp::error::ArpError;
use crate::arp::ArpResolve;
use crate::ip::error::IpError;

use crate::ip::IpAddress;
use crate::ip::IpParse;
use crate::Destination;
use crate::LinkDriver;

pub struct EthernetDriver<T, S>
where
    T: ArpResolve<LinkAddress = MacAddress, InternetAddress = IpAddress>,
    S: IpParse,
{
    promisc: bool,
    mac_addr: MacAddress,
    arp_resolver: T,
    ip_parser: S,
}

impl<T, S> LinkDriver for EthernetDriver<T, S>
where
    T: ArpResolve<LinkAddress = MacAddress, InternetAddress = IpAddress>,
    S: IpParse,
{
    fn send(&self, _data: &[u8]) {
        unimplemented!();
    }
}

impl<T, S> EthernetDriver<T, S>
where
    T: ArpResolve<LinkAddress = MacAddress, InternetAddress = IpAddress>,
    S: IpParse,
{
    pub fn new(mac_addr: MacAddress, ip_addr: IpAddress, promisc: bool) -> Self {
        EthernetDriver {
            promisc,
            mac_addr,
            arp_resolver: T::new(mac_addr.clone()),
            ip_parser: S::new(ip_addr.clone()),
        }
    }

    fn analyze_arp(&mut self, data: &[u8], frame_dst: Destination) -> Result<(), ArpError> {
        println!("Received ARP packet",);
        self.arp_resolver.parse(data, frame_dst)
    }

    fn analyze_ipv4(&mut self, data: &[u8], frame_dst: Destination) -> Result<(), IpError> {
        println!("Received IPv4 packet",);
        let packet = {
            let packet = self.ip_parser.parse(data, frame_dst)?;
            if packet.is_none() {
                return Ok(());
            }

            packet.unwrap()
        };

        unimplemented!()
    }

    fn unknown_type(&self, ether_type: u16) {
        println!("Unknown ethertype: {:02X}", ether_type);
    }

    pub fn analyze(&mut self, mac_header: &header::MacHeader, data: &[u8]) {
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
