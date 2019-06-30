use super::{header, MACAddress, BROADCAST_MAC_ADDR};
use crate::arp::error::ARPError;
use crate::arp::ARPResolve;
use crate::ip::error::IPError;

use crate::ip::IPAddress;
use crate::ip::IPParse;
use crate::Destination;
use crate::LinkDriver;

pub struct EthernetDriver<T, S>
where
    T: ARPResolve<LinkAddress = MACAddress, InternetAddress = IPAddress>,
    S: IPParse,
{
    promisc: bool,
    mac_addr: MACAddress,
    arp_resolver: T,
    ip_parser: S,
}

impl<T, S> LinkDriver for EthernetDriver<T, S>
where
    T: ARPResolve<LinkAddress = MACAddress, InternetAddress = IPAddress>,
    S: IPParse,
{
    fn send(&self, _data: &[u8]) {
        unimplemented!();
    }
}

impl<T, S> EthernetDriver<T, S>
where
    T: ARPResolve<LinkAddress = MACAddress, InternetAddress = IPAddress>,
    S: IPParse,
{
    pub fn new(mac_addr: MACAddress, ip_addr: IPAddress, promisc: bool) -> Self {
        EthernetDriver {
            promisc,
            mac_addr,
            arp_resolver: T::new(mac_addr.clone()),
            ip_parser: S::new(ip_addr.clone()),
        }
    }

    fn analyze_arp(&mut self, data: &[u8], frame_dst: Destination) -> Result<(), ARPError> {
        println!("Received ARP packet",);
        self.arp_resolver.parse(data, frame_dst)
    }

    fn analyze_ipv4(&self, data: &[u8], frame_dst: Destination) -> Result<(), IPError> {
        println!("Received IPv4 packet",);
        self.ip_parser.parse(data, frame_dst, self)
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
