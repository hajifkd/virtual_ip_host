use super::{header, MacAddress, BROADCAST_MAC_ADDR};
use crate::arp::{ArpReply, ArpResolve, ResolveResult};

use crate::ether::header::MacHeader;
use crate::ip::{IpAddress, IpParse, IpReply};
use crate::socket::Socket;
use crate::Destination;

use futures::channel::mpsc::channel;
use futures::future;
use futures::prelude::*;
use libc::ETH_ZLEN;
use map_struct::Mappable;
use std::future::Future;
use std::pin::Pin;

const N_CHANNEL_BUFFER: usize = 256;

pub struct EthernetDriver<T, S>
where
    T: ArpResolve<LinkAddress = MacAddress, InternetAddress = IpAddress> + Sync + Send,
    S: IpParse + Sync + Send,
{
    promisc: bool,
    arp_resolver: T,
    ip_parser: S,
    device: EtherDevice,
}

#[derive(Clone)]
struct EtherDevice {
    mac_addr: MacAddress,
    socket: Socket,
}

impl EtherDevice {
    fn send(&self, data: &[u8]) {
        // TODO check MTU
        unsafe {
            let res = self.socket.send(data);
            if res as usize != data.len() {
                use crate::utils;
                utils::show_error_text();
            }
        }
    }

    fn constract_ethernet_frame(&self, dst: MacAddress, ether_type: u16, data: &[u8]) -> Vec<u8> {
        let mac_header = MacHeader {
            dst_mac: dst,
            src_mac: self.mac_addr,
            ether_type: u16::to_be(ether_type),
        };

        let mut result = mac_header.as_bytes().to_vec();
        result.extend_from_slice(data);

        if result.len() < ETH_ZLEN as _ {
            result.resize(ETH_ZLEN as _, 0);
        }

        result
    }
}

impl<T, S> EthernetDriver<T, S>
where
    T: ArpResolve<LinkAddress = MacAddress, InternetAddress = IpAddress> + Sync + Send,
    S: IpParse + Sync + Send,
{
    pub fn new(mac_addr: MacAddress, ip_addr: IpAddress, promisc: bool, socket: Socket) -> Self {
        EthernetDriver {
            promisc,
            arp_resolver: T::new(mac_addr.clone(), ip_addr.clone()),
            ip_parser: S::new(ip_addr.clone()),
            device: EtherDevice { mac_addr, socket },
        }
    }

    pub fn send(&self, data: &[u8]) {
        self.device.send(data);
    }

    pub fn recv<'a>(mut self) -> impl Stream<Item = ()> {
        let (mut sender, receiver) = channel::<Vec<u8>>(N_CHANNEL_BUFFER);
        let socket = self.device.socket.clone();

        std::thread::spawn(move || loop {
            let data = unsafe { socket.recv() };

            sender.try_send(data).expect("The buffer is full");
        });

        receiver.then(move |data| {
            let d = MacHeader::mapped(&data[..]);
            if let Some((h, d)) = d {
                self.analyze(h, d)
            } else {
                future::ready(()).boxed()
            }
        })
    }

    pub fn resolve(
        &mut self,
        ip_addr: IpAddress,
    ) -> Pin<Box<dyn Future<Output = Option<MacAddress>> + Send>> {
        match self.arp_resolver.resolve(ip_addr) {
            ResolveResult::Found(value) => future::ready(Some(value)).boxed(),
            ResolveResult::NotFound {
                packet_to_send,
                result,
            } => {
                println!("- Asking {:?} by broadcasting.", ip_addr);
                self.device.send(&self.device.constract_ethernet_frame(
                    BROADCAST_MAC_ADDR,
                    header::ETHERTYPE_ARP,
                    &packet_to_send,
                ));
                result
            }
        }
    }

    fn analyze_arp(
        &mut self,
        data: &[u8],
        frame_dst: Destination,
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        match self.arp_resolver.parse(data, frame_dst) {
            Err(err) => {
                println!("- {}", err);
            }
            Ok(ArpReply::Nop) => {}
            Ok(ArpReply::Reply { dst, data }) => {
                self.device.send(&self.device.constract_ethernet_frame(
                    dst,
                    header::ETHERTYPE_ARP,
                    &data,
                ));
            }
        }
        future::ready(()).boxed()
    }

    fn analyze_ipv4(
        &mut self,
        data: &[u8],
        frame_dst: Destination,
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        match self.ip_parser.parse(data, frame_dst) {
            Err(err) => {
                println!("- {}", err);
                future::ready(()).boxed()
            }
            Ok(IpReply::Nop) => future::ready(()).boxed(),
            Ok(IpReply::Reply { dst, data }) => {
                let sender = self.device.clone();
                println!("- Resolving IP Address {:?} for ICMP Reply", dst);
                self.resolve(dst)
                    .map(move |result| {
                        if let Some(mac_addr) = result {
                            println!("- ARP Resolving succeeded for ICMP Reply",);
                            sender.send(&sender.constract_ethernet_frame(
                                mac_addr,
                                header::ETHERTYPE_ARP,
                                &data,
                            ));
                        } else {
                            println!("- ARP Resolving failed for ICMP Reply",);
                        }
                    })
                    .boxed()
            }
        }
    }

    fn unknown_type(&self, ether_type: u16) -> Pin<Box<dyn Future<Output = ()>>> {
        println!("Unknown ethertype: {:02X}", ether_type);
        future::ready(()).boxed()
    }

    fn analyze(
        &mut self,
        mac_header: &header::MacHeader,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        let frame_dst = if mac_header.dst_mac == self.device.mac_addr {
            Destination::ToMyself
        } else if mac_header.dst_mac == BROADCAST_MAC_ADDR {
            Destination::Broadcast
        } else {
            Destination::Promisc
        };

        if !self.promisc && frame_dst == Destination::Promisc {
            return future::ready(()).boxed();
        }

        let ether_type = u16::from_be(mac_header.ether_type);

        match ether_type {
            header::ETHERTYPE_IP => self.analyze_ipv4(data, frame_dst),
            header::ETHERTYPE_ARP => self.analyze_arp(data, frame_dst),
            _ => self.unknown_type(ether_type),
        }
    }
}
