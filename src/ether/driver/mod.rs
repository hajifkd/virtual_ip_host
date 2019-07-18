use super::{header, MacAddress, BROADCAST_MAC_ADDR};
use crate::arp::ArpResolve;

use crate::ether::header::MacHeader;
use crate::ip::IpAddress;
use crate::ip::IpParse;
use crate::socket::Socket;
use crate::Destination;

use futures::channel::mpsc::channel;
use futures::future;
use futures::prelude::*;
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
    mac_addr: MacAddress,
    arp_resolver: T,
    ip_parser: S,
    socket: Socket,
}

impl<T, S> EthernetDriver<T, S>
where
    T: ArpResolve<LinkAddress = MacAddress, InternetAddress = IpAddress> + Sync + Send,
    S: IpParse + Sync + Send,
{
    pub fn new(mac_addr: MacAddress, ip_addr: IpAddress, promisc: bool, socket: Socket) -> Self {
        EthernetDriver {
            promisc,
            mac_addr,
            arp_resolver: T::new(mac_addr.clone()),
            ip_parser: S::new(ip_addr.clone()),
            socket,
        }
    }

    pub fn send(&self, data: &[u8]) {
        // TODO check MTU
        unsafe {
            self.socket.send(data);
        }
    }

    pub fn recv<'a>(mut self) -> impl Stream<Item = ()> {
        let (mut sender, receiver) = channel::<Vec<u8>>(N_CHANNEL_BUFFER);
        let socket = self.socket.clone();

        std::thread::spawn(move || loop {
            let data = unsafe { socket.recv() };

            sender.try_send(data).expect("The buffer is full");
        });

        receiver.then(move |data| {
            let d = MacHeader::mapped(&data[..]);
            if let Some((h, d)) = d {
                self.analyze(h, d)
            } else {
                future::lazy(|_| ()).boxed()
            }
        })
    }

    fn analyze_arp(
        &mut self,
        data: &[u8],
        frame_dst: Destination,
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        println!("Received ARP packet",);
        self.arp_resolver.parse(data, frame_dst);

        // TODO reply

        future::lazy(|_| unimplemented!()).boxed()
    }

    fn analyze_ipv4(
        &mut self,
        data: &[u8],
        frame_dst: Destination,
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        println!("Received IPv4 packet",);
        let packet = {
            let packet = self.ip_parser.parse(data, frame_dst);

            if let Err(err) = packet {
                println!(" - {}", err);
                return future::lazy(|_| ()).boxed();
            }

            let packet = packet.unwrap();

            if packet.is_none() {
                return future::lazy(|_| ()).boxed();
            }

            packet.unwrap()
        };

        // TODO parse

        future::lazy(|_| ()).boxed()
    }

    fn unknown_type(&self, ether_type: u16) -> Pin<Box<dyn Future<Output = ()>>> {
        println!("Unknown ethertype: {:02X}", ether_type);
        future::lazy(|_| ()).boxed()
    }

    fn analyze(
        &mut self,
        mac_header: &header::MacHeader,
        data: &[u8],
    ) -> Pin<Box<dyn Future<Output = ()>>> {
        let frame_dst = if mac_header.dst_mac == self.mac_addr {
            Destination::ToMyself
        } else if mac_header.dst_mac == BROADCAST_MAC_ADDR {
            Destination::Broadcast
        } else {
            Destination::Promisc
        };

        if !self.promisc && frame_dst == Destination::Promisc {
            return future::lazy(|_| ()).boxed();
        }

        let ether_type = u16::from_be_bytes(mac_header.ether_type);

        match ether_type {
            header::ETHERTYPE_IP => self.analyze_ipv4(data, frame_dst),
            header::ETHERTYPE_ARP => self.analyze_arp(data, frame_dst),
            _ => self.unknown_type(ether_type),
        }
    }
}
