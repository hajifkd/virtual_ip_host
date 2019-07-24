use virtual_ip_host::arp::EtherIpResolver;
use virtual_ip_host::ether::driver::EthernetDriver;
use virtual_ip_host::ether::MacAddress;
use virtual_ip_host::ip::IpAddress;
use virtual_ip_host::ip::IpDriver;
use virtual_ip_host::socket::Socket;
use virtual_ip_host::utils;

use futures::executor::block_on;
use futures::prelude::*;

fn main() {
    unsafe {
        let mut s = Socket::open_raw_socket();
        if s.fd == -1 {
            utils::show_error_text();
            return;
        }

        s.limit_interface("enp0s3")
            .unwrap_or_else(|| utils::show_error_text());

        s.enable_promisc_mode()
            .unwrap_or_else(|| utils::show_error_text());

        let mut driver = EthernetDriver::<EtherIpResolver, IpDriver>::new(
            MacAddress::new([0x02, 0x00, 0x00, 0xEF, 0x24, 0xA8]),
            IpAddress::new_be_bytes([192, 168, 1, 111]),
            false,
            s,
        );
        let arp_test = driver
            .resolve(IpAddress::new_be_bytes([192, 168, 1, 19]))
            .map(|d| println!("- ARP Resolving Result: {:?}", d));
        let recv = driver.recv();
        let _ = block_on(future::join(arp_test, recv.for_each(|_| future::ready(()))).map(|_| ()));
    }
}
