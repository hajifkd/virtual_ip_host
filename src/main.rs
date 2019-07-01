use virtual_ip_host::arp::EtherIpResolver;
use virtual_ip_host::ether::driver::EthernetDriver;
use virtual_ip_host::ether::MacAddress;
use virtual_ip_host::ip::IpAddress;
use virtual_ip_host::ip::IpDriver;
use virtual_ip_host::socket::Socket;
use virtual_ip_host::utils;

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

        s.recv(&mut EthernetDriver::<EtherIpResolver, IpDriver>::new(
            MacAddress::new([0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            IpAddress::new_be_bytes([192, 168, 1, 180]),
            true,
        ));
    }
}
