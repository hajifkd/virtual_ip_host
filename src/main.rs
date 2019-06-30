use virtual_ip_host::arp::EtherIPResolver;
use virtual_ip_host::ether::driver::EthernetDriver;
use virtual_ip_host::ether::MACAddress;
use virtual_ip_host::ip::IPAddress;
use virtual_ip_host::ip::IPDriver;
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

        s.recv(&mut EthernetDriver::<EtherIPResolver, IPDriver>::new(
            MACAddress::new([0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            IPAddress::new_be_bytes([192, 168, 1, 180]),
            true,
        ));
    }
}
