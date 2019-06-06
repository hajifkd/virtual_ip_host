extern crate libc;
extern crate map_struct;
#[macro_use]
extern crate failure;

mod arp;
mod ether;
mod ip;
mod socket;
mod utils;

use ether::driver::EthernetDriver;
use ether::MACAddress;
use socket::Socket;

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

        s.recv(&mut EthernetDriver::new(
            MACAddress::new([0x03, 0x04, 0x05, 0x06, 0x07, 0x08]),
            true,
        ));
    }
}
