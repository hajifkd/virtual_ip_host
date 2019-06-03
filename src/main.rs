extern crate libc;
extern crate map_struct;

mod ether;
mod socket;
mod utils;

use ether::headers::MACHeader;
use socket::Socket;

fn main() {
    unsafe {
        let mut s = Socket::open_raw_socket();
        println!("fd: {:?}", s);
        if s.fd == -1 {
            utils::show_error_text();
            return;
        }

        s.limit_interface("enp0s3")
            .unwrap_or_else(|| utils::show_error_text());

        s.enable_promisc_mode()
            .unwrap_or_else(|| utils::show_error_text());

        s.recv(&MyAnalyzer);
    }
}

struct MyAnalyzer;

impl socket::EtherAnalyze for MyAnalyzer {
    fn analyze(&self, mac_header: &MACHeader, data: &[u8]) {
        println!("packet received");
        println!("MAC header: {:?}", mac_header);
    }
}
