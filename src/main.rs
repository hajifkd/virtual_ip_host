extern crate libc;

use libc::recv;

mod headers;
mod socket;
mod utils;

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

        let length = 128;
        let mut buf = vec![0u8; length];
        let r = recv(s.fd, buf.as_mut_ptr() as _, length, 0);
        let mac_header: *const headers::MACHeader = buf.as_ptr() as _;
        dbg!(r);
        println!("{:?}", &*mac_header);
    }
}
