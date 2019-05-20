extern crate libc;

use libc::{c_int, recv, socket, ETH_P_ALL, PF_PACKET, SOCK_RAW};

mod headers;
mod utils;

fn main() {
    unsafe {
        let s = open_socket();
        println!("fd: {}", s);
        if s == -1 {
            utils::show_error_text();
            return;
        }

        let length = 128;
        let mut buf = vec![0u8; length];
        let r = recv(s, buf.as_mut_ptr() as _, length, 0);
        let mac_header: *const headers::MACHeader = buf.as_ptr() as _;
        println!("{:?}", &*mac_header);
    }
}

unsafe fn open_socket() -> c_int {
    socket(
        PF_PACKET,
        SOCK_RAW,
        utils::swap_endian_16(ETH_P_ALL as _) as _,
    )
}
