extern crate libc;

use libc::{c_int, socket, recv, ETH_P_ALL, PF_PACKET, SOCK_RAW, PT_NULL};

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
        dbg!(r);
        dbg!(buf);
    }
    println!("Hello, world!");
}

unsafe fn open_socket() -> c_int {
    socket(
        PF_PACKET,
        SOCK_RAW,
        utils::swap_endian_16(ETH_P_ALL as _) as _,
    )
}
