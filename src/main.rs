extern crate libc;

use libc::{__errno_location, c_int, socket, strerror, ETH_P_ALL, PF_PACKET, SOCK_RAW};
use std::ffi::CStr;

mod utils;

fn main() {
    unsafe {
        let s = open_socket();
        println!("fd: {}", s);
        if s == -1 {
            let errno = *__errno_location();
            let error_str = CStr::from_ptr(strerror(errno));
            println!("{}", error_str.to_str().unwrap());
        }
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
