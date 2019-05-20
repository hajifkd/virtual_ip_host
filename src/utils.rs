use libc::{__errno_location, strerror};
use std::ffi::CStr;

// little <-> big for 16bit
pub fn swap_endian_16(t: u16) -> u16 {
    t << 8 | t >> 8
}

// little <-> big for 16bit
pub fn swap_endian_32(t: u32) -> u32 {
    t << 24 | (t << 8 & 0x00_FF_00_00) | (t >> 8 & 0x00_00_FF_00) | t >> 24
}

pub unsafe fn show_error_text() {
    let errno = *__errno_location();
    let error_str = CStr::from_ptr(strerror(errno));
    println!("{}", error_str.to_str().unwrap());
}

#[cfg(test)]
mod test {
    use crate::utils::*;

    #[test]
    fn test_swap_endian() {
        assert_eq!(0xFF_00u16, swap_endian_16(0x00_FFu16));
        assert_eq!(0xFF_00_AA_88u32, swap_endian_32(0x88_AA_00_FFu32));
    }
}
