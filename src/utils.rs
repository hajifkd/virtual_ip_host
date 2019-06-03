use libc::{__errno_location, strerror};
use std::ffi::CStr;
use std::fmt;

// little <-> big for 16bit
pub fn swap_endian_16(t: u16) -> u16 {
    t << 8 | t >> 8
}

// little <-> big for 16bit
#[allow(dead_code)]
pub fn swap_endian_32(t: u32) -> u32 {
    t << 24 | (t << 8 & 0x00_FF_00_00) | (t >> 8 & 0x00_00_FF_00) | t >> 24
}

pub unsafe fn show_error_text() {
    let errno = *__errno_location();
    let error_str = CStr::from_ptr(strerror(errno));
    println!("{}", error_str.to_str().unwrap());
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    for i in 0..(data.len() / 2) {
        let n = u16::from_ne_bytes([data[i * 2], data[i * 2 + 1]]);
        sum += n as u32;
    }

    let i_last = data.len() / 2;
    if i_last * 2 != data.len() {
        let n = u16::from_ne_bytes([data[i_last * 2], 0]);
        sum += n as u32;
    }

    !(((sum & 0xFFFF) + (sum >> 16)) as u16)
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct Byte(u8);

impl fmt::Debug for Byte {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:02X}", self.0)
    }
}

#[cfg(test)]
mod test {
    use crate::utils::*;

    #[test]
    fn test_swap_endian() {
        assert_eq!(0xFF_00u16, swap_endian_16(0x00_FFu16));
        assert_eq!(0xFF_00_AA_88u32, swap_endian_32(0x88_AA_00_FFu32));
    }

    #[test]
    fn test_checksum() {
        assert_eq!(
            [!0xDD, !0xF2],
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]).to_ne_bytes()
        );
        assert_eq!(
            [!0xF0, !0xEB],
            checksum(&[0x03, 0xf4, 0xf5, 0xf6, 0xf7]).to_ne_bytes()
        );
    }
}
