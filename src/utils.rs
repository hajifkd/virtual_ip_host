use libc::{__errno_location, strerror};
use std::ffi::CStr;
use std::fmt;

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
