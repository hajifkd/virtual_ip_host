use map_struct::Mappable;
use std::fmt;

pub mod driver;
pub mod header;

#[repr(C, packed)]
#[derive(PartialEq, Eq, Copy, Clone, Hash)]
pub struct MacAddress {
    pub address: [u8; 6],
}

impl MacAddress {
    pub fn new(address: [u8; 6]) -> Self {
        MacAddress { address }
    }
}

unsafe impl Mappable for MacAddress {}

pub const BROADCAST_MAC_ADDR: MacAddress = MacAddress {
    address: [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
};

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (i, n) in self.address.iter().enumerate() {
            if i != 0 {
                write!(f, ":")?;
            }
            write!(f, "{:02X}", n)?;
        }
        Ok(())
    }
}
