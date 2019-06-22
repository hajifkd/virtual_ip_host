use map_struct::Mappable;
use std::fmt;

pub mod header;
pub mod icmp;

#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct IPAddress(u32);

impl IPAddress {
    pub fn from_network_endian(self) -> Self {
        IPAddress(u32::from_be(self.0))
    }
}

unsafe impl Mappable for IPAddress {}

impl fmt::Debug for IPAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addrs = self.0.to_ne_bytes();
        for (i, addr) in addrs.iter().enumerate() {
            if i != 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", addr)?;
        }
        Ok(())
    }
}
