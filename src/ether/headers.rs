use map_struct::Mappable;
use std::fmt;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct MACHeader {
    pub dst_mac: MACAddress,
    pub src_mac: MACAddress,
    pub ether_type: [u8; 2],
}

unsafe impl Mappable for MACHeader {}

#[repr(C)]
#[derive(PartialEq, Eq)]
pub struct MACAddress {
    pub address: [u8; 6],
}

impl fmt::Debug for MACAddress {
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

pub const ETHERTYPE_IP: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
