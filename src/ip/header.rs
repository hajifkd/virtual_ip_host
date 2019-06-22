use super::IPAddress;
use crate::utils::checksum;
use map_struct::Mappable;

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct IPHeaderWithoutOptions {
    pub version_ihl: u8,
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_addr: IPAddress,
    pub dst_addr: IPAddress,
}

unsafe impl Mappable for IPHeaderWithoutOptions {}

impl IPHeaderWithoutOptions {
    pub fn is_valid(&self, orig_data: &[u8]) -> bool {
        let ihl = self.version_ihl & 0x0F;
        checksum(&orig_data[..(ihl << 2) as usize]) == 0
    }

    pub fn version(&self) -> u8 {
        self.version_ihl >> 2
    }

    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }
}
