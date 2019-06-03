use crate::utils::checksum;
use map_struct::Mappable;

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct IPHeaderWithoutOptions {
    version_ihl: u8,
    type_of_service: u8,
    total_length: u16,
    identification: u16,
    flags_fragment_offset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src_addr: u32,
    dst_addr: u32,
}

unsafe impl Mappable for IPHeaderWithoutOptions {}

impl IPHeaderWithoutOptions {
    pub fn is_valid(&self, orig_data: &[u8]) -> bool {
        let ihl = self.version_ihl & 0x0F;
        dbg!(std::mem::size_of::<IPHeaderWithoutOptions>());
        checksum(&orig_data[..(ihl << 2) as usize]) == 0
    }
}
