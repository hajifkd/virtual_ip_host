use map_struct::Mappable;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ICMPHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
}

unsafe impl Mappable for ICMPHeader {}
