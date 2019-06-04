use map_struct::Mappable;

#[derive(Debug, Copy, Clone)]
#[repr(C, packed)]
pub struct ARPHeader {
    pub hard_addr_space: u16,
    pub proto_addr_space: u16,
    pub hard_addr_len: u8,
    pub proto_addr_len: u8,
    pub op_code: u16,
}

unsafe impl Mappable for ARPHeader {}
