// little <-> big for 16bit
pub fn swap_endian_16(t: u16) -> u16 {
    t << 8 | t >> 8
}

// little <-> big for 16bit
pub fn swap_endian_32(t: u32) -> u32 {
    t << 24 | (t << 16 & 0x00_FF_00_00) | (t >> 16 & 0x00_00_FF_00) | t >> 24
}
