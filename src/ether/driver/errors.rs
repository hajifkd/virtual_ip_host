#[derive(Debug, Fail)]
pub enum ARPError {
    #[fail(display = "unsupported hardware address space: 0x{:04X}", _0)]
    UnsupportedHardwareAddressSpace(u16),

    #[fail(display = "unsupported protocol address space: 0x{:04X}", _0)]
    UnsupportedProtocolAddressSpace(u16),

    #[fail(display = "unsupported operation code: 0x{:04X}", _0)]
    UnsupportedOperationCode(u16),
    #[fail(display = "invalid ARP packet")]
    InvalidARPPacket,
}
