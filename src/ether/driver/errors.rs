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

#[derive(Debug, Fail)]
pub enum IPError {
    #[fail(display = "unsupported protocol: 0x{:02X}", _0)]
    UnsupportedProtocol(u8),

    #[fail(display = "unimplemented")]
    Unimplemented,

    #[fail(display = "invalid IP packet")]
    InvalidIPPacket,

    #[fail(display = "invalid checksum")]
    InvalidChecksum,
}
