#[derive(Debug, Fail)]
pub enum IcmpError {
    #[fail(display = "unsupported type: 0x{:02X}", _0)]
    UnsupportedType(u8),

    #[fail(display = "unsupported code: 0x{:02X}", _0)]
    UnsupportedCode(u8),

    #[fail(display = "unimplemented")]
    Unimplemented,

    #[fail(display = "invalid ICMP packet")]
    InvalidIcmpPacket,

    #[fail(display = "invalid checksum")]
    InvalidChecksum,

    #[fail(display = "no empty echo buffer")]
    NoEmptyEchoBuffer,
}
