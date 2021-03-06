#[derive(Debug, Fail)]
pub enum IpError {
    #[fail(display = "unsupported protocol: 0x{:02X}", _0)]
    UnsupportedProtocol(u8),

    #[fail(display = "unimplemented")]
    Unimplemented,

    #[fail(display = "invalid IP packet")]
    InvalidIpPacket,

    #[fail(display = "invalid checksum")]
    InvalidChecksum,

    #[fail(display = "{}", _0)]
    IcmpError(#[fail(cause)] super::icmp::error::IcmpError),
}
