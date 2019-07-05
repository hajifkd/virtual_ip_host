use crate::Destination;
use crate::LinkDriver;
use error::IpError;
use header::IpHeaderWithoutOptions;
use icmp::error::IcmpError;
use map_struct::Mappable;
use std::fmt;

pub mod error;
pub mod header;
pub mod icmp;

#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct IpAddress(u32);

impl IpAddress {
    pub fn new_be_bytes(addr: [u8; 4]) -> Self {
        IpAddress(u32::from_be_bytes(addr))
    }
}

unsafe impl Mappable for IpAddress {}

impl fmt::Debug for IpAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let addrs = self.0.to_be_bytes();
        for (i, addr) in addrs.iter().enumerate() {
            if i != 0 {
                write!(f, ".")?;
            }
            write!(f, "{}", addr)?;
        }
        Ok(())
    }
}

pub trait IpParse {
    fn new(my_addr: IpAddress) -> Self;
    // Should return impl Future
    fn parse<T: crate::LinkDriver>(
        &self,
        data: &[u8],
        frame_dst: Destination,
        driver: &T,
    ) -> Result<(), IpError>;
}

pub struct IpDriver {
    my_addr: IpAddress,
}

impl IpDriver {
    fn parse_and_reply_icmp(data: &[u8]) -> Result<(), IcmpError> {
        unimplemented!()
    }
}

impl IpParse for IpDriver {
    fn new(my_addr: IpAddress) -> Self {
        IpDriver { my_addr }
    }

    fn parse<T: crate::LinkDriver>(
        &self,
        data: &[u8],
        frame_dst: Destination,
        driver: &T,
    ) -> Result<(), IpError> {
        let (header, _) = IpHeaderWithoutOptions::mapped(&data).ok_or(IpError::InvalidIpPacket)?;

        if header.version() != 4 {
            return Err(IpError::Unimplemented);
        }

        if !header.is_valid(&data) {
            return Err(IpError::InvalidChecksum);
        }

        // TODO flagmentation

        let header_length_in_byte = (header.ihl() * 4) as usize;
        if header_length_in_byte >= data.len() {
            return Err(IpError::InvalidIpPacket);
        }

        let payload = &data[header_length_in_byte..];

        if frame_dst == Destination::Promisc {
            return Ok(());
        }

        match header.protocol {
            icmp::ICMP_PROTOCOL_NUMBER => Err(IpError::Unimplemented),
            _ => Err(IpError::Unimplemented),
        }
    }
}
