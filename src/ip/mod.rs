use crate::Destination;
use error::IPError;
use header::IPHeaderWithoutOptions;
use icmp::error::IcmpError;
use map_struct::Mappable;
use std::fmt;

pub mod error;
pub mod header;
pub mod icmp;

#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct IPAddress(u32);

impl IPAddress {
    pub fn new_be_bytes(addr: [u8; 4]) -> Self {
        IPAddress(u32::from_be_bytes(addr))
    }
}

unsafe impl Mappable for IPAddress {}

impl fmt::Debug for IPAddress {
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

pub trait IPParse {
    fn new(my_addr: IPAddress) -> Self;
    // Should return impl Future
    fn parse<T: crate::LinkDriver>(
        &self,
        data: &[u8],
        frame_dst: Destination,
        driver: &T,
    ) -> Result<(), IPError>;
}

pub struct IPDriver {
    my_addr: IPAddress,
}

impl IPDriver {
    fn parse_and_reply_icmp(data: &[u8]) -> Result<(), IcmpError> {
        Ok(())
    }
}

impl IPParse for IPDriver {
    fn new(my_addr: IPAddress) -> Self {
        IPDriver { my_addr }
    }

    fn parse<T: crate::LinkDriver>(
        &self,
        data: &[u8],
        frame_dst: Destination,
        driver: &T,
    ) -> Result<(), IPError> {
        let (header, _) = IPHeaderWithoutOptions::mapped(&data).ok_or(IPError::InvalidIPPacket)?;

        if header.version() != 4 {
            return Err(IPError::Unimplemented);
        }

        if !header.is_valid(&data) {
            return Err(IPError::InvalidChecksum);
        }

        // TODO flagmentation

        let header_length_in_byte = (header.ihl() * 4) as usize;
        if header_length_in_byte >= data.len() {
            return Err(IPError::InvalidIPPacket);
        }

        let payload = &data[header_length_in_byte..];

        if frame_dst == Destination::Promisc {
            return Ok(());
        }

        match header.protocol {
            icmp::ICMP_PROTOCOL_NUMBER => Err(IPError::Unimplemented),
            _ => Err(IPError::Unimplemented),
        }
    }
}
