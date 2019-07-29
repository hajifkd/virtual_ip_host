use crate::Destination;
use error::IpError;
use header::IpHeaderWithoutOptions;
use icmp::error::IcmpError;
use icmp::{IcmpDriver, IcmpReply};
use map_struct::Mappable;
use std::fmt;
use std::mem;

pub mod error;
pub mod header;
pub mod icmp;

#[repr(transparent)]
#[derive(Copy, Clone, Hash, PartialEq, Eq)]
pub struct IpAddress(u32);

pub enum IpReply {
    Reply { dst: IpAddress, data: Vec<u8> },
    Nop,
}

impl IpAddress {
    pub fn new_be_bytes(addr: [u8; 4]) -> Self {
        IpAddress(u32::from_be_bytes(addr))
    }

    pub fn from_be_int(addr: u32) -> IpAddress {
        IpAddress(u32::from_be(addr))
    }

    pub fn from_be(addr: IpAddress) -> IpAddress {
        IpAddress(u32::from_be(addr.0))
    }

    pub fn to_be(addr: IpAddress) -> IpAddress {
        IpAddress(u32::to_be(addr.0))
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

    fn parse(&mut self, data: &[u8], frame_dst: Destination) -> Result<IpReply, IpError>;
}

pub struct IpDriver {
    my_addr: IpAddress,
    icmp_driver: IcmpDriver,
}

fn construct_packet(proto: u8, dst: IpAddress, payload: &[u8]) -> Vec<u8> {
    let mut result = vec![0; mem::size_of::<IpHeaderWithoutOptions>() + payload.len()];
    {
        let (ip_header, payload) = IpHeaderWithoutOptions::mapped_mut(&mut result).unwrap();
        unimplemented!();
    }

    result
}

impl IpDriver {
    fn parse_and_reply_icmp(
        &mut self,
        from: IpAddress,
        frame_dst: Destination,
        data: &[u8],
    ) -> Result<IpReply, IcmpError> {
        let reply = self.icmp_driver.parse(from, frame_dst, data)?;

        match reply {
            IcmpReply::Reply { dst, data } => {
                return Ok(IpReply::Reply {
                    dst,
                    data: construct_packet(icmp::ICMP_PROTOCOL_NUMBER, dst, &data[..]),
                })
            }
            _ => Ok(IpReply::Nop),
        }
    }
}

impl IpParse for IpDriver {
    fn new(my_addr: IpAddress) -> Self {
        IpDriver {
            my_addr,
            icmp_driver: IcmpDriver::new(),
        }
    }

    fn parse(&mut self, data: &[u8], frame_dst: Destination) -> Result<IpReply, IpError> {
        println!("Received IPv4 packet",);
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

        match header.protocol {
            icmp::ICMP_PROTOCOL_NUMBER => self
                .parse_and_reply_icmp(IpAddress::from_be(header.src_addr), frame_dst, payload)
                .map_err(IpError::IcmpError),
            _ => Err(IpError::Unimplemented),
        }
    }
}
