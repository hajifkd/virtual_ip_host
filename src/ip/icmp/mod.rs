pub mod error;
pub mod header;

use crate::utils;
use error::IcmpError;
use header::IcmpHeader;
use map_struct::Mappable;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct EchoPacketWithoutData {
    identifier: u16,
    sequence_id: u16,
}

unsafe impl Mappable for EchoPacketWithoutData {}

pub const ICMP_PROTOCOL_NUMBER: u8 = 1;

pub const ECHO_REPLY_TYPE: u8 = 0;
pub const ECHO_TYPE: u8 = 8;
pub const ECHO_CODE: u8 = 0;

pub enum IcmpReply {
    Reply(Vec<u8>),
    Nop,
}

pub struct IcmpDriver {
    // HashMap, for instance?
}

impl IcmpDriver {
    fn parse(&self, data: &[u8]) -> Result<IcmpReply, IcmpError> {
        let (header, payload) = IcmpHeader::mapped(data).ok_or(IcmpError::InvalidIcmpPacket)?;

        if utils::checksum(data) != 0 {
            return Err(IcmpError::InvalidChecksum);
        }

        if header.code != ECHO_CODE {
            return Err(IcmpError::Unimplemented);
        }

        match header.icmp_type {
            ECHO_TYPE => {
                let (id_seq, data) =
                    EchoPacketWithoutData::mapped(data).ok_or(IcmpError::InvalidIcmpPacket)?;

                let reply_header = IcmpHeader {
                    icmp_type: ECHO_REPLY_TYPE,
                    code: ECHO_CODE,
                    checksum: 0,
                };

                let reply_packet_wo_data = EchoPacketWithoutData {
                    identifier: id_seq.identifier,
                    sequence_id: id_seq.sequence_id + 1,
                };

                let mut result = vec![];
                // TODO checksum
                result.extend_from_slice(reply_header.as_bytes());
                result.extend_from_slice(reply_packet_wo_data.as_bytes());
                result.extend_from_slice(data);

                //Ok(IcmpReply::Reply(result))
                return unimplemented!();
            }
            ECHO_REPLY_TYPE => {
                return unimplemented!();
                //Ok(IcmpReply::Nop);
            }
            _ => Err(IcmpError::Unimplemented),
        }
    }
}
