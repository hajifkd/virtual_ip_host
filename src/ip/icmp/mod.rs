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
    pub fn parse(&self, data: &[u8]) -> Result<IcmpReply, IcmpError> {
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
                    EchoPacketWithoutData::mapped(payload).ok_or(IcmpError::InvalidIcmpPacket)?;

                let mut result = vec![0; data.len()];
                {
                    let (reply_header, rest) = IcmpHeader::mapped_mut(&mut result).unwrap();
                    reply_header.icmp_type = ECHO_REPLY_TYPE;
                    reply_header.code = ECHO_CODE;

                    let (reply_packet_wo_data, rest) =
                        EchoPacketWithoutData::mapped_mut(rest).unwrap();
                    reply_packet_wo_data.identifier = id_seq.identifier;
                    reply_packet_wo_data.sequence_id = id_seq.sequence_id + 1;

                    rest.copy_from_slice(data);
                }
                let checksum = utils::checksum(&result);
                {
                    let (reply_header, _) = IcmpHeader::mapped_mut(&mut result).unwrap();
                    reply_header.checksum = checksum;
                }

                Ok(IcmpReply::Reply(result))
            }
            ECHO_REPLY_TYPE => {
                //Ok(IcmpReply::Nop)
                unimplemented!()
            }
            _ => Err(IcmpError::Unimplemented),
        }
    }
}
