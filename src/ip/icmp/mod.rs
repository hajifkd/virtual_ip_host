pub mod echo;
pub mod error;
pub mod header;

use super::IpAddress;
use crate::utils;
use echo::{EchoPacketWithoutData, EchoReply};
use error::IcmpError;
use futures::channel::mpsc::{channel, Receiver, Sender};
use header::IcmpHeader;
use map_struct::Mappable;
use std::collections::{HashMap, HashSet};
use std::mem::size_of;

pub const ICMP_PROTOCOL_NUMBER: u8 = 1;

pub const ECHO_REPLY_TYPE: u8 = 0;
pub const ECHO_TYPE: u8 = 8;
pub const ECHO_CODE: u8 = 0;

const BUFFER_SIZE: usize = 32;

pub enum IcmpReply {
    Reply { dst: IpAddress, data: Vec<u8> },
    Nop,
}

pub struct IcmpDriver {
    // HashMap, for instance?
    echo_requests: HashMap<u16, Sender<EchoReply>>,
    used_identifier: HashSet<u16>,
}

fn construct_echo_packet(
    icmp_type: u8,
    echo_wo_data: EchoPacketWithoutData,
    data: &[u8],
) -> Vec<u8> {
    let mut result =
        vec![0; size_of::<IcmpHeader>() + size_of::<EchoPacketWithoutData>() + data.len()];
    {
        let (reply_header, rest) = IcmpHeader::mapped_mut(&mut result).unwrap();
        reply_header.icmp_type = icmp_type.to_be();
        reply_header.code = ECHO_CODE.to_be();

        let (reply_packet_wo_data, rest) = EchoPacketWithoutData::mapped_mut(rest).unwrap();
        reply_packet_wo_data.identifier = echo_wo_data.identifier.to_be();
        reply_packet_wo_data.sequence_id = echo_wo_data.sequence_id.to_be();

        rest.copy_from_slice(data);
    }
    let checksum = utils::checksum(&result);
    {
        let (reply_header, _) = IcmpHeader::mapped_mut(&mut result).unwrap();
        reply_header.checksum = checksum.to_be();
    }
    result
}

impl IcmpDriver {
    pub fn new() -> Self {
        IcmpDriver {
            echo_requests: HashMap::new(),
            used_identifier: HashSet::new(),
        }
    }

    pub fn register_echo(&mut self, data: &[u8]) -> Option<(u16, Vec<u8>, Receiver<EchoReply>)> {
        let identifier = (0..=(std::u16::MAX))
            .filter(|&v| !self.used_identifier.contains(&v))
            .next()?;
        let (sender, receiver) = channel(BUFFER_SIZE);
        self.used_identifier.insert(identifier);

        self.echo_requests.insert(identifier, sender);

        Some((
            identifier,
            construct_echo_packet(
                ECHO_TYPE,
                EchoPacketWithoutData {
                    identifier,
                    sequence_id: 0,
                },
                data,
            ),
            receiver,
        ))
    }

    pub fn parse(&mut self, from: IpAddress, data: &[u8]) -> Result<IcmpReply, IcmpError> {
        let (header, payload) = IcmpHeader::mapped(data).ok_or(IcmpError::InvalidIcmpPacket)?;

        if utils::checksum(data) != 0 {
            return Err(IcmpError::InvalidChecksum);
        }

        if u8::from_be(header.code) != ECHO_CODE {
            return Err(IcmpError::Unimplemented);
        }

        match u8::from_be(header.icmp_type) {
            ECHO_TYPE => {
                let (id_seq, data) =
                    EchoPacketWithoutData::mapped(payload).ok_or(IcmpError::InvalidIcmpPacket)?;

                let result = construct_echo_packet(
                    ECHO_REPLY_TYPE,
                    EchoPacketWithoutData {
                        identifier: u16::from_be(id_seq.identifier),
                        sequence_id: u16::from_be(id_seq.sequence_id) + 1,
                    },
                    data,
                );

                Ok(IcmpReply::Reply {
                    dst: from,
                    data: result,
                })
            }
            ECHO_REPLY_TYPE => {
                let (id_seq, data) =
                    EchoPacketWithoutData::mapped(payload).ok_or(IcmpError::InvalidIcmpPacket)?;

                let receiver = self
                    .echo_requests
                    .get_mut(&u16::from_be(id_seq.identifier))
                    .ok_or(IcmpError::InvalidIcmpPacket)?;

                receiver
                    .try_send(EchoReply {
                        src: from,
                        sequence_id: u16::from_be(id_seq.sequence_id) + 1,
                        data: data.into(),
                    })
                    .map_err(|_| IcmpError::NoEmptyEchoBuffer)?;
                Ok(IcmpReply::Nop)
            }
            _ => Err(IcmpError::Unimplemented),
        }
    }
}
