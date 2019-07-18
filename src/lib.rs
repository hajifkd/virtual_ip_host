extern crate libc;
extern crate map_struct;
#[macro_use]
extern crate failure;
extern crate futures;

pub mod arp;
pub mod ether;
pub mod ip;
pub mod socket;
pub mod utils;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Destination {
    ToMyself,
    Broadcast,
    Promisc,
}
