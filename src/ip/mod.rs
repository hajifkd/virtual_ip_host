use map_struct::Mappable;

pub mod headers;

#[repr(transparent)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct IPAddress(u32);

unsafe impl Mappable for IPAddress {}
