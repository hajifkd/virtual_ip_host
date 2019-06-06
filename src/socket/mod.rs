use libc::{
    bind, c_int, ioctl, packet_mreq, recv, setsockopt, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL,
    PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC, PF_PACKET, SOCK_RAW, SOL_PACKET,
};

use crate::ether::header::MACHeader;
use crate::ether::driver::EthernetDriver;
use map_struct::Mappable;

mod ifreq;

/// ./x86_64-linux-gnu/bits/ioctls.h:#define SIOCGIFINDEX	0x8933		/* name -> if_index mapping	*/
const SIOCGIFINDEX: usize = 0x8933;

#[derive(Debug)]
pub struct Socket {
    pub fd: c_int,
    pub ifindex: i32,
}

impl Socket {
    pub unsafe fn open_raw_socket() -> Socket {
        Socket {
            fd: socket(PF_PACKET, SOCK_RAW, u16::from_be(ETH_P_ALL as _) as _),
            ifindex: -1,
        }
    }

    // Should be Result
    pub unsafe fn limit_interface(&mut self, iface_name: &str) -> Option<()> {
        let mut if_req: ifreq::ifreq = std::mem::uninitialized();
        let chars = iface_name.as_bytes();

        if chars.len() + 1 > ifreq::IFNAMSIZ {
            return None;
        }

        for i in 0..chars.len() {
            if_req.ifr_name[i] = chars[i] as _;
        }

        let io_result = ioctl(self.fd, SIOCGIFINDEX as _, &mut if_req as *mut _);

        if io_result < 0 {
            return None;
        }

        dbg!("aaaa");

        let mut sa: sockaddr_ll = std::mem::uninitialized();

        sa.sll_family = AF_PACKET as _;
        sa.sll_protocol = u16::from_be(ETH_P_ALL as _) as _;
        sa.sll_ifindex = if_req.result.ifr_ifindex;
        self.ifindex = if_req.result.ifr_ifindex;

        let bind_result = bind(
            self.fd,
            &sa as *const _ as _,
            std::mem::size_of::<sockaddr_ll>() as _,
        );

        if bind_result < 0 {
            None
        } else {
            Some(())
        }
    }

    pub unsafe fn enable_promisc_mode(&self) -> Option<()> {
        let mut opt: packet_mreq = std::mem::uninitialized();

        if self.ifindex >= 0 {
            opt.mr_ifindex = self.ifindex;
        }

        opt.mr_type = PACKET_MR_PROMISC as _; // the other fields are not used

        if setsockopt(
            self.fd,
            SOL_PACKET,            // socket level API
            PACKET_ADD_MEMBERSHIP, // control physical layer
            &opt as *const _ as _,
            std::mem::size_of::<packet_mreq>() as _,
        ) >= 0
        {
            Some(())
        } else {
            None
        }
    }

    pub unsafe fn recv(&self, analyzer: &mut EthernetDriver) {
        loop {
            // todo use aio?
            let length = 2048;
            let mut buf = vec![0u8; length];
            let l_recv = recv(self.fd, buf.as_mut_ptr() as _, length, 0) as usize;
            MACHeader::mapped(&buf[..l_recv]).map(|(h, d)| analyzer.analyze(h, d));
        }
    }
}
