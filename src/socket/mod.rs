use libc::{bind, c_int, ioctl, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL, PF_PACKET, SOCK_RAW};

use crate::utils;

mod ifreq;

/// ./x86_64-linux-gnu/bits/ioctls.h:#define SIOCGIFINDEX	0x8933		/* name -> if_index mapping	*/
const SIOCGIFINDEX: usize = 0x8933;

#[derive(Debug)]
pub struct Socket {
    pub fd: c_int,
}

impl Socket {
    pub unsafe fn open_raw_socket() -> Socket {
        Socket {
            fd: socket(
                PF_PACKET,
                SOCK_RAW,
                utils::swap_endian_16(ETH_P_ALL as _) as _,
            ),
        }
    }

    // Should be Result
    pub unsafe fn limit_interface(&self, iface_name: &str) -> Option<()> {
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

        println!("aaaa",);

        let mut sa: sockaddr_ll = std::mem::uninitialized();

        sa.sll_family = AF_PACKET as _;
        sa.sll_protocol = utils::swap_endian_16(ETH_P_ALL as _) as _;
        sa.sll_ifindex = if_req.result.ifr_ifindex;

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
}
