use libc::{
    bind, c_int, ioctl, open, packet_mreq, recv, sendto, setsockopt, sockaddr_ll, socket, write,
    AF_PACKET, ETH_ALEN, ETH_P_ALL, IFF_TAP, O_RDWR, PACKET_ADD_MEMBERSHIP, PACKET_MR_PROMISC,
    PF_PACKET, SOCK_RAW, SOL_PACKET,
};

use std::ffi::CStr;

mod ifreq;

/// ./x86_64-linux-gnu/bits/ioctls.h:#define SIOCGIFINDEX	0x8933		/* name -> if_index mapping	*/
const SIOCGIFINDEX: usize = 0x8933;

const TUNSETIFF: usize = 0x400454ca;
const TAP_NAME: &'static [u8; 4] = b"tap0";

#[derive(Debug, Clone)]
pub struct Socket {
    pub fd: c_int,
    pub tap_fd: c_int,
    pub ifindex: i32,
}

unsafe fn open_tap() -> Option<c_int> {
    let mut if_req: ifreq::ifreq = std::mem::uninitialized();
    let fd = open(
        CStr::from_bytes_with_nul_unchecked(b"/dev/net/tun\0").as_ptr() as _,
        O_RDWR,
    );
    if fd < 0 {
        return None;
    }

    if_req.param.ifr_flags = IFF_TAP as _;
    for i in 0..TAP_NAME.len() {
        if_req.ifr_name[i] = TAP_NAME[i] as _;
    }

    let err = ioctl(fd, TUNSETIFF as _, &mut if_req as *mut _);

    if err < 0 {
        None
    } else {
        Some(fd)
    }
}

impl Socket {
    pub unsafe fn open_raw_socket() -> Socket {
        Socket {
            fd: socket(PF_PACKET, SOCK_RAW, u16::from_be(ETH_P_ALL as _) as _),
            tap_fd: open_tap().expect("Open TAP Failed"),
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

        let mut sa: sockaddr_ll = std::mem::uninitialized();

        sa.sll_family = AF_PACKET as _;
        sa.sll_protocol = u16::from_be(ETH_P_ALL as _) as _;
        sa.sll_ifindex = if_req.param.ifr_ifindex;
        self.ifindex = if_req.param.ifr_ifindex;

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

    pub unsafe fn recv(&self) -> Vec<u8> {
        let length = 2048;
        let mut buf = vec![0u8; length];
        let l_recv = recv(self.fd, buf.as_mut_ptr() as _, length, 0) as usize;
        buf.truncate(l_recv);
        buf
    }

    pub unsafe fn send(&self, buf: &[u8]) -> isize {
        let mut sa: sockaddr_ll = std::mem::uninitialized();

        sa.sll_family = AF_PACKET as _;
        if self.ifindex >= 0 {
            sa.sll_ifindex = self.ifindex;
        }
        sa.sll_halen = ETH_ALEN as _;
        for i in 0..ETH_ALEN as _ {
            sa.sll_addr[i] = 0xFF;
        }

        write(self.tap_fd, buf.as_ptr() as _, buf.len());

        sendto(
            self.fd,
            buf.as_ptr() as _,
            buf.len(),
            0,
            &sa as *const _ as _,
            std::mem::size_of::<sockaddr_ll>() as _,
        )
    }
}
