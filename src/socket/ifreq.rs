use libc::{c_char, c_int, c_short, sockaddr};

pub const IFNAMSIZ: usize = 16;

#[derive(Copy, Clone)]
#[repr(C)]
pub union IfreqParam {
    pub ifr_addr: sockaddr,
    pub ifr_dstaddr: sockaddr,
    pub ifr_broadaddr: sockaddr,
    pub ifr_netmask: sockaddr,
    pub ifr_hwaddr: sockaddr,
    pub ifr_flags: c_short,
    pub ifr_ifindex: c_int,
    pub ifr_metric: c_int,
    pub ifr_mtu: c_int,
    //struct ifmap    ifr_map;
    /*
    struct ifmap {
        unsigned long   mem_start;
        unsigned long   mem_end;
        unsigned short  base_addr;
        unsigned char   irq;
        unsigned char   dma;
        unsigned char   port;
    };
    */
    pub ifr_slave: [c_char; IFNAMSIZ],
    pub ifr_newname: [c_char; IFNAMSIZ],
    pub ifr_data: *mut c_char,
}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct ifreq {
    pub ifr_name: [c_char; IFNAMSIZ],
    pub param: IfreqParam,
}
