cargo build && sudo setcap cap_net_raw,cap_net_admin=eip target/debug/virtual_ip_host && ./target/debug/virtual_ip_host
