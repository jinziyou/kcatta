//! Listening sockets from `/proc/net/tcp`, `tcp6`, `udp`, `udp6`.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use scanner_contract::{Asset, Port, PortProto};

const PROC_TCP: &str = "/proc/net/tcp";
const PROC_TCP6: &str = "/proc/net/tcp6";
const PROC_UDP: &str = "/proc/net/udp";
const PROC_UDP6: &str = "/proc/net/udp6";

/// TCP `LISTEN` (0x0A) and bound UDP (`st` 07, remote 0).
pub fn collect() -> Vec<Asset> {
    let inode_pid = build_inode_pid_map();
    let mut assets = Vec::new();
    parse_file(PROC_TCP, PortProto::Tcp, false, &inode_pid, &mut assets);
    parse_file(PROC_TCP6, PortProto::Tcp, true, &inode_pid, &mut assets);
    parse_file(PROC_UDP, PortProto::Udp, false, &inode_pid, &mut assets);
    parse_file(PROC_UDP6, PortProto::Udp, true, &inode_pid, &mut assets);
    assets
}

fn parse_file(
    path: &str,
    proto: PortProto,
    ipv6: bool,
    inode_pid: &HashMap<u64, u32>,
    out: &mut Vec<Asset>,
) {
    let Ok(content) = fs::read_to_string(path) else {
        return;
    };
    for line in content.lines().skip(1) {
        if let Some(port) = parse_line(line, proto, ipv6, inode_pid) {
            out.push(Asset::Port(port));
        }
    }
}

fn parse_line(
    line: &str,
    proto: PortProto,
    ipv6: bool,
    inode_pid: &HashMap<u64, u32>,
) -> Option<Port> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    // sl local rem st ... inode
    if fields.len() < 10 {
        return None;
    }
    let local = fields[1];
    let remote = fields[2];
    let st = fields[3];
    let inode: u64 = fields[9].parse().ok()?;

    if !is_listening(proto, st, remote) {
        return None;
    }

    let (addr_hex, port_hex) = local.rsplit_once(':')?;
    let port = parse_proc_port(port_hex)?;
    let listen_addr = if ipv6 {
        parse_proc_ipv6(addr_hex)
    } else {
        parse_proc_ipv4(addr_hex)
    };

    let pid = inode_pid.get(&inode).copied();
    let process_name = pid.and_then(read_comm);

    Some(Port {
        asset_id: format!(
            "port-{port}-{}-{listen_addr}",
            match proto {
                PortProto::Tcp => "tcp",
                PortProto::Udp => "udp",
            }
        ),
        proto,
        port,
        listen_addr,
        process_name,
        pid,
    })
}

/// TCP LISTEN; UDP bound with no remote endpoint.
fn is_listening(proto: PortProto, st: &str, remote: &str) -> bool {
    match proto {
        PortProto::Tcp => st.eq_ignore_ascii_case("0A"),
        PortProto::Udp => st.eq_ignore_ascii_case("07") && is_unbound_remote(remote),
    }
}

/// Remote `00000000:0000` (IPv4) or `000…000:0000` (IPv6) in `/proc/net`.
fn is_unbound_remote(remote: &str) -> bool {
    let Some((addr, port)) = remote.rsplit_once(':') else {
        return false;
    };
    port == "0000" && addr.chars().all(|c| c == '0')
}

fn parse_proc_port(hex: &str) -> Option<u16> {
    u16::from_str_radix(hex, 16).ok()
}

fn parse_proc_ipv4(hex: &str) -> String {
    let n = u32::from_str_radix(hex, 16).unwrap_or(0);
    format!(
        "{}.{}.{}.{}",
        n & 0xff,
        (n >> 8) & 0xff,
        (n >> 16) & 0xff,
        (n >> 24) & 0xff
    )
}

fn parse_proc_ipv6(hex: &str) -> String {
    if hex.len() != 32 {
        return hex.to_string();
    }
    let mut parts = Vec::with_capacity(8);
    for i in 0..8 {
        let word = u16::from_str_radix(&hex[i * 4..i * 4 + 4], 16).unwrap_or(0);
        parts.push(format!("{:x}", word.to_be()));
    }
    parts.join(":")
}

fn build_inode_pid_map() -> HashMap<u64, u32> {
    let mut map = HashMap::new();
    let proc = Path::new("/proc");
    let Ok(entries) = fs::read_dir(proc) else {
        return map;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let fd_dir = proc.join(name.as_ref()).join("fd");
        let Ok(fds) = fs::read_dir(fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            let Some(rest) = target.strip_prefix("socket:[") else {
                continue;
            };
            let Some(inode_str) = rest.strip_suffix(']') else {
                continue;
            };
            let Ok(inode) = inode_str.parse::<u64>() else {
                continue;
            };
            map.entry(inode).or_insert(pid);
        }
    }
    map
}

fn read_comm(pid: u32) -> Option<String> {
    let comm = fs::read_to_string(format!("/proc/{pid}/comm")).ok()?;
    let name = comm.trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proc_port_hex() {
        assert_eq!(parse_proc_port("1F98").unwrap(), 8088);
        assert_eq!(parse_proc_port("0050").unwrap(), 80);
    }

    #[test]
    fn parse_proc_ipv4_loopback() {
        assert_eq!(parse_proc_ipv4("0100007F"), "127.0.0.1");
        assert_eq!(parse_proc_ipv4("00000000"), "0.0.0.0");
    }

    #[test]
    fn tcp_listen_line() {
        let line = "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        let port = parse_line(line, PortProto::Tcp, false, &HashMap::new()).unwrap();
        assert_eq!(port.port, 80);
        assert_eq!(port.listen_addr, "127.0.0.1");
        assert_eq!(port.proto, PortProto::Tcp);
    }

    #[test]
    fn tcp_non_listen_skipped() {
        let line = "   0: 0100007F:0050 0100007F:0016 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        assert!(parse_line(line, PortProto::Tcp, false, &HashMap::new()).is_none());
    }

    #[test]
    fn udp_bound_line() {
        let line = " 2387: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 7186 2 00000000eac42c63 0";
        let port = parse_line(line, PortProto::Udp, false, &HashMap::new()).unwrap();
        assert_eq!(port.port, 53);
        assert_eq!(port.listen_addr, "0.0.0.0");
    }

    #[test]
    fn udp6_bound_line() {
        let line = " 2657: 00000000000000000000000001000000:0143 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 7175 2 000000006dd2f201 0";
        assert!(parse_line(line, PortProto::Udp, true, &HashMap::new()).is_some());
    }
}
