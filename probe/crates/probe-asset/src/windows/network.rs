//! Network addresses from the SYSTEM registry hive (Tcpip + adapter class).

use std::collections::HashSet;

use super::registry::{control_set_prefix, HiveKind, RegistryAccess};

const NET_CLASS: &str = r"Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

/// Observed IP and MAC addresses from offline/live registry data.
pub struct NetworkAddrs {
    pub ip_addrs: Vec<String>,
    pub mac_addrs: Vec<String>,
}

/// Collect non-loopback IP and hardware MAC addresses from registry.
pub fn collect_network(reg: &RegistryAccess) -> NetworkAddrs {
    let cs = control_set_prefix(reg);
    let mut ips = HashSet::new();
    let mut macs = HashSet::new();

    let iface_base = format!("{cs}\\Services\\Tcpip\\Parameters\\Interfaces");
    for guid in reg.list_subkeys(HiveKind::System, &iface_base) {
        let path = format!("{iface_base}\\{guid}");
        for ip in reg.get_multi_string(HiveKind::System, &path, "IPAddress") {
            push_ip(&mut ips, &ip);
        }
        for ip in reg.get_multi_string(HiveKind::System, &path, "DhcpIPAddress") {
            push_ip(&mut ips, &ip);
        }
        if let Some(ip) = reg.get_string(HiveKind::System, &path, "DhcpIPAddress") {
            push_ip(&mut ips, &ip);
        }
    }

    let class_base = format!("{cs}\\{NET_CLASS}");
    for subkey in reg.list_subkeys(HiveKind::System, &class_base) {
        if !subkey.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let path = format!("{class_base}\\{subkey}");
        let values = reg.read_values(HiveKind::System, &path);
        let desc = values.get("DriverDesc").map(String::as_str).unwrap_or("");
        if is_virtual_adapter(desc) {
            continue;
        }
        if let Some(raw) = values.get("NetworkAddress").filter(|m| !m.is_empty()) {
            if let Some(mac) = format_mac(raw) {
                macs.insert(mac);
            }
        }
    }

    NetworkAddrs {
        ip_addrs: sorted(ips),
        mac_addrs: sorted(macs),
    }
}

fn push_ip(out: &mut HashSet<String>, ip: &str) {
    let ip = ip.trim();
    if ip.is_empty() || is_noise_ip(ip) {
        return;
    }
    out.insert(ip.to_string());
}

fn is_noise_ip(ip: &str) -> bool {
    ip == "0.0.0.0"
        || ip.starts_with("127.")
        || ip == "::1"
        || ip.starts_with("fe80:")
        || ip.starts_with("169.254.")
}

fn is_virtual_adapter(desc: &str) -> bool {
    let lowered = desc.to_ascii_lowercase();
    lowered.contains("virtual")
        || lowered.contains("hyper-v")
        || lowered.contains("vmware")
        || lowered.contains("loopback")
        || lowered.contains("vpn")
        || lowered.contains("tap")
}

fn format_mac(raw: &str) -> Option<String> {
    let hex: String = raw.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 12 {
        return None;
    }
    let bytes: Vec<&str> = hex
        .as_bytes()
        .chunks(2)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect();
    Some(bytes.join(":").to_ascii_uppercase())
}

fn sorted(set: HashSet<String>) -> Vec<String> {
    let mut out: Vec<String> = set.into_iter().collect();
    out.sort();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_registry_mac() {
        assert_eq!(
            format_mac("001122AABBCC").as_deref(),
            Some("00:11:22:AA:BB:CC")
        );
    }

    #[test]
    fn filters_noise_ips() {
        assert!(is_noise_ip("0.0.0.0"));
        assert!(is_noise_ip("127.0.0.1"));
        assert!(!is_noise_ip("10.0.0.5"));
    }
}
