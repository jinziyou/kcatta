//! Linux host descriptor from fixed paths under the scan root.
//!
//! Most facts come from files under `ctx.scan_root` so an offline/mounted image
//! scans the same as a live host. Two facts are genuinely runtime state and have
//! no on-disk source: IP addresses (collected via `getifaddrs`, **only** when the
//! scan root is the live `/`) and — best-effort — MACs (read from
//! `sys/class/net/*/address`, which exists under a live root).

use std::path::Path;

use crate::ScanContext;
use agent_contract::HostInfo;

use crate::root::{join_root, read_trim_at};

/// Collect [`HostInfo`] from `etc/hostname`, `etc/os-release`, `proc/*`, and
/// (live root only) the network interfaces.
pub fn collect(ctx: &ScanContext) -> HostInfo {
    let root = &ctx.scan_root;
    let kernel = read_trim_at(root, "proc/version");
    let hostname = read_hostname(root);

    HostInfo {
        host_id: stable_host_id(&hostname, root),
        hostname,
        os: read_os_release(&join_root(ctx, "etc/os-release"))
            .unwrap_or_else(|| "unknown".to_string()),
        arch: detect_arch(ctx, kernel.as_deref()),
        mac_addrs: read_mac_addrs(root),
        ip_addrs: read_ip_addrs(root),
        kernel,
        boot_time: None,
    }
}

/// `/`-root means we're scanning the live host (vs a mounted image).
fn is_live_root(root: &Path) -> bool {
    root == Path::new("/")
}

/// Hostname from `etc/hostname`, falling back to `proc/sys/kernel/hostname`
/// (populated on a live host even when `/etc/hostname` is empty — common on
/// cloud/systemd images), then a stable placeholder.
fn read_hostname(root: &Path) -> String {
    read_trim_at(root, "etc/hostname")
        .or_else(|| read_trim_at(root, "proc/sys/kernel/hostname"))
        .unwrap_or_else(|| "unknown-host".to_string())
}

fn stable_host_id(hostname: &str, root: &std::path::Path) -> String {
    let safe: String = hostname
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let root_tag = root.file_name().and_then(|s| s.to_str()).unwrap_or("root");
    format!("host-{safe}-{root_tag}")
}

fn read_os_release(path: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let mut pretty = None;
    let mut name = None;
    let mut version = None;
    for line in text.lines() {
        if let Some(v) = parse_kv(line, "PRETTY_NAME") {
            pretty = Some(v);
        } else if let Some(v) = parse_kv(line, "NAME") {
            name = Some(v);
        } else if let Some(v) = parse_kv(line, "VERSION_ID") {
            version = Some(v);
        }
    }
    pretty.or_else(|| match (name, version) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        _ => None,
    })
}

fn read_os_release_key(path: &std::path::Path, key: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|line| parse_kv(line, key))
}

/// Best-effort CPU architecture. Order: an explicit `ARCHITECTURE=` in
/// os-release (rare), the arch token in the kernel version string (works on
/// x86_64 and arm64, where `/proc/cpuinfo` has no `machine:` line), the
/// `/proc/cpuinfo` `machine:` line (s390/ppc/some arm), and finally — when
/// scanning the live root — the arch this binary was built for (it runs on the
/// target, so they match).
fn detect_arch(ctx: &ScanContext, kernel: Option<&str>) -> Option<String> {
    read_os_release_key(&join_root(ctx, "etc/os-release"), "ARCHITECTURE")
        .or_else(|| kernel.and_then(arch_from_kernel))
        .or_else(|| read_machine_arch(&join_root(ctx, "proc/cpuinfo")))
        .or_else(|| is_live_root(&ctx.scan_root).then(|| std::env::consts::ARCH.to_string()))
}

/// Normalize the arch token embedded in a kernel version string
/// (e.g. `...el10_1.x86_64 ...` → `x86_64`, Debian `...-amd64` → `x86_64`).
fn arch_from_kernel(kernel: &str) -> Option<String> {
    // Order matters only in that each needle is distinctive; substrings are safe.
    const MAP: &[(&str, &str)] = &[
        ("x86_64", "x86_64"),
        ("amd64", "x86_64"),
        ("aarch64", "aarch64"),
        ("arm64", "aarch64"),
        ("ppc64le", "ppc64le"),
        ("s390x", "s390x"),
        ("riscv64", "riscv64"),
        ("armv7l", "armv7l"),
        ("i686", "i686"),
    ];
    MAP.iter()
        .find(|(needle, _)| kernel.contains(needle))
        .map(|(_, canon)| (*canon).to_string())
}

fn read_machine_arch(cpuinfo: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(cpuinfo).ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("machine\t: ")
            .map(str::trim)
            .map(str::to_string)
    })
}

/// MAC addresses from `sys/class/net/*/address` under the scan root (skips
/// loopback and the all-zero placeholder). Deterministically ordered.
fn read_mac_addrs(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Ok(entries) = std::fs::read_dir(root.join("sys/class/net")) else {
        return out;
    };
    for entry in entries.flatten() {
        if entry.file_name() == "lo" {
            continue;
        }
        if let Some(mac) = read_trim_at(&entry.path(), "address") {
            if mac != "00:00:00:00:00:00" && !out.contains(&mac) {
                out.push(mac);
            }
        }
    }
    out.sort();
    out
}

/// Non-loopback/link-local IP addresses. Runtime state, so only collected when
/// scanning the live root (`/`); a mounted image has no on-disk source and
/// querying the scanner's own interfaces would be wrong.
fn read_ip_addrs(root: &Path) -> Vec<String> {
    if !is_live_root(root) {
        return Vec::new();
    }
    live_ip_addrs()
}

#[cfg(target_os = "linux")]
fn live_ip_addrs() -> Vec<String> {
    use std::net::{IpAddr, SocketAddrV4, SocketAddrV6};

    let Ok(addrs) = nix::ifaddrs::getifaddrs() else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for ifaddr in addrs {
        let Some(storage) = ifaddr.address else {
            continue;
        };
        let ip: Option<IpAddr> = if let Some(sin) = storage.as_sockaddr_in() {
            Some(IpAddr::V4(*SocketAddrV4::from(*sin).ip()))
        } else {
            storage
                .as_sockaddr_in6()
                .map(|sin6| IpAddr::V6(*SocketAddrV6::from(*sin6).ip()))
        };
        if let Some(ip) = ip {
            if !is_uninteresting_ip(&ip) {
                let text = ip.to_string();
                if !out.contains(&text) {
                    out.push(text);
                }
            }
        }
    }
    out
}

#[cfg(not(target_os = "linux"))]
fn live_ip_addrs() -> Vec<String> {
    Vec::new()
}

/// Drop loopback, link-local, and unspecified addresses — never useful as a
/// host's identity/reachability.
// Only the Linux `live_ip_addrs` calls this (other targets return no live IPs);
// it is still exercised by the cross-platform unit tests, so allow dead_code in
// the non-Linux lib build rather than gate it away from the tests.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn is_uninteresting_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        // fe80::/10 is IPv6 link-local (is_unicast_link_local is still unstable).
        std::net::IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn parse_kv(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    let rest = line.strip_prefix(&prefix)?;
    Some(rest.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_from_kernel_x86_64_almalinux() {
        let k = "Linux version 6.12.0-124.8.1.el10_1.x86_64 (mockbuild@x64) (gcc ...) #1 SMP";
        assert_eq!(arch_from_kernel(k).as_deref(), Some("x86_64"));
    }

    #[test]
    fn arch_from_kernel_debian_amd64_and_arm64() {
        assert_eq!(
            arch_from_kernel("Linux version 6.1.0-13-amd64").as_deref(),
            Some("x86_64")
        );
        assert_eq!(
            arch_from_kernel("Linux version 6.5.0-1008-arm64").as_deref(),
            Some("aarch64")
        );
        assert_eq!(
            arch_from_kernel("Linux version 6.12.0-124.aarch64").as_deref(),
            Some("aarch64")
        );
    }

    #[test]
    fn arch_from_kernel_unknown_is_none() {
        assert_eq!(arch_from_kernel("Linux version 1.0 (nobody)"), None);
    }

    #[test]
    fn uninteresting_ips_are_filtered() {
        use std::net::IpAddr;
        for s in ["127.0.0.1", "169.254.1.2", "0.0.0.0", "::1", "fe80::1"] {
            assert!(
                is_uninteresting_ip(&s.parse::<IpAddr>().unwrap()),
                "{s} should be filtered"
            );
        }
        for s in ["203.0.113.10", "172.17.0.1", "192.168.1.5"] {
            assert!(
                !is_uninteresting_ip(&s.parse::<IpAddr>().unwrap()),
                "{s} should be kept"
            );
        }
    }
}
