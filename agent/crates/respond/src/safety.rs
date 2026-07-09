//! Safety layer — the anti-self-DoS veto. The single most important subsystem
//! for an active-response daemon: it refuses actions that could damage the host.

use std::net::{IpAddr, Ipv6Addr};
// Ipv4Addr is only referenced by the Linux `default_gateways()` (/proc/net/route);
// gate it so non-Linux targets don't warn on an unused import.
#[cfg(target_os = "linux")]
use std::net::Ipv4Addr;
use std::path::Path;

use crate::config::ResponsePolicy;
use crate::decide::Action;

/// System path prefixes whose executables must never be quarantined, regardless
/// of the configured critical-path list (P0-3): removing a system binary/lib a
/// running process depends on can break the host.
const SYSTEM_PREFIXES: &[&str] = &["/bin", "/sbin", "/usr", "/lib", "/lib64", "/boot"];

/// Returns `Some(reason)` when `action` must NOT be applied.
///
/// `self_pid` is the guard's own PID, which (with PID 1) is never killable.
pub fn veto(action: &Action, policy: &ResponsePolicy, self_pid: u32) -> Option<String> {
    match action {
        Action::None => None,
        Action::Quarantine { path } => veto_file(path, policy),
        Action::BlockConnection { dst_ip } => veto_block(dst_ip, policy),
        Action::Kill { pid } => veto_kill(*pid, policy, self_pid),
    }
}

fn veto_file(path: &str, policy: &ResponsePolicy) -> Option<String> {
    let p = Path::new(path);
    for crit in &policy.critical_paths {
        if p == crit || p.starts_with(crit) {
            return Some(format!("under critical path {}", crit.display()));
        }
    }
    for allow in &policy.allowlist_paths {
        if p.starts_with(allow) {
            return Some(format!("under allowlisted path {}", allow.display()));
        }
    }
    if SYSTEM_PREFIXES.iter().any(|pre| p.starts_with(pre)) {
        return Some("under a system prefix (/bin,/usr,/lib,...)".to_string());
    }
    if is_mapped_by_running_process(path) {
        return Some("mmap'd by a running process".to_string());
    }
    None
}

/// Veto a connection block that would be self-harmful. Beyond loopback, this
/// refuses to drop traffic to the host's own infrastructure (default gateway,
/// configured DNS resolvers), to private/link-local ranges unless explicitly
/// allowed, and to any operator-listed never-block address (e.g. the analyzer).
/// Without these, a single IOC hit on a port-based rule could be steered into
/// cutting the host off from its network — turning active response into a
/// remotely-triggerable self-DoS.
fn veto_block(dst_ip: &str, policy: &ResponsePolicy) -> Option<String> {
    const NEVER_BLOCK_NAMES: &[&str] = &["0.0.0.0", "localhost"];
    if NEVER_BLOCK_NAMES.contains(&dst_ip) {
        return Some(format!("refusing to block loopback/unspecified {dst_ip}"));
    }
    if policy.never_block_ips.iter().any(|n| n == dst_ip) {
        return Some(format!("{dst_ip} is on the never-block list"));
    }
    let Ok(ip) = dst_ip.parse::<IpAddr>() else {
        // An unparseable target would produce a malformed/over-broad rule.
        return Some(format!("refusing to block unparseable target {dst_ip}"));
    };
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return Some(format!(
            "refusing to block loopback/unspecified/multicast {dst_ip}"
        ));
    }
    if !policy.allow_block_private && is_private_or_local(&ip) {
        return Some(format!(
            "refusing to block private/link-local address {dst_ip} (set allow_block_private to override)"
        ));
    }
    if is_infrastructure_endpoint(&ip) {
        return Some(format!(
            "refusing to block gateway/DNS infrastructure {dst_ip}"
        ));
    }
    None
}

/// RFC1918 / link-local (v4) and unique-local fc00::/7 / link-local fe80::/10 (v6).
fn is_private_or_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => is_unique_local_v6(v6) || is_link_local_v6(v6),
    }
}

/// fc00::/7 unique-local addresses (`Ipv6Addr::is_unique_local` is still unstable).
fn is_unique_local_v6(v6: &Ipv6Addr) -> bool {
    (v6.octets()[0] & 0xfe) == 0xfc
}

/// fe80::/10 link-local addresses (`is_unicast_link_local` is still unstable).
fn is_link_local_v6(v6: &Ipv6Addr) -> bool {
    (v6.segments()[0] & 0xffc0) == 0xfe80
}

fn veto_kill(pid: u32, policy: &ResponsePolicy, self_pid: u32) -> Option<String> {
    if pid == 1 {
        return Some("refusing to kill PID 1 (init)".to_string());
    }
    if pid == self_pid {
        return Some("refusing to kill the guard itself".to_string());
    }
    if policy.allowlist_pids.contains(&pid) {
        return Some(format!("PID {pid} is allowlisted"));
    }
    critical_process_veto(pid, self_pid, policy)
}

/// The built-in set of critical-service `comm` names the responder must never
/// kill. Operators extend it via [`ResponsePolicy::protected_processes`]; the
/// built-ins can only be added to, never removed, so a misconfiguration can never
/// un-protect `sshd` or the data tier.
#[cfg(target_os = "linux")]
const DEFAULT_PROTECTED: &[&str] = &[
    // Core system / init / login / IPC.
    "systemd",
    "init",
    "sshd",
    "dbus-daemon",
    "dbus-broker",
    "agetty",
    "login",
    "NetworkManager",
    // Container / orchestration runtimes — killing these cascades to every workload.
    "containerd",
    "containerd-shim",
    "dockerd",
    "crio",
    "kubelet",
    // Databases — an `exe_deleted_running` false positive after a package upgrade
    // must never take the data tier down.
    "postgres",
    "postmaster",
    "mysqld",
    "mariadbd",
    "mongod",
    "redis-server",
    // Web / proxy front ends.
    "nginx",
    "httpd",
    "apache2",
    "haproxy",
    "envoy",
];

/// Whether `comm` names a process the responder must never kill: a built-in
/// critical service, a `systemd-*` helper, or an operator-configured extra name.
#[cfg(target_os = "linux")]
fn is_protected_process_name(comm: &str, extra: &[String]) -> bool {
    DEFAULT_PROTECTED.contains(&comm)
        || comm.starts_with("systemd-")
        || extra.iter().any(|name| name == comm)
}

/// Refuse to kill core system services, or any process that is an ancestor of the
/// guard itself. Without this, an `exe_deleted_running` false positive (e.g. a
/// long-running service whose binary was replaced by a package upgrade) could
/// SIGKILL `sshd`/`systemd`/a database and take the host down. The protected set
/// is the built-in critical list plus any [`ResponsePolicy::protected_processes`].
#[cfg(target_os = "linux")]
fn critical_process_veto(pid: u32, self_pid: u32, policy: &ResponsePolicy) -> Option<String> {
    if let Some(comm) = read_comm(pid) {
        if is_protected_process_name(&comm, &policy.protected_processes) {
            return Some(format!(
                "refusing to kill critical system process {comm} (pid {pid})"
            ));
        }
    }
    if is_ancestor_of(pid, self_pid) {
        return Some(format!(
            "refusing to kill pid {pid}: it is an ancestor of the guard"
        ));
    }
    None
}

#[cfg(not(target_os = "linux"))]
fn critical_process_veto(_pid: u32, _self_pid: u32, _policy: &ResponsePolicy) -> Option<String> {
    None
}

#[cfg(target_os = "linux")]
fn read_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(target_os = "linux")]
fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

/// Is `candidate` an ancestor of `pid` (bounded walk up the parent chain)?
#[cfg(target_os = "linux")]
fn is_ancestor_of(candidate: u32, mut pid: u32) -> bool {
    for _ in 0..64 {
        match read_ppid(pid) {
            Some(0) | None => return false,
            Some(ppid) if ppid == candidate => return true,
            Some(ppid) => pid = ppid,
        }
    }
    false
}

/// Default-route gateways from `/proc/net/route` (best-effort).
#[cfg(target_os = "linux")]
fn default_gateways() -> Vec<IpAddr> {
    let mut gws = Vec::new();
    let Ok(content) = std::fs::read_to_string("/proc/net/route") else {
        return gws;
    };
    for line in content.lines().skip(1) {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Default route has Destination == 00000000; field[2] is the gateway as
        // little-endian hex.
        if f.len() > 2 && f[1] == "00000000" {
            if let Ok(raw) = u32::from_str_radix(f[2], 16) {
                let ip = Ipv4Addr::from(raw.to_le_bytes());
                if !ip.is_unspecified() {
                    gws.push(IpAddr::V4(ip));
                }
            }
        }
    }
    gws
}

/// Resolver addresses from `/etc/resolv.conf` (best-effort).
#[cfg(target_os = "linux")]
fn resolver_addrs() -> Vec<IpAddr> {
    let mut out = Vec::new();
    let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") else {
        return out;
    };
    for line in content.lines() {
        if let Some(rest) = line.trim().strip_prefix("nameserver") {
            if let Ok(ip) = rest.trim().parse::<IpAddr>() {
                out.push(ip);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn is_infrastructure_endpoint(ip: &IpAddr) -> bool {
    default_gateways().contains(ip) || resolver_addrs().contains(ip)
}

#[cfg(not(target_os = "linux"))]
fn is_infrastructure_endpoint(_ip: &IpAddr) -> bool {
    false
}

/// Best-effort check: is `path` currently mapped into a running process?
///
/// Scans `/proc/<pid>/maps`. Any error (no permission, race) returns `false` —
/// the other vetoes (critical paths, system prefixes) still apply, and a guard
/// that cannot read `/proc` is almost certainly unprivileged enough that it
/// cannot quarantine anyway.
#[cfg(target_os = "linux")]
pub fn is_mapped_by_running_process(path: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let maps = entry.path().join("maps");
        let Ok(contents) = std::fs::read_to_string(&maps) else {
            continue;
        };
        // Each maps line ends with the mapped file path (when file-backed).
        if contents
            .lines()
            .any(|line| line.split_whitespace().last() == Some(path))
        {
            return true;
        }
    }
    false
}

/// Non-Linux fallback: cannot inspect process maps, so do not veto on this basis.
#[cfg(not(target_os = "linux"))]
pub fn is_mapped_by_running_process(_path: &str) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ResponsePolicy {
        ResponsePolicy::default()
    }

    #[test]
    fn vetoes_critical_and_system_paths() {
        assert!(veto_file("/etc/passwd", &policy()).is_some());
        assert!(veto_file("/usr/bin/curl", &policy()).is_some());
        assert!(veto_file("/boot/vmlinuz", &policy()).is_some());
    }

    #[test]
    fn vetoes_vault_allowlist() {
        assert!(veto_file("/var/lib/agent-respond/quarantine/x", &policy()).is_some());
    }

    #[test]
    fn allows_non_system_path() {
        // /opt is neither critical, allowlisted, nor a system prefix (and a
        // bogus path is not mmap'd by anything).
        assert!(veto_file("/opt/app/totally-not-real-xyz.bin", &policy()).is_none());
    }

    #[test]
    fn never_kills_init_or_self() {
        assert!(veto_kill(1, &policy(), 4242).is_some());
        assert!(veto_kill(4242, &policy(), 4242).is_some());
        assert!(veto_kill(9999, &policy(), 4242).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn protected_process_names_cover_builtin_systemd_and_config() {
        // Built-in critical set, incl. the databases / web servers added to stop
        // the post-upgrade self-DoS by default.
        for name in [
            "sshd",
            "systemd",
            "postgres",
            "redis-server",
            "nginx",
            "mysqld",
        ] {
            assert!(
                is_protected_process_name(name, &[]),
                "{name} must be protected"
            );
        }
        // systemd-* helpers match by prefix.
        assert!(is_protected_process_name("systemd-resolved", &[]));
        // Operator-configured extras are protected; the same name is NOT protected
        // without configuration.
        let extra = vec!["my-critical-app".to_string()];
        assert!(is_protected_process_name("my-critical-app", &extra));
        assert!(!is_protected_process_name("my-critical-app", &[]));
        assert!(!is_protected_process_name("python3", &[]));
    }

    #[test]
    fn never_blocks_loopback_or_unparseable() {
        assert!(veto_block("127.0.0.1", &policy()).is_some());
        assert!(veto_block("::1", &policy()).is_some());
        assert!(veto_block("localhost", &policy()).is_some());
        assert!(veto_block("not-an-ip", &policy()).is_some());
        // A genuine public address is allowed (TEST-NET-3 documentation range).
        assert!(veto_block("203.0.113.5", &policy()).is_none());
    }

    #[test]
    fn never_blocks_private_unless_opted_in() {
        assert!(veto_block("10.0.0.5", &policy()).is_some());
        assert!(veto_block("192.168.1.10", &policy()).is_some());
        assert!(veto_block("172.16.4.4", &policy()).is_some());
        assert!(veto_block("169.254.1.1", &policy()).is_some());
        assert!(veto_block("fd00::1", &policy()).is_some());

        let mut p = policy();
        p.allow_block_private = true;
        // With the opt-in, a private target is allowed (gateway/DNS still vetoed
        // separately at runtime).
        assert!(veto_block("203.0.113.5", &p).is_none());
        assert!(veto_block("10.0.0.5", &p).is_none());
    }

    #[test]
    fn honors_never_block_list() {
        let mut p = policy();
        p.never_block_ips = vec!["203.0.113.99".to_string()];
        assert!(veto_block("203.0.113.99", &p).is_some());
        assert!(veto_block("203.0.113.5", &p).is_none());
    }

    #[test]
    fn ipv6_range_classification() {
        use std::net::Ipv6Addr;
        assert!(is_unique_local_v6(&"fd00::1".parse::<Ipv6Addr>().unwrap()));
        assert!(is_unique_local_v6(&"fc00::1".parse::<Ipv6Addr>().unwrap()));
        assert!(is_link_local_v6(&"fe80::1".parse::<Ipv6Addr>().unwrap()));
        assert!(!is_unique_local_v6(
            &"2606:4700::1111".parse::<Ipv6Addr>().unwrap()
        ));
        assert!(!is_link_local_v6(
            &"2606:4700::1111".parse::<Ipv6Addr>().unwrap()
        ));
    }
}
