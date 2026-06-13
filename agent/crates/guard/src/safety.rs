//! Safety layer — the anti-self-DoS veto. The single most important subsystem
//! for an active-response daemon: it refuses actions that could damage the host.

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
        Action::BlockConnection { dst_ip } => veto_block(dst_ip),
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

fn veto_block(dst_ip: &str) -> Option<String> {
    const NEVER_BLOCK: &[&str] = &["127.0.0.1", "::1", "0.0.0.0", "localhost"];
    if NEVER_BLOCK.contains(&dst_ip) {
        return Some(format!("refusing to block loopback/unspecified {dst_ip}"));
    }
    None
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
    None
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
        assert!(veto_file("/var/lib/agent-guard/quarantine/x", &policy()).is_some());
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

    #[test]
    fn never_blocks_loopback() {
        assert!(veto_block("127.0.0.1").is_some());
        assert!(veto_block("::1").is_some());
        assert!(veto_block("203.0.113.5").is_none());
    }
}
