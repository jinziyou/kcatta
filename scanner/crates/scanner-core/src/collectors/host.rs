//! Best-effort host descriptor collector.
//!
//! Reads what is cheap and portable on Linux:
//!   * `/etc/hostname`         -> hostname
//!   * `/etc/os-release`       -> os (PRETTY_NAME)
//!   * `std::env::consts::ARCH` -> arch
//!
//! Anything missing falls back to a stable placeholder rather than
//! failing the whole scan, so the rest of the report can still be
//! delivered.

use std::fs;

use uuid::Uuid;

use crate::contract::HostInfo;

const HOSTNAME_FILE: &str = "/etc/hostname";
const OS_RELEASE_FILE: &str = "/etc/os-release";

pub fn collect() -> anyhow::Result<HostInfo> {
    let hostname = read_trim(HOSTNAME_FILE).unwrap_or_else(|| "unknown-host".to_string());
    let os = read_os_release(OS_RELEASE_FILE).unwrap_or_else(|| "unknown".to_string());

    Ok(HostInfo {
        host_id: format!("host-{}", Uuid::new_v4()),
        hostname,
        os,
        kernel: None,
        arch: Some(std::env::consts::ARCH.to_string()),
        ip_addrs: Vec::new(),
        mac_addrs: Vec::new(),
        boot_time: None,
    })
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parse `/etc/os-release`, preferring `PRETTY_NAME`.
fn read_os_release(path: &str) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
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

fn parse_kv(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    let rest = line.strip_prefix(&prefix)?;
    Some(rest.trim_matches('"').to_string())
}
