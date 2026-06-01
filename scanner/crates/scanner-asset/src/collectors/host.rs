//! Host descriptor from static files under the scan root.

use scanner_contract::HostInfo;
use scanner_runtime::{Collector, CollectorOutput, ScanContext};

use crate::root::{join_root, read_trim_at};

/// Collects [`HostInfo`] from `etc/hostname`, `etc/os-release`, and `proc/version`.
pub struct HostCollector;

impl Collector for HostCollector {
    fn id(&self) -> &'static str {
        "host"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        Ok(CollectorOutput::Host(collect_host(ctx)?))
    }
}

pub(crate) fn collect_host(ctx: &ScanContext) -> anyhow::Result<HostInfo> {
    let root = &ctx.scan_root;
    let hostname = read_trim_at(root, "etc/hostname").unwrap_or_else(|| "unknown-host".to_string());
    let os =
        read_os_release(&join_root(ctx, "etc/os-release")).unwrap_or_else(|| "unknown".to_string());
    let arch = read_os_release_key(&join_root(ctx, "etc/os-release"), "ARCHITECTURE")
        .or_else(|| read_machine_arch(&join_root(ctx, "proc/cpuinfo")));

    Ok(HostInfo {
        host_id: stable_host_id(&hostname, root),
        hostname,
        os,
        kernel: read_trim_at(root, "proc/version"),
        arch,
        ip_addrs: Vec::new(),
        mac_addrs: Vec::new(),
        boot_time: None,
    })
}

/// Reproducible id for the same mount + hostname.
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

fn read_machine_arch(cpuinfo: &std::path::Path) -> Option<String> {
    let text = std::fs::read_to_string(cpuinfo).ok()?;
    text.lines().find_map(|line| {
        line.strip_prefix("machine\t: ")
            .map(str::trim)
            .map(str::to_string)
    })
}

fn parse_kv(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    let rest = line.strip_prefix(&prefix)?;
    Some(rest.trim_matches('"').to_string())
}
