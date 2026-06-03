//! Windows host descriptor from registry hives or live HKLM.

use probe_contract::HostInfo;
use probe_runtime::ScanContext;

use super::boot;
use super::distro::WindowsDistro;
use super::network;
use super::registry::{control_set_prefix, HiveKind, RegistryAccess};

/// Collect [`HostInfo`] for a Windows scan root.
pub fn collect_host(ctx: &ScanContext) -> anyhow::Result<HostInfo> {
    let reg = RegistryAccess::open(ctx);
    let distro = WindowsDistro::read(&reg);
    let cs = control_set_prefix(&reg);
    let net = network::collect_network(&reg);

    let hostname = reg
        .get_string(
            HiveKind::System,
            &format!("{cs}\\Control\\ComputerName"),
            "ComputerName",
        )
        .or_else(|| {
            reg.get_string(
                HiveKind::System,
                &format!("{cs}\\Control\\ComputerName"),
                "ActiveComputerName",
            )
        })
        .unwrap_or_else(|| "unknown-host".to_string());

    let arch = reg
        .get_string(
            HiveKind::System,
            &format!("{cs}\\Control\\Session Manager\\Environment"),
            "PROCESSOR_ARCHITECTURE",
        )
        .or_else(|| {
            reg.get_string(
                HiveKind::Software,
                r"Microsoft\Windows NT\CurrentVersion",
                "BuildLabEx",
            )
        });

    Ok(HostInfo {
        host_id: stable_host_id(&hostname, &ctx.scan_root),
        hostname,
        os: distro.pretty_os(),
        kernel: distro.kernel_string(),
        arch,
        ip_addrs: net.ip_addrs,
        mac_addrs: net.mac_addrs,
        boot_time: boot::boot_time(ctx),
    })
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
    let root_tag = root
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("root");
    format!("host-{safe}-{root_tag}")
}
