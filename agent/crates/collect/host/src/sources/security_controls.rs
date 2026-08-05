//! Explicit host security-control coverage from process and configuration evidence.

use std::fs;
use std::io;

use agent_contract::{
    Asset, ProcessAsset, SecurityControl, SecurityControlStatus, SecurityControlType,
};

use crate::root::join_root;
use crate::ScanContext;

/// Same-pass diagnostics for filesystem evidence behind security controls.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SecurityControlCoverage {
    source_incomplete: bool,
}

impl SecurityControlCoverage {
    pub(crate) fn source_incomplete(self) -> bool {
        self.source_incomplete
    }
}

/// Emit one row for every required control family, including unavailable/unknown.
#[allow(dead_code)] // Compatibility wrapper for crate-local callers outside the scan runner.
pub fn collect(ctx: &ScanContext, processes: &[Asset]) -> Vec<Asset> {
    collect_with_coverage(ctx, processes).0
}

/// Emit control assets and filesystem-read diagnostics from the same pass.
pub(crate) fn collect_with_coverage(
    ctx: &ScanContext,
    processes: &[Asset],
) -> (Vec<Asset>, SecurityControlCoverage) {
    let mut coverage = SecurityControlCoverage::default();
    let names: Vec<String> = processes
        .iter()
        .filter_map(|asset| match asset {
            Asset::Process(ProcessAsset { name, .. }) => Some(name.to_ascii_lowercase()),
            _ => None,
        })
        .collect();
    let assets = vec![
        firewall(ctx, &names, &mut coverage),
        mac(ctx, &mut coverage),
        process_control(
            ctx,
            &names,
            SecurityControlType::Audit,
            "auditd",
            &["auditd"],
            &["etc/audit/auditd.conf"],
            &mut coverage,
        ),
        process_control(
            ctx,
            &names,
            SecurityControlType::TimeSync,
            "time synchronization",
            &["chronyd", "systemd-timesyncd", "ntpd"],
            &[
                "etc/chrony.conf",
                "etc/ntp.conf",
                "etc/systemd/timesyncd.conf",
            ],
            &mut coverage,
        ),
        process_control(
            ctx,
            &names,
            SecurityControlType::LogForwarding,
            "log forwarding",
            &["rsyslogd", "syslog-ng", "fluent-bit", "filebeat", "vector"],
            &[
                "etc/rsyslog.conf",
                "etc/rsyslog.d",
                "etc/filebeat",
                "etc/vector",
            ],
            &mut coverage,
        ),
    ]
    .into_iter()
    .map(Asset::SecurityControl)
    .collect();
    (assets, coverage)
}

fn firewall(
    ctx: &ScanContext,
    names: &[String],
    coverage: &mut SecurityControlCoverage,
) -> SecurityControl {
    let active = names.iter().any(|name| name == "firewalld");
    let firewalld = optional_path_exists(&join_root(ctx, "etc/firewalld"), coverage);
    let nftables = optional_path_exists(&join_root(ctx, "etc/nftables.conf"), coverage);
    let (name, status, details) = if active {
        (
            "firewalld",
            SecurityControlStatus::Active,
            Some("runtime process observed".to_string()),
        )
    } else if firewalld || nftables {
        (
            if firewalld { "firewalld" } else { "nftables" },
            SecurityControlStatus::Configured,
            Some("configuration present; runtime state unverified".to_string()),
        )
    } else {
        ("host firewall", SecurityControlStatus::Unavailable, None)
    };
    SecurityControl {
        asset_id: "security-control-firewall".to_string(),
        parent_asset_id: None,
        control: SecurityControlType::Firewall,
        name: name.to_string(),
        status,
        mode: None,
        details,
    }
}

fn mac(ctx: &ScanContext, coverage: &mut SecurityControlCoverage) -> SecurityControl {
    let enforce = read_optional_text(&join_root(ctx, "sys/fs/selinux/enforce"), coverage)
        .map(|value| value.trim().to_string());
    if enforce
        .as_deref()
        .is_some_and(|value| !matches!(value, "0" | "1"))
    {
        coverage.source_incomplete = true;
    }
    let config = read_optional_text(&join_root(ctx, "etc/selinux/config"), coverage);
    let configured_mode = config.as_deref().and_then(|text| {
        text.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "SELINUX").then(|| value.trim().to_string())
        })
    });
    if config.is_some() && configured_mode.is_none() {
        coverage.source_incomplete = true;
    }
    if configured_mode.as_deref().is_some_and(|mode| {
        !matches!(
            mode.to_ascii_lowercase().as_str(),
            "enforcing" | "permissive" | "disabled"
        )
    }) {
        coverage.source_incomplete = true;
    }
    let (status, mode) = match enforce.as_deref() {
        Some("1") => (SecurityControlStatus::Active, Some("enforcing".to_string())),
        Some("0") => (
            SecurityControlStatus::Active,
            Some("permissive".to_string()),
        ),
        _ if configured_mode.is_some() => (SecurityControlStatus::Configured, configured_mode),
        _ => (SecurityControlStatus::Unavailable, None),
    };
    SecurityControl {
        asset_id: "security-control-mac".to_string(),
        parent_asset_id: None,
        control: SecurityControlType::MandatoryAccessControl,
        name: "SELinux".to_string(),
        status,
        mode,
        details: None,
    }
}

fn process_control(
    ctx: &ScanContext,
    names: &[String],
    control: SecurityControlType,
    display: &str,
    process_names: &[&str],
    config_paths: &[&str],
    coverage: &mut SecurityControlCoverage,
) -> SecurityControl {
    let active_name = process_names
        .iter()
        .find(|candidate| names.iter().any(|name| name == **candidate));
    let configured = config_paths
        .iter()
        .any(|path| optional_path_exists(&join_root(ctx, path), coverage));
    let (status, details) = if active_name.is_some() {
        (
            SecurityControlStatus::Active,
            Some("runtime process observed".to_string()),
        )
    } else if configured {
        (
            SecurityControlStatus::Configured,
            Some("configuration present; runtime state unverified".to_string()),
        )
    } else {
        (SecurityControlStatus::Unavailable, None)
    };
    SecurityControl {
        asset_id: format!(
            "security-control-{}",
            match control {
                SecurityControlType::Firewall => "firewall",
                SecurityControlType::MandatoryAccessControl => "mac",
                SecurityControlType::Audit => "audit",
                SecurityControlType::TimeSync => "time-sync",
                SecurityControlType::LogForwarding => "log-forwarding",
            }
        ),
        parent_asset_id: None,
        control,
        name: active_name.copied().unwrap_or(display).to_string(),
        status,
        mode: None,
        details,
    }
}

fn optional_path_exists(path: &std::path::Path, coverage: &mut SecurityControlCoverage) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(_) => {
            coverage.source_incomplete = true;
            false
        }
    }
}

fn read_optional_text(
    path: &std::path::Path,
    coverage: &mut SecurityControlCoverage,
) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(_) => {
            coverage.source_incomplete = true;
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_active_configured_and_unavailable_distinctly() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc/audit")).unwrap();
        fs::write(root.join("etc/audit/auditd.conf"), "log_format = RAW\n").unwrap();
        fs::create_dir_all(root.join("sys/fs/selinux")).unwrap();
        fs::write(root.join("sys/fs/selinux/enforce"), "1\n").unwrap();
        let processes = vec![Asset::Process(ProcessAsset {
            asset_id: "process-1".to_string(),
            parent_asset_id: None,
            pid: 1,
            ppid: None,
            name: "chronyd".to_string(),
            exe_path: None,
            executable_sha256: None,
            uid: Some(0),
            username: Some("root".to_string()),
            command_line: None,
            command_line_redacted: false,
            systemd_unit: None,
            container_id: None,
            started_at: None,
        })];
        let rows = collect(&ScanContext::at(root), &processes);
        let controls: Vec<_> = rows
            .iter()
            .map(|asset| match asset {
                Asset::SecurityControl(value) => value,
                _ => panic!("expected control"),
            })
            .collect();
        assert!(controls.iter().any(|row| {
            row.control == SecurityControlType::MandatoryAccessControl
                && row.status == SecurityControlStatus::Active
        }));
        assert!(controls.iter().any(|row| {
            row.control == SecurityControlType::Audit
                && row.status == SecurityControlStatus::Configured
        }));
        assert!(controls.iter().any(|row| {
            row.control == SecurityControlType::TimeSync
                && row.status == SecurityControlStatus::Active
        }));
    }

    #[test]
    fn coverage_marks_control_source_read_and_metadata_failures() {
        let unreadable = tempfile::tempdir().unwrap();
        fs::create_dir_all(unreadable.path().join("etc/selinux")).unwrap();
        fs::write(unreadable.path().join("etc/selinux/config"), [0xff, 0xfe]).unwrap();
        let (rows, coverage) = collect_with_coverage(&ScanContext::at(unreadable.path()), &[]);
        assert_eq!(rows.len(), 5);
        assert!(coverage.source_incomplete());

        let blocked = tempfile::tempdir().unwrap();
        fs::write(blocked.path().join("etc"), b"not a directory").unwrap();
        let (_, coverage) = collect_with_coverage(&ScanContext::at(blocked.path()), &[]);
        assert!(coverage.source_incomplete());
    }
}
