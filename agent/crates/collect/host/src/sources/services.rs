//! Linux services from fixed systemd and SysV paths.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::PathBuf;

use crate::ScanContext;
use agent_contract::{Asset, Service};

use crate::root::join_root;

const SYSTEMD_DIRS: &[&str] = &[
    "etc/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
];

/// Installed services as contract [`Asset`]s.
#[allow(dead_code)] // Compatibility wrapper for existing collector callers.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    collect_with_coverage(ctx).0
}

/// Same-pass diagnostics for service inventory sources.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ServiceCoverage {
    source_incomplete: bool,
}

impl ServiceCoverage {
    pub(crate) fn source_incomplete(self) -> bool {
        self.source_incomplete
    }

    pub(crate) fn incomplete() -> Self {
        Self {
            source_incomplete: true,
        }
    }
}

/// Installed services plus source diagnostics from the same pass.
pub(crate) fn collect_with_coverage(ctx: &ScanContext) -> (Vec<Asset>, ServiceCoverage) {
    let mut coverage = ServiceCoverage::default();
    let enabled = enabled_systemd_units(ctx, &mut coverage);
    let mut by_name: HashMap<String, (PathBuf, bool)> = HashMap::new();

    for dir in SYSTEMD_DIRS {
        let path = join_root(ctx, dir);
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => {
                coverage.source_incomplete = true;
                continue;
            }
        };
        for item in entries {
            let entry = match item {
                Ok(entry) => entry,
                Err(_) => {
                    coverage.source_incomplete = true;
                    continue;
                }
            };
            let file = entry.path();
            let metadata = match fs::metadata(&file) {
                Ok(metadata) => metadata,
                Err(_) => {
                    coverage.source_incomplete = true;
                    continue;
                }
            };
            if !metadata.is_file() {
                continue;
            }
            let Some(name) = file
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_suffix(".service"))
            else {
                if file
                    .extension()
                    .is_some_and(|extension| extension == "service")
                {
                    coverage.source_incomplete = true;
                }
                continue;
            };
            let from_etc = dir.starts_with("etc/");
            match by_name.get_mut(name) {
                Some((_, is_etc)) if *is_etc => {}
                Some((path, is_etc)) if from_etc => {
                    *path = file;
                    *is_etc = true;
                }
                Some(_) => {}
                None => {
                    by_name.insert(name.to_string(), (file, from_etc));
                }
            }
        }
    }

    let mut out = Vec::new();
    for (name, (path, _)) in by_name {
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(_) => {
                coverage.source_incomplete = true;
                continue;
            }
        };
        if !valid_systemd_service(&text) {
            coverage.source_incomplete = true;
        }
        let exec_path = parse_exec_start(&text);
        let status = if enabled.contains(&name) {
            "enabled".to_string()
        } else if has_install_section(&text) {
            "disabled".to_string()
        } else {
            "static".to_string()
        };
        out.push(Asset::Service(Service {
            asset_id: format!("svc-{name}"),
            parent_asset_id: None,
            name,
            status,
            exec_path,
        }));
    }

    out.extend(collect_sysv(ctx, &mut coverage));
    out.sort_by(|a, b| service_name(a).cmp(service_name(b)));
    (out, coverage)
}

fn service_name(asset: &Asset) -> &str {
    match asset {
        Asset::Service(s) => &s.name,
        _ => "",
    }
}

fn collect_sysv(ctx: &ScanContext, coverage: &mut ServiceCoverage) -> Vec<Asset> {
    let dir = join_root(ctx, "etc/init.d");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(_) => {
            coverage.source_incomplete = true;
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for item in entries {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                coverage.source_incomplete = true;
                continue;
            }
        };
        let path = entry.path();
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => continue,
            Err(_) => {
                coverage.source_incomplete = true;
                continue;
            }
        }
        let Some(name) = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(str::to_string)
        else {
            coverage.source_incomplete = true;
            continue;
        };
        if name.starts_with('.') || name.ends_with(".bak") {
            continue;
        }
        out.push(Asset::Service(Service {
            asset_id: format!("svc-{name}"),
            parent_asset_id: None,
            name,
            status: "installed".to_string(),
            exec_path: Some(
                path.strip_prefix(&ctx.scan_root)
                    .unwrap_or(&path)
                    .display()
                    .to_string(),
            ),
        }));
    }
    out
}

fn enabled_systemd_units(ctx: &ScanContext, coverage: &mut ServiceCoverage) -> HashSet<String> {
    let wants_root = join_root(ctx, "etc/systemd/system");
    let mut enabled = HashSet::new();
    let entries = match fs::read_dir(&wants_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return enabled,
        Err(_) => {
            coverage.source_incomplete = true;
            return enabled;
        }
    };
    for item in entries {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                coverage.source_incomplete = true;
                continue;
            }
        };
        let path = entry.path();
        match fs::metadata(&path) {
            Ok(metadata) if metadata.is_dir() => {}
            Ok(_) => continue,
            Err(_) => {
                coverage.source_incomplete = true;
                continue;
            }
        }
        let Some(dir_name) = path.file_name().and_then(|s| s.to_str()) else {
            coverage.source_incomplete = true;
            continue;
        };
        if !dir_name.ends_with(".wants") {
            continue;
        }
        let links = match fs::read_dir(&path) {
            Ok(links) => links,
            Err(_) => {
                coverage.source_incomplete = true;
                continue;
            }
        };
        for item in links {
            let link = match item {
                Ok(link) => link,
                Err(_) => {
                    coverage.source_incomplete = true;
                    continue;
                }
            };
            let file_name = link.file_name();
            let Some(name) = file_name.to_str().and_then(|s| s.strip_suffix(".service")) else {
                if file_name.to_str().is_none() {
                    coverage.source_incomplete = true;
                }
                continue;
            };
            enabled.insert(name.to_string());
        }
    }
    enabled
}

fn has_install_section(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim().eq_ignore_ascii_case("[Install]"))
}

fn valid_systemd_service(text: &str) -> bool {
    text.lines()
        .any(|line| line.trim().eq_ignore_ascii_case("[Service]"))
}

fn parse_exec_start(text: &str) -> Option<String> {
    let mut in_service = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_service = trimmed.eq_ignore_ascii_case("[Service]");
            continue;
        }
        if !in_service {
            continue;
        }
        let Some(rest) = trimmed.strip_prefix("ExecStart=") else {
            continue;
        };
        return Some(first_exec_token(rest));
    }
    None
}

fn first_exec_token(exec: &str) -> String {
    exec.split_whitespace()
        .next()
        .unwrap_or(exec)
        .trim_matches('"')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;

    #[test]
    fn parses_systemd_unit_and_enabled_state() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("usr/lib/systemd/system")).unwrap();
        fs::write(
            root.join("usr/lib/systemd/system/sshd.service"),
            "[Service]\nExecStart=/usr/sbin/sshd -D\n[Install]\nWantedBy=multi-user.target\n",
        )
        .unwrap();
        fs::create_dir_all(root.join("etc/systemd/system/multi-user.target.wants")).unwrap();
        std::os::unix::fs::symlink(
            root.join("usr/lib/systemd/system/sshd.service"),
            root.join("etc/systemd/system/multi-user.target.wants/sshd.service"),
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Service(s) => {
                assert_eq!(s.name, "sshd");
                assert_eq!(s.status, "enabled");
                assert_eq!(s.exec_path.as_deref(), Some("/usr/sbin/sshd"));
            }
            other => panic!("expected service, got {other:?}"),
        }
    }

    #[test]
    fn collects_sysv_init_scripts() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc/init.d")).unwrap();
        fs::write(root.join("etc/init.d/nginx"), "#!/bin/sh\n").unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Service(s) => {
                assert_eq!(s.name, "nginx");
                assert_eq!(s.status, "installed");
            }
            other => panic!("expected service, got {other:?}"),
        }
    }

    #[test]
    fn coverage_marks_unit_read_failures() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("usr/lib/systemd/system")).unwrap();
        fs::write(
            temp.path().join("usr/lib/systemd/system/bad.service"),
            "not a systemd unit\n",
        )
        .unwrap();
        let (assets, coverage) = collect_with_coverage(&ScanContext::at(temp.path()));
        assert_eq!(assets.len(), 1);
        assert!(coverage.source_incomplete());
    }
}
