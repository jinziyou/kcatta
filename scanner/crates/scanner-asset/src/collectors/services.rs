//! Installed systemd / SysV services from static files under the scan root.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use scanner_contract::{Asset, Service};
use scanner_runtime::{Collector, CollectorOutput, ScanContext};

use crate::root::join_root;

pub struct ServicesCollector;

impl Collector for ServicesCollector {
    fn id(&self) -> &'static str {
        "services"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        require_host_id(ctx)?;
        Ok(CollectorOutput::Assets(collect(ctx)))
    }
}

fn require_host_id(ctx: &ScanContext) -> anyhow::Result<()> {
    if ctx.host_id.is_none() {
        anyhow::bail!("host collector must run before services");
    }
    Ok(())
}

const SYSTEMD_DIRS: &[&str] = &[
    "etc/systemd/system",
    "usr/lib/systemd/system",
    "lib/systemd/system",
];

/// Installed services as contract [`Asset`]s.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let enabled = enabled_systemd_units(ctx);
    let mut by_name: HashMap<String, (PathBuf, bool)> = HashMap::new();

    for dir in SYSTEMD_DIRS {
        let path = join_root(ctx, dir);
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            let file = entry.path();
            let Some(name) = file
                .file_name()
                .and_then(|s| s.to_str())
                .and_then(|s| s.strip_suffix(".service"))
            else {
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

    let mut out: Vec<Asset> = by_name
        .into_iter()
        .filter_map(|(name, (path, _))| {
            let text = fs::read_to_string(&path).ok()?;
            let exec_path = parse_exec_start(&text);
            let status = if enabled.contains(&name) {
                "enabled".to_string()
            } else if has_install_section(&text) {
                "disabled".to_string()
            } else {
                "static".to_string()
            };
            Some(Asset::Service(Service {
                asset_id: format!("svc-{name}"),
                name,
                status,
                exec_path,
            }))
        })
        .collect();

    out.extend(collect_sysv(ctx));
    out.sort_by(|a, b| service_name(a).cmp(service_name(b)));
    out
}

fn service_name(asset: &Asset) -> &str {
    match asset {
        Asset::Service(s) => &s.name,
        _ => "",
    }
}

fn collect_sysv(ctx: &ScanContext) -> Vec<Asset> {
    let dir = join_root(ctx, "etc/init.d");
    let Ok(entries) = fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_file() {
                return None;
            }
            let name = path.file_name()?.to_str()?.to_string();
            if name.starts_with('.') || name.ends_with(".bak") {
                return None;
            }
            Some(Asset::Service(Service {
                asset_id: format!("svc-{name}"),
                name,
                status: "installed".to_string(),
                exec_path: Some(path.strip_prefix(&ctx.scan_root).unwrap_or(&path).display().to_string()),
            }))
        })
        .collect()
}

fn enabled_systemd_units(ctx: &ScanContext) -> HashSet<String> {
    let wants_root = join_root(ctx, "etc/systemd/system");
    let mut enabled = HashSet::new();
    let Ok(entries) = fs::read_dir(&wants_root) else {
        return enabled;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(dir_name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if !dir_name.ends_with(".wants") {
            continue;
        }
        let Ok(links) = fs::read_dir(&path) else {
            continue;
        };
        for link in links.flatten() {
            let file_name = link.file_name();
            let Some(name) = file_name.to_str().and_then(|s| s.strip_suffix(".service")) else {
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
    use scanner_runtime::ScanContext;

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
}
