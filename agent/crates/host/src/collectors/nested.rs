//! Nested asset scan inside Docker/Podman merged container rootfs paths.

use std::path::PathBuf;

use agent_contract::Asset;
use crate::{Collector, CollectorOutput, ScanContext};

use crate::container_scan::ContainerScanOptions;

use super::{
    accounts, collect_packages, containers, credentials, services, stamp_nested_assets,
};

/// Scans merged rootfs directories discovered by [`super::containers`].
pub struct NestedAssetsCollector {
    /// Nested scan limits and category toggles.
    pub options: ContainerScanOptions,
}

impl NestedAssetsCollector {
    /// Build a nested collector with the given options (disabled by default).
    pub fn new(options: ContainerScanOptions) -> Self {
        Self { options }
    }
}

impl Collector for NestedAssetsCollector {
    fn id(&self) -> &'static str {
        "nested-container-assets"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "nested-container-assets")?;
        Ok(CollectorOutput::Assets(collect(ctx, &self.options)))
    }
}

/// Collect nested assets from scannable container rootfs paths.
pub fn collect(ctx: &ScanContext, options: &ContainerScanOptions) -> Vec<Asset> {
    if !options.enabled {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut seen_rootfs = std::collections::HashSet::new();

    for (container, rootfs) in
        containers::scannable_rootfs(ctx, options.include_stopped).take(options.max_containers)
    {
        let key = rootfs.display().to_string();
        if !seen_rootfs.insert(key) {
            continue;
        }
        out.extend(scan_rootfs(ctx, &container.asset_id, &rootfs, options));
    }

    out
}

fn scan_rootfs(
    host_ctx: &ScanContext,
    parent_asset_id: &str,
    rootfs: &PathBuf,
    options: &ContainerScanOptions,
) -> Vec<Asset> {
    if !rootfs.is_dir() {
        return Vec::new();
    }

    let mut sub = ScanContext::at(rootfs);
    sub.host_id = host_ctx.host_id.clone();
    sub.host = host_ctx.host.clone();

    let mut assets = Vec::new();

    if options.scan_packages {
        assets.extend(stamp_nested_assets(
            collect_packages(&mut sub, None),
            parent_asset_id,
        ));
    }
    if options.scan_services {
        assets.extend(stamp_nested_assets(services::collect(&sub), parent_asset_id));
    }
    if options.scan_accounts {
        assets.extend(stamp_nested_assets(accounts::collect(&sub), parent_asset_id));
    }
    if options.scan_credentials {
        assets.extend(stamp_nested_assets(
            credentials::collect(&sub),
            parent_asset_id,
        ));
    }

    assets
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;
    use std::fs;

    #[test]
    fn scans_packages_inside_docker_merged_rootfs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();

        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(root.join("etc/hostname"), "docker-host\n").unwrap();
        fs::write(
            root.join("etc/os-release"),
            "ID=ubuntu\nVERSION_ID=\"22.04\"\n",
        )
        .unwrap();

        let id = "abc123def4567890abc123def4567890abc123def4567890abc123def4567890";
        let merged = root.join(format!("var/lib/docker/overlay2/{id}/merged"));
        fs::create_dir_all(merged.join("var/lib/dpkg")).unwrap();
        fs::write(
            merged.join("var/lib/dpkg/status"),
            "Package: curl\nStatus: install ok installed\nArchitecture: amd64\nVersion: 7.81.0-1\n",
        )
        .unwrap();

        fs::create_dir_all(root.join(format!("var/lib/docker/containers/{id}"))).unwrap();
        fs::write(
            root.join(format!("var/lib/docker/containers/{id}/config.v2.json")),
            format!(
                r#"{{
                "ID": "{id}",
                "Name": "/web",
                "State": {{ "Status": "running" }},
                "Config": {{ "Image": "ubuntu:22.04" }},
                "GraphDriver": {{
                    "Data": {{
                        "MergedDir": "/var/lib/docker/overlay2/{id}/merged"
                    }}
                }}
            }}"#
            ),
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let opts = ContainerScanOptions::enabled();
        let assets = collect(&ctx, &opts);

        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "curl");
                assert_eq!(
                    p.parent_asset_id.as_deref(),
                    Some("ctr-docker-abc123def4567890abc123def4567890abc123def4567890abc123def4567890")
                );
            }
            other => panic!("expected package, got {other:?}"),
        }
    }

    #[test]
    fn scans_packages_inside_containerd_snapshot_rootfs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let id = "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6";

        let fs_dir = root.join(format!(
            "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs"
        ));
        fs::create_dir_all(fs_dir.join("var/lib/dpkg")).unwrap();
        fs::write(
            fs_dir.join("var/lib/dpkg/status"),
            "Package: nginx\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.24.0\n",
        )
        .unwrap();
        fs::write(
            root.join(
                "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/labels",
            ),
            format!("containerd.io/snapshot/key=k8s.io/{id}\n"),
        )
        .unwrap();

        let cri_dir = root.join(format!(
            "run/containerd/io.containerd.grpc.v1.cri/containers/{id}"
        ));
        fs::create_dir_all(&cri_dir).unwrap();
        fs::write(
            cri_dir.join("config.json"),
            format!(
                r#"{{
                "image": {{ "image": "nginx:1.24" }},
                "labels": {{
                    "io.kubernetes.pod.name": "web",
                    "io.kubernetes.container.name": "web"
                }},
                "info": {{ "snapshotKey": "k8s.io/{id}" }}
            }}"#
            ),
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let opts = ContainerScanOptions::enabled();
        let assets = collect(&ctx, &opts);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Package(p) => {
                assert_eq!(p.name, "nginx");
                assert_eq!(p.parent_asset_id.as_deref(), Some("ctr-containerd-c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"));
            }
            other => panic!("expected package, got {other:?}"),
        }
    }

    #[test]
    fn disabled_returns_empty() {
        let ctx = ScanContext::at("/");
        assert!(collect(&ctx, &ContainerScanOptions::default()).is_empty());
    }
}
