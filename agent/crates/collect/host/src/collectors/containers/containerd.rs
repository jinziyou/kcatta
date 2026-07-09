//! containerd / CRI container metadata and overlay snapshot rootfs resolution.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::ScanContext;
use agent_contract::{Asset, Container};
use serde::Deserialize;

use super::{normalize_container_name, rel_path};
use crate::root::{join_root, resolve_under_root};

const CRI_CONTAINER_DIRS: &[&str] = &[
    "run/containerd/io.containerd.grpc.v1.cri/containers",
    "var/run/containerd/io.containerd.grpc.v1.cri/containers",
];

const OVERLAY_SNAPSHOT_ROOTS: &[&str] =
    &["var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"];

/// Containerd CRI containers with resolved overlay snapshot rootfs when available.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let snapshot_index = SnapshotIndex::build(ctx);
    let mut out = Vec::new();

    for cri_root in CRI_CONTAINER_DIRS {
        let base = join_root(ctx, cri_root);
        let Ok(entries) = fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            let dir = entry.path();
            if !dir.is_dir() {
                continue;
            }
            let Some(container_id) = dir.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let config_path = dir.join("config.json");
            if !config_path.is_file() {
                continue;
            }
            let Some(container) =
                parse_cri_container(ctx, container_id, &config_path, &snapshot_index)
            else {
                continue;
            };
            out.push(Asset::Container(container));
        }
    }

    out
}

fn parse_cri_container(
    ctx: &ScanContext,
    container_id: &str,
    config_path: &Path,
    snapshot_index: &SnapshotIndex,
) -> Option<Container> {
    let text = fs::read_to_string(config_path).ok()?;
    let meta: CreContainerConfig = serde_json::from_str(&text).ok()?;
    let status = read_cri_status(config_path).or_else(|| meta.cri_status());

    let pod_name = meta.label("io.kubernetes.pod.name");
    let k8s_container = meta.label("io.kubernetes.container.name");
    let name = normalize_container_name(
        k8s_container
            .as_deref()
            .or(meta.metadata.as_ref().and_then(|m| m.name.as_deref()))
            .or(pod_name.as_deref()),
        Some(container_id),
    )?;

    let image = meta
        .image
        .as_ref()
        .and_then(|i| i.image.clone())
        .filter(|s| !s.is_empty());

    let rootfs_path = meta
        .snapshot_key()
        .and_then(|key| snapshot_index.rootfs_for_key(ctx, &key))
        .or_else(|| snapshot_index.rootfs_for_container_id(ctx, container_id));

    Some(Container {
        asset_id: format!("ctr-containerd-{container_id}"),
        parent_asset_id: None,
        name,
        runtime: if pod_name.is_some() {
            "kubernetes".to_string()
        } else {
            "containerd".to_string()
        },
        image,
        status,
        container_id: Some(container_id.to_string()),
        config_path: Some(rel_path(ctx, config_path)),
        rootfs_path,
    })
}

fn read_cri_status(config_path: &Path) -> Option<String> {
    let status_path = config_path.with_file_name("status");
    let text = fs::read_to_string(status_path).ok()?;
    let status: CreContainerStatus = serde_json::from_str(&text).ok()?;
    status.normalized()
}

#[derive(Debug, Deserialize)]
struct CreContainerConfig {
    metadata: Option<CreMetadata>,
    image: Option<CreImage>,
    labels: Option<HashMap<String, String>>,
    annotations: Option<HashMap<String, String>>,
    info: Option<HashMap<String, serde_json::Value>>,
}

impl CreContainerConfig {
    fn label(&self, key: &str) -> Option<String> {
        self.labels
            .as_ref()
            .and_then(|m| m.get(key))
            .cloned()
            .filter(|s| !s.is_empty())
    }

    fn snapshot_key(&self) -> Option<String> {
        if let Some(info) = &self.info {
            if let Some(key) = info.get("snapshotKey").and_then(|v| v.as_str()) {
                return Some(key.to_string());
            }
        }
        self.annotations.as_ref().and_then(|m| {
            m.get("io.containerd.snapshotter/cri/snapshot-key")
                .or_else(|| m.get("containerd.io/snapshot-key"))
                .cloned()
        })
    }

    fn cri_status(&self) -> Option<String> {
        self.info
            .as_ref()
            .and_then(|m| m.get("state"))
            .and_then(|v| v.as_str())
            .map(normalize_cri_state)
    }
}

#[derive(Debug, Deserialize)]
struct CreMetadata {
    name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreImage {
    image: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreContainerStatus {
    status: Option<String>,
    state: Option<String>,
}

impl CreContainerStatus {
    fn normalized(&self) -> Option<String> {
        self.state
            .as_deref()
            .or(self.status.as_deref())
            .map(normalize_cri_state)
            .filter(|s| !s.is_empty())
    }
}

fn normalize_cri_state(raw: &str) -> String {
    raw.trim_start_matches("CONTAINER_")
        .trim_start_matches("STATE_")
        .to_ascii_lowercase()
}

struct SnapshotIndex {
    by_key: HashMap<String, String>,
    by_container_id: HashMap<String, String>,
}

impl SnapshotIndex {
    fn build(ctx: &ScanContext) -> Self {
        let mut by_key = HashMap::new();
        let mut by_container_id = HashMap::new();

        for root in OVERLAY_SNAPSHOT_ROOTS {
            let base = join_root(ctx, root);
            let Ok(entries) = fs::read_dir(&base) else {
                continue;
            };
            for entry in entries.flatten() {
                let dir = entry.path();
                if !dir.is_dir() {
                    continue;
                }
                let fs_dir = dir.join("fs");
                if !fs_dir.is_dir() {
                    continue;
                }
                let rel = rel_path(ctx, &fs_dir);
                if let Some(key) = read_snapshot_label(&dir, "containerd.io/snapshot/key") {
                    by_key.insert(key, rel.clone());
                }
                if let Some(labels) = read_snapshot_labels(&dir) {
                    for value in labels.values() {
                        if value.len() >= 12 && value.chars().all(|c| c.is_ascii_hexdigit()) {
                            by_container_id
                                .entry(value.to_string())
                                .or_insert_with(|| rel.clone());
                        }
                    }
                    for value in labels.values() {
                        if let Some(id) = value.strip_prefix("k8s.io/") {
                            by_container_id
                                .entry(id.to_string())
                                .or_insert_with(|| rel.clone());
                        }
                    }
                }
            }
        }

        Self {
            by_key,
            by_container_id,
        }
    }

    fn rootfs_for_key(&self, ctx: &ScanContext, key: &str) -> Option<String> {
        if let Some(rel) = self.by_key.get(key) {
            let abs = resolve_under_root(&ctx.scan_root, rel);
            if abs.is_dir() {
                return Some(rel.clone());
            }
        }
        // Some snapshot keys are path-like; try resolving directly under overlay root.
        for root in OVERLAY_SNAPSHOT_ROOTS {
            let candidate = join_root(ctx, root).join(key).join("fs");
            if candidate.is_dir() {
                return Some(rel_path(ctx, &candidate));
            }
        }
        None
    }

    fn rootfs_for_container_id(&self, ctx: &ScanContext, container_id: &str) -> Option<String> {
        if let Some(rel) = self.by_container_id.get(container_id) {
            let abs = resolve_under_root(&ctx.scan_root, rel);
            if abs.is_dir() {
                return Some(rel.clone());
            }
        }
        None
    }
}

fn read_snapshot_label(dir: &Path, key: &str) -> Option<String> {
    read_snapshot_labels(dir).and_then(|m| m.get(key).cloned())
}

fn read_snapshot_labels(dir: &Path) -> Option<HashMap<String, String>> {
    let path = dir.join("labels");
    if !path.is_file() {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let mut out = HashMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=')?;
        out.insert(key.to_string(), value.to_string());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;
    use std::fs;

    #[test]
    fn collects_cri_container_with_snapshot_rootfs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let id = "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6";

        let fs_dir =
            root.join("var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs");
        fs::create_dir_all(&fs_dir).unwrap();
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
                "metadata": {{ "name": "{id}" }},
                "image": {{ "image": "registry.k8s.io/pause:3.9" }},
                "labels": {{
                    "io.kubernetes.pod.name": "nginx-pod",
                    "io.kubernetes.container.name": "nginx"
                }},
                "info": {{ "snapshotKey": "k8s.io/{id}" }}
            }}"#
            ),
        )
        .unwrap();
        fs::write(
            cri_dir.join("status"),
            r#"{"status":"CONTAINER_RUNNING","state":"CONTAINER_RUNNING"}"#,
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Container(c) => {
                assert_eq!(c.name, "nginx");
                assert_eq!(c.runtime, "kubernetes");
                assert_eq!(c.status.as_deref(), Some("running"));
                assert!(c.rootfs_path.is_some());
            }
            other => panic!("expected container, got {other:?}"),
        }
    }

    #[test]
    fn maps_snapshot_labels_to_container_id() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let id = "abcabcabcabcabcabcabcabcabcabc";

        let fs_dir =
            root.join("var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/fs");
        fs::create_dir_all(&fs_dir).unwrap();
        fs::write(
            root.join(
                "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/labels",
            ),
            format!("containerd.io/gc.ref.snapshot.k8s.io={id}\n"),
        )
        .unwrap();

        let cri_dir = root.join(format!(
            "run/containerd/io.containerd.grpc.v1.cri/containers/{id}"
        ));
        fs::create_dir_all(&cri_dir).unwrap();
        fs::write(
            cri_dir.join("config.json"),
            r#"{
                "metadata": { "name": "demo" },
                "image": { "image": "alpine:latest" }
            }"#,
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Container(c) => {
                assert_eq!(c.runtime, "containerd");
                assert!(c.rootfs_path.is_some());
            }
            other => panic!("expected container, got {other:?}"),
        }
    }
}
