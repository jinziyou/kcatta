//! Container instances and runtime metadata from static files under the scan root.

mod containerd;

use std::fs;
use std::path::{Path, PathBuf};

use agent_contract::{Asset, Container};
use crate::{Collector, CollectorOutput, ScanContext};
use serde::Deserialize;

use crate::root::{join_root, resolve_under_root};

/// Collects container instances from Docker, Podman, and Kubernetes static metadata.
pub struct ContainersCollector;

impl Collector for ContainersCollector {
    fn id(&self) -> &'static str {
        "containers"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "containers")?;
        Ok(CollectorOutput::Assets(collect(ctx)))
    }
}

/// Container assets from static runtime metadata on disk.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let mut out = Vec::new();
    out.extend(collect_docker(ctx));
    out.extend(collect_podman(ctx));
    let containerd_assets = containerd::collect(ctx);
    let static_pods = filter_superseded_static_pods(&containerd_assets, collect_kubernetes_static_pods(ctx));
    out.extend(containerd_assets);
    out.extend(static_pods);
    out.sort_by(|a, b| container_name(a).cmp(container_name(b)));
    out
}

/// Drop static-pod manifest rows when a CRI container with rootfs covers the same pod name.
fn filter_superseded_static_pods(containerd_assets: &[Asset], static_pods: Vec<Asset>) -> Vec<Asset> {
    let mut live_pod_names = std::collections::HashSet::new();
    for asset in containerd_assets {
        let Asset::Container(c) = asset else {
            continue;
        };
        if c.rootfs_path.is_some() && c.runtime == "kubernetes" {
            live_pod_names.insert(c.name.clone());
        }
    }
    static_pods
        .into_iter()
        .filter(|asset| {
            let Asset::Container(c) = asset else {
                return true;
            };
            !live_pod_names.contains(&c.name)
        })
        .collect()
}

/// Containers with a resolvable merged rootfs directory under `scan_root`.
pub fn scannable_rootfs(
    ctx: &ScanContext,
    include_stopped: bool,
) -> impl Iterator<Item = (Container, PathBuf)> + '_ {
    collect(ctx).into_iter().filter_map(move |asset| {
        let Asset::Container(container) = asset else {
            return None;
        };
        if !include_stopped && container_is_stopped(&container) {
            return None;
        }
        let rel = container.rootfs_path.as_ref()?;
        let abs = resolve_under_root(&ctx.scan_root, rel);
        if !abs.is_dir() {
            return None;
        }
        Some((container, abs))
    })
}

#[allow(dead_code)]
fn container_is_stopped(container: &Container) -> bool {
    match container.status.as_deref() {
        None | Some("running") | Some("static_pod") => false,
        Some(status) => {
            let lower = status.to_ascii_lowercase();
            !(lower == "paused" || lower == "restarting")
        }
    }
}

pub(super) fn rootfs_rel(ctx: &ScanContext, path: &str) -> Option<String> {
    let abs = resolve_under_root(&ctx.scan_root, path);
    if !abs.is_dir() {
        return None;
    }
    Some(rel_path(ctx, &abs))
}

fn container_name(asset: &Asset) -> &str {
    match asset {
        Asset::Container(c) => &c.name,
        _ => "",
    }
}

pub(super) fn rel_path(ctx: &ScanContext, path: &Path) -> String {
    path.strip_prefix(&ctx.scan_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn collect_docker(ctx: &ScanContext) -> Vec<Asset> {
    let data_root = docker_data_root(ctx);
    let containers_dir = join_root(ctx, &format!("{data_root}/containers"));
    let Ok(entries) = fs::read_dir(&containers_dir) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            if !dir.is_dir() {
                return None;
            }
            let config_path = dir.join("config.v2.json");
            if !config_path.is_file() {
                return None;
            }
            let text = fs::read_to_string(&config_path).ok()?;
            let meta: DockerConfigV2 = serde_json::from_str(&text).ok()?;
            let container_id = meta
                .id
                .or_else(|| {
                    dir.file_name()
                        .and_then(|s| s.to_str())
                        .map(str::to_string)
                })
                .filter(|id| !id.is_empty());
            let name = normalize_container_name(meta.name.as_deref(), container_id.as_deref())?;
            let asset_id = format!(
                "ctr-docker-{}",
                container_id.as_deref().unwrap_or(&name)
            );
            Some(Asset::Container(Container {
                asset_id,
                parent_asset_id: None,
                name,
                runtime: "docker".to_string(),
                image: meta.config.and_then(|c| c.image),
                status: meta.state.map(|s| s.status).filter(|s| !s.is_empty()),
                container_id,
                config_path: Some(rel_path(ctx, &config_path)),
                rootfs_path: meta
                    .graph_driver
                    .and_then(|g| g.data)
                    .and_then(|d| d.merged_dir)
                    .and_then(|p| rootfs_rel(ctx, &p)),
            }))
        })
        .collect()
}

fn docker_data_root(ctx: &ScanContext) -> String {
    let daemon_json = join_root(ctx, "etc/docker/daemon.json");
    let Ok(text) = fs::read_to_string(&daemon_json) else {
        return "var/lib/docker".to_string();
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        return "var/lib/docker".to_string();
    };
    value
        .get("data-root")
        .and_then(|v| v.as_str())
        .map(|s| s.trim_start_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "var/lib/docker".to_string())
}

#[derive(Debug, Deserialize)]
struct DockerConfigV2 {
    #[serde(rename = "ID")]
    id: Option<String>,
    #[serde(rename = "Name")]
    name: Option<String>,
    #[serde(rename = "State")]
    state: Option<DockerState>,
    #[serde(rename = "Config")]
    config: Option<DockerConfig>,
    #[serde(rename = "GraphDriver")]
    graph_driver: Option<DockerGraphDriver>,
}

#[derive(Debug, Deserialize)]
struct DockerGraphDriver {
    #[serde(rename = "Data")]
    data: Option<DockerGraphDriverData>,
}

#[derive(Debug, Deserialize)]
struct DockerGraphDriverData {
    #[serde(rename = "MergedDir")]
    merged_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DockerState {
    #[serde(rename = "Status")]
    status: String,
}

#[derive(Debug, Deserialize)]
struct DockerConfig {
    #[serde(rename = "Image")]
    image: Option<String>,
}

fn collect_podman(ctx: &ScanContext) -> Vec<Asset> {
    let base = join_root(ctx, "var/lib/containers/storage/overlay-containers");
    let Ok(entries) = fs::read_dir(&base) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter_map(|entry| {
            let dir = entry.path();
            if !dir.is_dir() {
                return None;
            }
            let container_id = dir.file_name()?.to_str()?.to_string();
            let config_path = dir.join("userdata/config");
            if !config_path.is_file() {
                return None;
            }
            let text = fs::read_to_string(&config_path).ok()?;
            let meta: PodmanUserConfig = serde_json::from_str(&text).ok()?;
            let name = normalize_container_name(meta.name.as_deref(), Some(&container_id))?;
            let rootfs_path = meta
                .rootfs
                .as_deref()
                .and_then(|p| rootfs_rel(ctx, p))
                .or_else(|| podman_overlay_merged(ctx, &container_id));
            Some(Asset::Container(Container {
                asset_id: format!("ctr-podman-{container_id}"),
                parent_asset_id: None,
                name,
                runtime: "podman".to_string(),
                image: meta
                    .rootfs_image
                    .or(meta.image)
                    .or(meta.image_name)
                    .filter(|s| !s.is_empty()),
                status: meta.state.filter(|s| !s.is_empty()),
                container_id: Some(container_id),
                config_path: Some(rel_path(ctx, &config_path)),
                rootfs_path,
            }))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct PodmanUserConfig {
    name: Option<String>,
    state: Option<String>,
    image: Option<String>,
    image_name: Option<String>,
    rootfs_image: Option<String>,
    rootfs: Option<String>,
}

fn podman_overlay_merged(ctx: &ScanContext, container_id: &str) -> Option<String> {
    let link = join_root(
        ctx,
        &format!(
            "var/lib/containers/storage/overlay-containers/{container_id}/userdata/merged"
        ),
    );
    if link.is_dir() {
        return Some(rel_path(ctx, &link));
    }
    None
}

fn collect_kubernetes_static_pods(ctx: &ScanContext) -> Vec<Asset> {
    let dir = join_root(ctx, "etc/kubernetes/manifests");
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
            let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
            if ext != "yaml" && ext != "yml" {
                return None;
            }
            let text = fs::read_to_string(&path).ok()?;
            let (name, image) = parse_k8s_pod_manifest(&text)?;
            let rel = rel_path(ctx, &path);
            Some(Asset::Container(Container {
                asset_id: format!("ctr-k8s-{name}"),
                parent_asset_id: None,
                name,
                runtime: "kubernetes".to_string(),
                image,
                status: Some("static_pod".to_string()),
                container_id: None,
                config_path: Some(rel),
                rootfs_path: None,
            }))
        })
        .collect()
}

pub(super) fn normalize_container_name(name: Option<&str>, container_id: Option<&str>) -> Option<String> {
    if let Some(raw) = name.filter(|s| !s.is_empty()) {
        return Some(raw.trim_start_matches('/').to_string());
    }
    container_id.map(|id| id.chars().take(12).collect())
}

/// Minimal YAML scan for `metadata.name` and the first container `image`.
fn parse_k8s_pod_manifest(text: &str) -> Option<(String, Option<String>)> {
    let mut in_metadata = false;
    let mut in_containers = false;
    let mut name = None;
    let mut image = None;

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        if trimmed.ends_with(':') && !trimmed.contains(": ") {
            let section = trimmed.trim_end_matches(':');
            in_metadata = section == "metadata";
            in_containers = section == "containers";
            continue;
        }
        if in_metadata {
            if let Some(v) = parse_yaml_kv(trimmed, "name") {
                name = Some(v);
                in_metadata = false;
            }
            continue;
        }
        if in_containers && image.is_none() {
            if let Some(v) = parse_yaml_kv(trimmed, "image") {
                image = Some(v);
            }
        }
    }

    name.map(|n| (n, image))
}

fn parse_yaml_kv(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    let rest = line.strip_prefix(&prefix)?.trim();
    Some(rest.trim_matches('"').trim_matches('\'').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanContext;
    use std::fs;

    #[test]
    fn collects_docker_container_from_config_v2() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let id = "abc123def4567890abc123def4567890abc123def4567890abc123def4567890";
        let dir = root.join(format!("var/lib/docker/containers/{id}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("config.v2.json"),
            r#"{
                "ID": "abc123def4567890abc123def4567890abc123def4567890abc123def4567890",
                "Name": "/web",
                "State": { "Status": "running" },
                "Config": { "Image": "nginx:1.25" },
                "GraphDriver": {
                    "Data": {
                        "MergedDir": "/var/lib/docker/overlay2/abc123def4567890abc123def4567890abc123def4567890abc123def4567890/merged"
                    }
                }
            }"#,
        )
        .unwrap();
        fs::create_dir_all(
            root.join("var/lib/docker/overlay2/abc123def4567890abc123def4567890abc123def4567890abc123def4567890/merged"),
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Container(c) => {
                assert_eq!(c.name, "web");
                assert_eq!(c.runtime, "docker");
                assert_eq!(c.image.as_deref(), Some("nginx:1.25"));
                assert_eq!(c.status.as_deref(), Some("running"));
                assert!(c.rootfs_path.is_some());
            }
            other => panic!("expected container, got {other:?}"),
        }
    }

    #[test]
    fn collects_kubernetes_static_pod_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc/kubernetes/manifests")).unwrap();
        fs::write(
            root.join("etc/kubernetes/manifests/kube-apiserver.yaml"),
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: kube-apiserver\nspec:\n  containers:\n  - name: kube-apiserver\n    image: registry.k8s.io/kube-apiserver:v1.29.0\n",
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Container(c) => {
                assert_eq!(c.name, "kube-apiserver");
                assert_eq!(c.runtime, "kubernetes");
                assert_eq!(
                    c.image.as_deref(),
                    Some("registry.k8s.io/kube-apiserver:v1.29.0")
                );
                assert_eq!(c.status.as_deref(), Some("static_pod"));
            }
            other => panic!("expected container, got {other:?}"),
        }
    }

    #[test]
    fn prefers_cri_container_over_static_pod_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let id = "c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6";

        fs::create_dir_all(root.join("etc/kubernetes/manifests")).unwrap();
        fs::write(
            root.join("etc/kubernetes/manifests/kube-apiserver.yaml"),
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: kube-apiserver\nspec:\n  containers:\n  - name: kube-apiserver\n    image: registry.k8s.io/kube-apiserver:v1.29.0\n",
        )
        .unwrap();

        let fs_dir = root.join(format!(
            "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/42/fs"
        ));
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
                "image": {{ "image": "registry.k8s.io/kube-apiserver:v1.29.0" }},
                "labels": {{
                    "io.kubernetes.pod.name": "kube-apiserver",
                    "io.kubernetes.container.name": "kube-apiserver"
                }},
                "info": {{ "snapshotKey": "k8s.io/{id}" }}
            }}"#
            ),
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Container(c) => {
                assert_eq!(c.name, "kube-apiserver");
                assert_eq!(c.runtime, "kubernetes");
                assert!(c.rootfs_path.is_some());
            }
            other => panic!("expected container, got {other:?}"),
        }
    }

    #[test]
    fn respects_custom_docker_data_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc/docker")).unwrap();
        fs::write(
            root.join("etc/docker/daemon.json"),
            r#"{ "data-root": "/srv/docker" }"#,
        )
        .unwrap();
        let id = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let dir = root.join(format!("srv/docker/containers/{id}"));
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("config.v2.json"),
            r#"{
                "Name": "/custom",
                "State": { "Status": "exited" },
                "Config": { "Image": "alpine:latest" }
            }"#,
        )
        .unwrap();

        let ctx = ScanContext::at(root);
        let assets = collect(&ctx);
        assert_eq!(assets.len(), 1);
        match &assets[0] {
            Asset::Container(c) => assert_eq!(c.name, "custom"),
            other => panic!("expected container, got {other:?}"),
        }
    }
}
