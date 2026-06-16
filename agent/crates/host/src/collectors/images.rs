//! Static scanning of local container IMAGES (pulled images, which may never
//! have run as a container) from on-disk runtime storage.
//!
//! Unlike [`super::containers`] (which only resolves merged rootfs for created
//! containers) and [`super::nested`] (which scans inside them), this collector
//! enumerates images from Docker `overlay2` and Podman `overlay` storage, then
//! assembles each image's merged rootfs from its on-disk layer `diff`
//! directories ([`crate::assemble_rootfs_from_layer_dirs`]) and runs the package
//! collector against it. Each image becomes an [`Asset::Image`] inventory row,
//! and its packages are emitted as ordinary `Package` rows stamped with the
//! image's `asset_id` (so they get CVE-matched by the analyzer like any package).
//!
//! containerd images are intentionally out of scope: their image→layer mapping
//! lives in a boltdb (`io.containerd.metadata.v1.bolt`), not static JSON, so it
//! cannot be resolved purely from files; containerd *containers* remain covered
//! by [`super::nested`].

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

use agent_contract::{Asset, Image};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::container_scan::ContainerScanOptions;
use crate::root::{join_root, resolve_under_root};
use crate::{assemble_rootfs_from_layer_dirs, Collector, CollectorOutput, ScanContext};

use super::containers::docker_data_root;
use super::{collect_packages, stamp_nested_assets};

/// Enumerates local container images and collects their packages statically.
pub struct ImagesCollector {
    /// Shared container/image scan limits and toggles.
    pub options: ContainerScanOptions,
}

impl ImagesCollector {
    /// Build an image collector with the given options.
    pub fn new(options: ContainerScanOptions) -> Self {
        Self { options }
    }
}

impl Collector for ImagesCollector {
    fn id(&self) -> &'static str {
        "container-images"
    }

    fn collect(&self, ctx: &mut ScanContext) -> anyhow::Result<CollectorOutput> {
        super::require_host_id(ctx, "container-images")?;
        Ok(CollectorOutput::Assets(collect(ctx, &self.options)))
    }
}

/// Collect image inventory + per-image package assets under `ctx.scan_root`.
pub fn collect(ctx: &ScanContext, options: &ContainerScanOptions) -> Vec<Asset> {
    if !options.enabled || !options.scan_images {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut budget = options.max_images;
    collect_docker_images(ctx, &mut out, &mut budget);
    collect_podman_images(ctx, &mut out, &mut budget);
    out
}

/// Assemble an image rootfs from its ordered layer diff dirs and collect its
/// packages, stamped to the image's `asset_id`. Best-effort: returns empty if
/// the rootfs cannot be assembled.
fn scan_image_rootfs(
    host_ctx: &ScanContext,
    image_asset_id: &str,
    diff_dirs: &[PathBuf],
) -> Vec<Asset> {
    let Ok(tmp) = tempfile::tempdir() else {
        return Vec::new();
    };
    if assemble_rootfs_from_layer_dirs(diff_dirs, tmp.path()).is_err() {
        return Vec::new();
    }
    let mut sub = ScanContext::at(tmp.path());
    sub.host_id = host_ctx.host_id.clone();
    sub.host = host_ctx.host.clone();
    let packages = collect_packages(&mut sub, None);
    stamp_nested_assets(packages, image_asset_id)
}

/// First 12 hex chars of an image id (`sha256:abcd…` or bare hex).
fn short_id(image_id: &str) -> &str {
    let hex = image_id.strip_prefix("sha256:").unwrap_or(image_id);
    &hex[..hex.len().min(12)]
}

// ---- Docker overlay2 ----

#[derive(Debug, Deserialize)]
struct DockerRepositories {
    #[serde(rename = "Repositories", default)]
    repositories: HashMap<String, HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct DockerImageConfig {
    rootfs: Option<DockerRootfs>,
    created: Option<String>,
}

#[derive(Debug, Deserialize)]
struct DockerRootfs {
    #[serde(default)]
    diff_ids: Vec<String>,
}

fn collect_docker_images(ctx: &ScanContext, out: &mut Vec<Asset>, budget: &mut usize) {
    if *budget == 0 {
        return;
    }
    let data_root = docker_data_root(ctx);
    let driver = docker_driver(ctx, &data_root);

    // Group tags by image id (id = `sha256:<hex>`). Keys like `nginx@sha256:…` are
    // digest pins, not human tags — keep `repo:tag` forms as the displayable tags.
    let mut tags_by_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let repos_path = join_root(
        ctx,
        &format!("{data_root}/image/{driver}/repositories.json"),
    );
    if let Ok(text) = fs::read_to_string(&repos_path) {
        if let Ok(repos) = serde_json::from_str::<DockerRepositories>(&text) {
            for refs in repos.repositories.values() {
                for (reference, image_id) in refs {
                    let entry = tags_by_id.entry(image_id.clone()).or_default();
                    if !reference.contains('@') {
                        entry.push(reference.clone());
                    }
                }
            }
        }
    }
    // Also enumerate dangling/untagged images: configs present in imagedb but not
    // referenced by repositories.json (e.g. after a re-pull/re-tag) — parity with
    // podman, which lists all images. They still have a scannable layer chain.
    let imagedb = join_root(
        ctx,
        &format!("{data_root}/image/{driver}/imagedb/content/sha256"),
    );
    if let Ok(entries) = fs::read_dir(&imagedb) {
        for entry in entries.flatten() {
            if let Some(hex) = entry.file_name().to_str() {
                tags_by_id.entry(format!("sha256:{hex}")).or_default();
            }
        }
    }

    for (image_id, mut tags) in tags_by_id {
        if *budget == 0 {
            break;
        }
        tags.sort();
        tags.dedup();
        let short = short_id(&image_id);
        let asset_id = format!("img-docker-{short}");
        let hex = image_id.strip_prefix("sha256:").unwrap_or(&image_id);
        // `created` is read from the image config independently of layer
        // resolution, so it is preserved in the inventory even when the layer
        // graph is incomplete and the diff dirs can't be assembled for scanning.
        let (diff_ids, created) =
            docker_image_config(ctx, &data_root, driver, hex).unwrap_or_default();
        let diff_dirs =
            docker_resolve_diff_dirs(ctx, &data_root, driver, &diff_ids).unwrap_or_default();
        let name = tags.first().cloned().unwrap_or_else(|| short.to_string());

        out.push(Asset::Image(Image {
            asset_id: asset_id.clone(),
            parent_asset_id: None,
            name,
            runtime: "docker".to_string(),
            image_id: Some(image_id.clone()),
            tags,
            created,
        }));
        if !diff_dirs.is_empty() {
            out.extend(scan_image_rootfs(ctx, &asset_id, &diff_dirs));
        }
        *budget -= 1;
    }
}

/// Pick the docker storage driver dir that exists (`overlay2` preferred).
fn docker_driver(ctx: &ScanContext, data_root: &str) -> &'static str {
    for driver in ["overlay2", "overlay"] {
        if join_root(ctx, &format!("{data_root}/image/{driver}")).is_dir() {
            return driver;
        }
    }
    "overlay2"
}

/// Read a docker image's config: ordered uncompressed-layer `diff_ids` and the
/// `created` timestamp. `None` if the config blob is missing/unparseable.
fn docker_image_config(
    ctx: &ScanContext,
    data_root: &str,
    driver: &str,
    image_hex: &str,
) -> Option<(Vec<String>, Option<String>)> {
    let cfg_path = join_root(
        ctx,
        &format!("{data_root}/image/{driver}/imagedb/content/sha256/{image_hex}"),
    );
    let text = fs::read_to_string(cfg_path).ok()?;
    let cfg: DockerImageConfig = serde_json::from_str(&text).ok()?;
    let diff_ids = cfg.rootfs.map(|r| r.diff_ids).unwrap_or_default();
    Some((diff_ids, cfg.created))
}

/// Resolve an image's ordered layer diff dirs (lowest first) from overlay2
/// storage. All-or-nothing: `None` if ANY layer's cache-id or diff dir is
/// missing, so a partial/stale rootfs is never scanned (which would yield wrong
/// CVE results) — the image is still inventoried, just without packages.
fn docker_resolve_diff_dirs(
    ctx: &ScanContext,
    data_root: &str,
    driver: &str,
    diff_ids: &[String],
) -> Option<Vec<PathBuf>> {
    if diff_ids.is_empty() {
        return None;
    }
    let mut dirs = Vec::new();
    let mut chain = String::new();
    for (i, diff_id) in diff_ids.iter().enumerate() {
        chain = if i == 0 {
            diff_id.clone()
        } else {
            chain_id(&chain, diff_id)
        };
        let chain_hex = chain.strip_prefix("sha256:").unwrap_or(&chain);
        let cache_path = join_root(
            ctx,
            &format!("{data_root}/image/{driver}/layerdb/sha256/{chain_hex}/cache-id"),
        );
        let cache_id = fs::read_to_string(cache_path).ok()?;
        let cache_id = cache_id.trim();
        if cache_id.is_empty() {
            return None;
        }
        // cache-id is sanitized through resolve_under_root: a forged storage tree
        // cannot point the diff dir outside the scan root.
        let diff_dir = resolve_under_root(
            &ctx.scan_root,
            &format!("/{data_root}/{driver}/{cache_id}/diff"),
        );
        if !diff_dir.is_dir() {
            return None;
        }
        dirs.push(diff_dir);
    }
    Some(dirs)
}

/// Docker overlay2 layer chain id: `sha256(parentChainID + " " + diffID)`,
/// where both operands are full `sha256:<hex>` digest strings.
fn chain_id(parent_chain: &str, diff_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(parent_chain.as_bytes());
    hasher.update(b" ");
    hasher.update(diff_id.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(7 + 64);
    out.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---- Podman / containers-storage (overlay) ----

#[derive(Debug, Deserialize)]
struct PodmanImage {
    id: String,
    #[serde(default)]
    names: Vec<String>,
    #[serde(default)]
    layer: String,
    created: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PodmanLayer {
    id: String,
    parent: Option<String>,
}

fn collect_podman_images(ctx: &ScanContext, out: &mut Vec<Asset>, budget: &mut usize) {
    if *budget == 0 {
        return;
    }
    let storage = "var/lib/containers/storage";
    let images_path = join_root(ctx, &format!("{storage}/overlay-images/images.json"));
    let Ok(text) = fs::read_to_string(&images_path) else {
        return;
    };
    let Ok(images) = serde_json::from_str::<Vec<PodmanImage>>(&text) else {
        return;
    };
    let parents = load_podman_layer_parents(ctx, storage);

    for img in images {
        if *budget == 0 {
            break;
        }
        let short = short_id(&img.id);
        let asset_id = format!("img-podman-{short}");
        let mut tags = img.names;
        tags.sort();
        tags.dedup();
        let name = tags.first().cloned().unwrap_or_else(|| short.to_string());
        let diff_dirs = podman_image_diff_dirs(ctx, storage, &img.layer, &parents);

        out.push(Asset::Image(Image {
            asset_id: asset_id.clone(),
            parent_asset_id: None,
            name,
            runtime: "podman".to_string(),
            image_id: Some(img.id.clone()),
            tags,
            created: img.created,
        }));
        if !diff_dirs.is_empty() {
            out.extend(scan_image_rootfs(ctx, &asset_id, &diff_dirs));
        }
        *budget -= 1;
    }
}

/// Map every podman layer id to its parent id from `overlay-layers/layers.json`.
fn load_podman_layer_parents(ctx: &ScanContext, storage: &str) -> HashMap<String, Option<String>> {
    let path = join_root(ctx, &format!("{storage}/overlay-layers/layers.json"));
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let Ok(layers) = serde_json::from_str::<Vec<PodmanLayer>>(&text) else {
        return HashMap::new();
    };
    layers.into_iter().map(|l| (l.id, l.parent)).collect()
}

/// Walk the parent chain from `top_layer` to the root, returning the ordered
/// diff dirs (lowest first) that exist on disk.
fn podman_image_diff_dirs(
    ctx: &ScanContext,
    storage: &str,
    top_layer: &str,
    parents: &HashMap<String, Option<String>>,
) -> Vec<PathBuf> {
    let mut chain = Vec::new();
    let mut visited = HashSet::new();
    let mut cur = (!top_layer.is_empty()).then(|| top_layer.to_string());
    while let Some(id) = cur {
        // A visited-set both terminates a forged/cyclic parent chain and prevents
        // re-applying the same layer many times (a small forged layers.json could
        // otherwise amplify into hundreds of duplicate diff-dir applications).
        if id.is_empty() || !visited.insert(id.clone()) {
            break;
        }
        chain.push(id.clone());
        cur = parents.get(&id).cloned().flatten();
    }
    chain.reverse(); // lowest layer first
    chain
        .iter()
        .filter_map(|id| {
            let dir = resolve_under_root(&ctx.scan_root, &format!("/{storage}/overlay/{id}/diff"));
            dir.is_dir().then_some(dir)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn write(path: PathBuf, body: &str) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, body).unwrap();
    }

    #[test]
    fn chain_id_matches_docker_formula() {
        // Known vector: chainID(b) = sha256("<diff_a> <diff_b>").
        let a = "sha256:aaaa";
        let b = "sha256:bbbb";
        let expected = {
            let mut h = Sha256::new();
            h.update(b"sha256:aaaa sha256:bbbb");
            let d = h.finalize();
            let mut s = String::from("sha256:");
            for byte in d {
                use std::fmt::Write as _;
                let _ = write!(s, "{byte:02x}");
            }
            s
        };
        assert_eq!(chain_id(a, b), expected);
        // 'sha256:' + 64 hex chars.
        assert_eq!(chain_id(a, b).len(), 7 + 64);
    }

    #[test]
    fn enumerates_docker_image_and_scans_packages() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let data = "var/lib/docker";
        let image_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let diff_id = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        let cache_id = "cacheid0001";

        // repositories.json: nginx:1.25 -> the image id.
        write(
            root.join(format!("{data}/image/overlay2/repositories.json")),
            &format!(r#"{{"Repositories":{{"nginx":{{"nginx:1.25":"sha256:{image_hex}"}}}}}}"#),
        );
        // image config with a single layer.
        write(
            root.join(format!(
                "{data}/image/overlay2/imagedb/content/sha256/{image_hex}"
            )),
            &format!(
                r#"{{"created":"2026-01-01T00:00:00Z","rootfs":{{"type":"layers","diff_ids":["{diff_id}"]}}}}"#
            ),
        );
        // layerdb: chainID of a single layer == its diff_id; maps to cache-id.
        let chain_hex = diff_id.strip_prefix("sha256:").unwrap();
        write(
            root.join(format!(
                "{data}/image/overlay2/layerdb/sha256/{chain_hex}/cache-id"
            )),
            cache_id,
        );
        // the extracted layer diff: an apk-based image with a package DB.
        let diff = root.join(format!("{data}/overlay2/{cache_id}/diff"));
        write(diff.join("etc/os-release"), "ID=alpine\nVERSION_ID=3.20\n");
        write(diff.join("lib/apk/db/installed"), "P:curl\nV:8.7.1-r0\n\n");

        let mut ctx = ScanContext::at(root);
        ctx.host_id = Some("host-1".to_string());

        let opts = ContainerScanOptions::enabled();
        let assets = collect(&ctx, &opts);

        let images: Vec<_> = assets
            .iter()
            .filter_map(|a| match a {
                Asset::Image(i) => Some(i),
                _ => None,
            })
            .collect();
        assert_eq!(images.len(), 1, "one docker image expected");
        let img = images[0];
        assert_eq!(img.asset_id, "img-docker-111111111111");
        assert_eq!(img.name, "nginx:1.25");
        assert_eq!(img.runtime, "docker");
        assert_eq!(img.tags, vec!["nginx:1.25".to_string()]);
        assert_eq!(img.created.as_deref(), Some("2026-01-01T00:00:00Z"));

        // The apk package inside the image is collected and stamped to the image.
        let pkg = assets.iter().find_map(|a| match a {
            Asset::Package(p) if p.name == "curl" => Some(p),
            _ => None,
        });
        let pkg = pkg.expect("curl package from image rootfs");
        assert_eq!(
            pkg.parent_asset_id.as_deref(),
            Some("img-docker-111111111111")
        );
        assert!(pkg.asset_id.starts_with("img-docker-111111111111::"));
    }

    #[test]
    fn enumerates_dangling_untagged_docker_image() {
        // An image present in imagedb but absent from repositories.json (dangling
        // <none>) must still be enumerated and scanned — parity with podman.
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let data = "var/lib/docker";
        let image_hex = "9999999999999999999999999999999999999999999999999999999999999999";
        let diff_id = "sha256:8888888888888888888888888888888888888888888888888888888888888888";
        let cache_id = "danglingcache";
        // imagedb config only — NO repositories.json.
        write(
            root.join(format!(
                "{data}/image/overlay2/imagedb/content/sha256/{image_hex}"
            )),
            &format!(r#"{{"rootfs":{{"diff_ids":["{diff_id}"]}}}}"#),
        );
        let chain_hex = diff_id.strip_prefix("sha256:").unwrap();
        write(
            root.join(format!(
                "{data}/image/overlay2/layerdb/sha256/{chain_hex}/cache-id"
            )),
            cache_id,
        );
        let diff = root.join(format!("{data}/overlay2/{cache_id}/diff"));
        write(diff.join("etc/os-release"), "ID=alpine\nVERSION_ID=3.20\n");
        write(
            diff.join("lib/apk/db/installed"),
            "P:busybox\nV:1.36.1-r0\n\n",
        );

        let mut ctx = ScanContext::at(root);
        ctx.host_id = Some("h".to_string());
        let assets = collect(&ctx, &ContainerScanOptions::enabled());

        let img = assets.iter().find_map(|a| match a {
            Asset::Image(i) => Some(i),
            _ => None,
        });
        let img = img.expect("dangling image enumerated");
        assert_eq!(img.asset_id, "img-docker-999999999999");
        assert!(img.tags.is_empty(), "dangling image has no tags");
        assert_eq!(img.name, "999999999999", "falls back to short id");
        assert!(
            assets
                .iter()
                .any(|a| matches!(a, Asset::Package(p) if p.name == "busybox")),
            "dangling image packages are still collected"
        );
    }

    #[test]
    fn disabled_or_images_off_returns_empty() {
        let ctx = ScanContext::at("/");
        assert!(collect(&ctx, &ContainerScanOptions::default()).is_empty());
        let mut opts = ContainerScanOptions::enabled();
        opts.scan_images = false;
        assert!(collect(&ctx, &opts).is_empty());
    }

    #[test]
    fn enumerates_podman_image_layers_in_order() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let storage = "var/lib/containers/storage";
        write(
            root.join(format!("{storage}/overlay-images/images.json")),
            r#"[{"id":"abc123def456","names":["docker.io/library/busybox:latest"],"layer":"top","created":"2026-02-02T00:00:00Z"}]"#,
        );
        write(
            root.join(format!("{storage}/overlay-layers/layers.json")),
            r#"[{"id":"top","parent":"base"},{"id":"base","parent":null}]"#,
        );
        // base provides os-release; top adds the dpkg DB.
        write(
            root.join(format!("{storage}/overlay/base/diff/etc/os-release")),
            "ID=debian\nVERSION_ID=12\n",
        );
        write(
            root.join(format!("{storage}/overlay/top/diff/var/lib/dpkg/status")),
            "Package: wget\nStatus: install ok installed\nVersion: 1.21\nArchitecture: amd64\n",
        );

        let mut ctx = ScanContext::at(root);
        ctx.host_id = Some("host-1".to_string());
        let assets = collect(&ctx, &ContainerScanOptions::enabled());

        let img = assets.iter().find_map(|a| match a {
            Asset::Image(i) => Some(i),
            _ => None,
        });
        let img = img.expect("one podman image");
        assert_eq!(img.asset_id, "img-podman-abc123def456");
        assert_eq!(img.runtime, "podman");
        assert_eq!(img.name, "docker.io/library/busybox:latest");

        let pkg = assets.iter().find_map(|a| match a {
            Asset::Package(p) if p.name == "wget" => Some(p),
            _ => None,
        });
        assert!(
            pkg.expect("wget from podman image")
                .parent_asset_id
                .as_deref()
                == Some("img-podman-abc123def456")
        );
    }

    #[test]
    fn max_images_bounds_enumeration() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let storage = "var/lib/containers/storage";
        write(
            root.join(format!("{storage}/overlay-images/images.json")),
            r#"[{"id":"aaaa1111","names":["a:1"],"layer":""},{"id":"bbbb2222","names":["b:1"],"layer":""}]"#,
        );
        let mut ctx = ScanContext::at(root);
        ctx.host_id = Some("h".to_string());
        let mut opts = ContainerScanOptions::enabled();
        opts.max_images = 1;
        let images = collect(&ctx, &opts)
            .into_iter()
            .filter(|a| matches!(a, Asset::Image(_)))
            .count();
        assert_eq!(images, 1, "max_images caps the number of images");
    }
}
