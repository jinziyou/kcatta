//! Static container-image scanning.
//!
//! Assembles the merged root filesystem of a container image (a `docker save`
//! tarball or OCI image archive) by applying its layers in order — honoring OCI
//! whiteouts — **without running the image**. The resulting rootfs is then fed to
//! the normal host collectors (`-r <rootfs>`), so an image is scanned for
//! packages / SBOM / services / accounts / credentials / malware exactly like a
//! live filesystem, purely from static files.
//!
//! Layer ordering comes from the archive's `manifest.json` `Layers` array, which
//! both the classic docker-save format and OCI-format `docker save` emit (its
//! entries point at `blobs/sha256/<digest>`). Layer tars may be gzip-compressed;
//! that is detected per layer. Untrusted archive paths are sanitized to normal
//! components so a malicious layer cannot write outside the destination rootfs.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};

/// Prefix marking a whiteout entry: `.wh.<name>` deletes `<name>` from the merged fs.
const WHITEOUT_PREFIX: &str = ".wh.";
/// Opaque-directory whiteout: clears the parent directory's prior contents.
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

/// Assemble the merged root filesystem of an image archive into `dest`.
///
/// `image_archive` is a `docker save` / OCI tarball. Layers are applied in
/// manifest order with whiteout handling. `dest` is created if absent.
pub fn assemble_image_rootfs(image_archive: &Path, dest: &Path) -> Result<()> {
    let staging = tempfile::tempdir().context("create image staging dir")?;
    extract_archive(image_archive, staging.path())
        .with_context(|| format!("extract image archive {}", image_archive.display()))?;

    let layers = read_layer_paths(staging.path())?;
    anyhow::ensure!(!layers.is_empty(), "image archive lists no layers");

    fs::create_dir_all(dest).with_context(|| format!("create rootfs dir {}", dest.display()))?;
    for layer in &layers {
        apply_layer(&staging.path().join(layer), dest)
            .with_context(|| format!("apply layer {layer}"))?;
    }
    Ok(())
}

/// Extract the outer image archive (an uncompressed tar) into `dest`.
fn extract_archive(archive: &Path, dest: &Path) -> Result<()> {
    let file = fs::File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    let mut ar = tar::Archive::new(maybe_gzip(file)?);
    // The outer archive is a control structure (manifest.json + blobs); keep its
    // perms off and let the tar crate's own traversal guards reject escapes.
    ar.set_preserve_permissions(false);
    ar.set_overwrite(true);
    ar.unpack(dest).context("unpack image archive")?;
    Ok(())
}

/// Read the ordered layer paths from the archive's `manifest.json`.
fn read_layer_paths(staging: &Path) -> Result<Vec<String>> {
    let manifest_path = staging.join("manifest.json");
    let text = fs::read_to_string(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let manifest: serde_json::Value = serde_json::from_str(&text).context("parse manifest.json")?;
    let layers = manifest
        .get(0)
        .and_then(|entry| entry.get("Layers"))
        .and_then(|l| l.as_array())
        .context("manifest.json[0].Layers missing or not an array")?;
    Ok(layers
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect())
}

/// Apply one (possibly gzip-compressed) layer tar onto `dest`, honoring whiteouts.
fn apply_layer(layer_path: &Path, dest: &Path) -> Result<()> {
    let file = fs::File::open(layer_path)
        .with_context(|| format!("open layer {}", layer_path.display()))?;
    let mut ar = tar::Archive::new(maybe_gzip(file)?);
    // Files in an image layer are read-only data we scan; don't reapply their
    // archived mode (a 0-mode file would then be unreadable to the collectors).
    ar.set_preserve_permissions(false);

    for entry in ar.entries().context("read layer entries")? {
        let mut entry = entry.context("read layer entry")?;
        let raw = entry.path().context("entry path")?.into_owned();
        let rel = sanitize(&raw);
        if rel.as_os_str().is_empty() {
            continue;
        }
        let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Materialize the entry's parent chain as REAL dirs first: this both
        // creates intermediate dirs and replaces any lower-layer symlink in the
        // way, so neither a write nor a whiteout deletion below can be redirected
        // through a hostile symlink to outside `dest`.
        if !ensure_parent_dirs(dest, &rel) {
            continue;
        }
        let parent_dir = rel
            .parent()
            .map(|p| dest.join(p))
            .unwrap_or_else(|| dest.to_path_buf());

        if name == OPAQUE_WHITEOUT {
            // parent_dir is now guaranteed a real dir (ensure_parent_dirs); never
            // read_dir through a symlink.
            if fs::symlink_metadata(&parent_dir).is_ok_and(|m| m.is_dir()) {
                clear_dir(&parent_dir);
            }
            continue;
        }
        if let Some(victim) = whiteout_victim(name) {
            remove_path(&parent_dir.join(victim));
            continue;
        }

        let out = dest.join(&rel);
        if entry.header().entry_type().is_dir() {
            if fs::symlink_metadata(&out).is_ok_and(|m| !m.is_dir()) {
                remove_path(&out); // upper dir replaces a lower file/symlink
            }
            let _ = fs::create_dir_all(&out);
        } else {
            // Replace whatever is at this path with the upper layer's file/symlink.
            // Best-effort unpack: entries an unprivileged user can't materialize
            // (device nodes, fifos, …) are skipped — they carry no asset data.
            remove_path(&out);
            let _ = entry.unpack(&out);
        }
    }
    Ok(())
}

/// Validate a whiteout marker basename → the single victim name it deletes.
///
/// Per the OCI/AUFS convention a whiteout is `.wh.` followed by a **non-empty**
/// basename. A hostile marker such as bare `.wh.` (empty victim → would delete
/// the containing dir) or `.wh...` (victim `..` → would escape the rootfs and
/// delete host files) is NOT a valid whiteout and is ignored. Returns the victim
/// only when it is a single normal path component.
fn whiteout_victim(name: &str) -> Option<&str> {
    let victim = name.strip_prefix(WHITEOUT_PREFIX)?;
    if victim.is_empty()
        || victim == "."
        || victim == ".."
        || victim.contains('/')
        || victim.contains('\\')
    {
        return None;
    }
    Some(victim)
}

/// Wrap `file` in a gzip decoder when it begins with the gzip magic, else pass through.
fn maybe_gzip(file: fs::File) -> Result<Box<dyn Read>> {
    let mut reader = BufReader::new(file);
    let is_gzip = {
        let head = reader.fill_buf().context("read archive header")?;
        head.len() >= 2 && head[0] == 0x1f && head[1] == 0x8b
    };
    if is_gzip {
        Ok(Box::new(flate2::read::GzDecoder::new(reader)))
    } else {
        Ok(Box::new(reader))
    }
}

/// Keep only normal path components, dropping `/`, `.`, `..` and prefixes so an
/// untrusted layer cannot escape the destination rootfs.
fn sanitize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        if let Component::Normal(part) = component {
            out.push(part);
        }
    }
    out
}

/// Remove a file/dir/symlink at `path` (best-effort; never follows a dir symlink).
fn remove_path(path: &Path) {
    if path.is_dir() && !path.is_symlink() {
        let _ = fs::remove_dir_all(path);
    } else if path.exists() || path.is_symlink() {
        let _ = fs::remove_file(path);
    }
}

/// Remove every immediate child of `dir` (opaque-whiteout semantics).
fn clear_dir(dir: &Path) {
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            remove_path(&entry.path());
        }
    }
}

/// Assemble a merged rootfs into `dest` from already-extracted on-disk layer
/// **diff directories** (lowest layer first), the way Docker `overlay2` and
/// Podman store local image/container layers. This is the on-disk-storage
/// counterpart to [`assemble_image_rootfs`] (which consumes a `docker save`
/// tarball): each `diff` dir is overlaid in order with whiteout handling, so a
/// pulled image that was never run can still be scanned statically.
pub fn assemble_rootfs_from_layer_dirs(diff_dirs: &[PathBuf], dest: &Path) -> Result<()> {
    anyhow::ensure!(!diff_dirs.is_empty(), "image has no layer diff directories");
    fs::create_dir_all(dest).with_context(|| format!("create rootfs dir {}", dest.display()))?;
    for dir in diff_dirs {
        apply_layer_dir(dir, dest).with_context(|| format!("apply layer dir {}", dir.display()))?;
    }
    Ok(())
}

/// Overlay one extracted layer `diff` dir onto `dest`.
///
/// Whiteouts in a `diff` dir come in two encodings, both handled here:
/// AUFS-style `.wh.<name>` / `.wh..wh..opq` marker files (left in place by some
/// extractors) and overlayfs character-device(0,0) deletion markers. Parent
/// directories are materialized as real dirs (replacing any lower-layer symlink)
/// so a crafted symlink cannot redirect a write outside `dest`.
fn apply_layer_dir(src: &Path, dest: &Path) -> Result<()> {
    apply_layer_dir_rec(src, dest, Path::new(""))
}

fn apply_layer_dir_rec(src_dir: &Path, dest_root: &Path, rel_dir: &Path) -> Result<()> {
    let read = match fs::read_dir(src_dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    let dest_dir = dest_root.join(rel_dir);

    // An opaque marker means this layer replaces the lower dir wholesale: clear
    // the accumulated dest dir before laying down this layer's entries. dest_dir
    // is always a real dir here (created by the parent recursion, which replaces
    // a lower symlink before descending), so clear_dir cannot escape via symlink.
    if src_dir.join(OPAQUE_WHITEOUT).exists() {
        clear_dir(&dest_dir);
    }

    // Two ordered passes over this layer's entries: deletions first, then writes.
    // `fs::read_dir` order is arbitrary, so without this a same-layer `.wh.foo` +
    // real `foo` collision would resolve nondeterministically; deletions-first
    // makes the present file deterministically win (OCI "present file wins").
    let entries: Vec<_> = read.flatten().collect();

    // Pass 1 — deletions: `.wh.<victim>` markers and overlayfs char-dev(0,0).
    for entry in &entries {
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy();
        if name == OPAQUE_WHITEOUT {
            continue; // handled above
        }
        if let Some(victim) = whiteout_victim(&name) {
            remove_path(&dest_dir.join(victim));
            continue;
        }
        if fs::symlink_metadata(entry.path()).is_ok_and(|m| is_overlay_whiteout(&m)) {
            remove_path(&dest_dir.join(name.as_ref()));
        }
    }

    // Pass 2 — content: dirs, files, symlinks (override the deletions above).
    for entry in &entries {
        let name_os = entry.file_name();
        let name = name_os.to_string_lossy();
        // Skip every marker form (`.wh.`, `.wh.<x>`, `.wh..wh..opq`) and char-devs.
        if name.starts_with(WHITEOUT_PREFIX) {
            continue;
        }
        let src = entry.path();
        let Ok(meta) = fs::symlink_metadata(&src) else {
            continue;
        };
        if is_overlay_whiteout(&meta) {
            continue;
        }

        let rel = rel_dir.join(name.as_ref());
        let ft = meta.file_type();
        if ft.is_dir() {
            let out = dest_root.join(&rel);
            // An upper-layer dir replaces a lower-layer file/symlink at this path.
            if fs::symlink_metadata(&out).is_ok_and(|m| !m.is_dir()) {
                remove_path(&out);
            }
            let _ = fs::create_dir_all(&out);
            apply_layer_dir_rec(&src, dest_root, &rel)?;
        } else if ft.is_symlink() {
            if ensure_parent_dirs(dest_root, &rel) {
                let target_out = dest_root.join(&rel);
                remove_path(&target_out);
                if let Ok(link_target) = fs::read_link(&src) {
                    let _ = create_symlink(&link_target, &target_out);
                }
            }
        } else if ft.is_file() && ensure_parent_dirs(dest_root, &rel) {
            let target_out = dest_root.join(&rel);
            remove_path(&target_out);
            let _ = fs::copy(&src, &target_out);
        }
        // Other node types (fifo/socket/block dev) carry no asset data — skip.
    }
    Ok(())
}

/// Ensure every parent component of `rel` exists as a real directory under
/// `root`, replacing any symlink/file in the way. Returns false on failure
/// (treated as "skip this entry"). Components are layer-controlled but always
/// single Normal names here, so the join stays within `root`.
fn ensure_parent_dirs(root: &Path, rel: &Path) -> bool {
    let comps: Vec<Component> = rel.components().collect();
    if comps.is_empty() {
        return false;
    }
    let mut cur = root.to_path_buf();
    for comp in &comps[..comps.len() - 1] {
        let Component::Normal(name) = comp else {
            return false;
        };
        cur.push(name);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                // A lower-layer symlink/file occupies a path an upper layer needs
                // as a directory — replace it with a real dir.
                remove_path(&cur);
                if fs::create_dir(&cur).is_err() {
                    return false;
                }
            }
            Err(_) => {
                if fs::create_dir(&cur).is_err() {
                    return false;
                }
            }
        }
    }
    true
}

/// Overlayfs encodes a deleted lower-layer entry as a char device with rdev 0:0.
#[cfg(unix)]
fn is_overlay_whiteout(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    meta.file_type().is_char_device() && meta.rdev() == 0
}

#[cfg(not(unix))]
fn is_overlay_whiteout(_meta: &fs::Metadata) -> bool {
    false
}

// NOTE: opaque dirs can also be encoded as an overlayfs xattr
// (`trusted.overlay.opaque=y`); reading `trusted.*` xattrs needs privileges and a
// platform xattr API, and package collection rarely depends on opaque-dir
// semantics, so only the `.wh..wh..opq` marker-file form is recognized.

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, link)
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _link: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Build a tar (in memory) from `(path, contents)` pairs.
    fn make_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        builder.into_inner().unwrap()
    }

    /// Build a layer tar with file entries plus raw symlink entries (for crafting
    /// hostile layers — a symlink whose target escapes the rootfs).
    fn make_tar_with_symlinks(files: &[(&str, &[u8])], symlinks: &[(&str, &str)]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, data) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            builder.append_data(&mut header, path, *data).unwrap();
        }
        for (path, target) in symlinks {
            let mut header = tar::Header::new_gnu();
            header.set_size(0);
            header.set_mode(0o777);
            header.set_entry_type(tar::EntryType::Symlink);
            builder
                .append_link(&mut header, path, target)
                .expect("append symlink");
        }
        builder.into_inner().unwrap()
    }

    /// Build a docker-save-style outer archive: manifest.json + named layer tars.
    fn make_image(layers: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let names: Vec<&str> = layers.iter().map(|(n, _)| *n).collect();
        let manifest =
            serde_json::json!([{ "Config": "config.json", "Layers": names }]).to_string();
        let mut files: Vec<(&str, &[u8])> = vec![("manifest.json", manifest.as_bytes())];
        for (name, data) in layers {
            files.push((name, data));
        }
        make_tar(&files)
    }

    #[test]
    fn assembles_layers_with_overrides_and_whiteouts() {
        let layer1 = make_tar(&[
            ("etc/os-release", b"ID=alpine\nVERSION_ID=3.20\n"),
            ("etc/keep-me", b"old"),
            ("app/a.txt", b"layer1-a"),
        ]);
        // Layer 2 overrides a.txt, adds b.txt, and whiteouts etc/keep-me.
        let layer2 = make_tar(&[
            ("app/a.txt", b"layer2-a"),
            ("app/b.txt", b"layer2-b"),
            ("etc/.wh.keep-me", b""),
        ]);
        let image = make_image(&[("layer1.tar", layer1), ("layer2.tar", layer2)]);

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("image.tar");
        std::fs::File::create(&archive)
            .unwrap()
            .write_all(&image)
            .unwrap();
        let rootfs = dir.path().join("rootfs");
        assemble_image_rootfs(&archive, &rootfs).unwrap();

        // os-release carried through, so the collectors can derive the ecosystem.
        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc/os-release")).unwrap(),
            "ID=alpine\nVERSION_ID=3.20\n"
        );
        // Upper layer wins.
        assert_eq!(
            std::fs::read_to_string(rootfs.join("app/a.txt")).unwrap(),
            "layer2-a"
        );
        assert_eq!(
            std::fs::read_to_string(rootfs.join("app/b.txt")).unwrap(),
            "layer2-b"
        );
        // Whiteout removed the lower-layer file.
        assert!(
            !rootfs.join("etc/keep-me").exists(),
            "whiteout must delete etc/keep-me"
        );
    }

    #[test]
    fn opaque_whiteout_clears_directory() {
        let layer1 = make_tar(&[("data/old1", b"x"), ("data/old2", b"y")]);
        let layer2 = make_tar(&[("data/.wh..wh..opq", b""), ("data/new", b"z")]);
        let image = make_image(&[("l1.tar", layer1), ("l2.tar", layer2)]);

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("image.tar");
        std::fs::write(&archive, &image).unwrap();
        let rootfs = dir.path().join("rootfs");
        assemble_image_rootfs(&archive, &rootfs).unwrap();

        assert!(
            !rootfs.join("data/old1").exists(),
            "opaque whiteout clears prior contents"
        );
        assert!(!rootfs.join("data/old2").exists());
        assert_eq!(
            std::fs::read_to_string(rootfs.join("data/new")).unwrap(),
            "z"
        );
    }

    #[test]
    fn sanitize_strips_escape_components() {
        // A malicious layer entry can carry `..`, an absolute path, or a Windows
        // prefix; sanitize() must reduce every such path to a contained relative
        // one so `dest.join(...)` can never escape the rootfs. (A well-behaved tar
        // writer rejects `..` on write, so the runtime threat is hand-crafted
        // archives — we assert the property on the sanitizer itself.)
        assert_eq!(
            sanitize(Path::new("../../etc/evil")),
            PathBuf::from("etc/evil")
        );
        assert_eq!(
            sanitize(Path::new("/etc/shadow")),
            PathBuf::from("etc/shadow")
        );
        assert_eq!(sanitize(Path::new("a/../../b")), PathBuf::from("a/b"));
        assert_eq!(sanitize(Path::new("./app/./x")), PathBuf::from("app/x"));
        assert_eq!(sanitize(Path::new("..")), PathBuf::from(""));
        assert_eq!(
            sanitize(Path::new("usr/bin/sh")),
            PathBuf::from("usr/bin/sh")
        );
    }

    #[test]
    fn assembles_rootfs_from_layer_diff_dirs() {
        // Simulate overlay2/podman: two extracted layer `diff` dirs applied in order.
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("l1/diff");
        let l2 = dir.path().join("l2/diff");
        std::fs::create_dir_all(l1.join("etc")).unwrap();
        std::fs::create_dir_all(l1.join("var/lib/dpkg")).unwrap();
        std::fs::write(l1.join("etc/os-release"), "ID=debian\nVERSION_ID=12\n").unwrap();
        std::fs::write(l1.join("var/lib/dpkg/status"), "Package: curl\n").unwrap();
        std::fs::write(l1.join("etc/keep"), "old").unwrap();

        std::fs::create_dir_all(l2.join("etc")).unwrap();
        // Upper layer overrides keep, adds a file, and whiteouts os-release's sibling.
        std::fs::write(l2.join("etc/keep"), "new").unwrap();
        std::fs::write(l2.join("etc/extra"), "x").unwrap();
        std::fs::write(l2.join("etc/.wh.os-release"), "").unwrap();

        let rootfs = dir.path().join("rootfs");
        assemble_rootfs_from_layer_dirs(&[l1.clone(), l2.clone()], &rootfs).unwrap();

        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc/keep")).unwrap(),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(rootfs.join("etc/extra")).unwrap(),
            "x"
        );
        assert_eq!(
            std::fs::read_to_string(rootfs.join("var/lib/dpkg/status")).unwrap(),
            "Package: curl\n"
        );
        // .wh. whiteout removed the lower-layer file.
        assert!(
            !rootfs.join("etc/os-release").exists(),
            "whiteout must drop etc/os-release"
        );
    }

    /// Helper: write an image archive to a fresh tempdir, with a `HOSTFILE` and a
    /// `HOSTDIR/secret` placed OUTSIDE the rootfs, then assemble. Returns the dir.
    fn assemble_with_host_bait(image: &[u8]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("HOSTFILE"), "host").unwrap();
        std::fs::create_dir_all(dir.path().join("HOSTDIR")).unwrap();
        std::fs::write(dir.path().join("HOSTDIR/secret"), "topsecret").unwrap();
        let archive = dir.path().join("image.tar");
        std::fs::write(&archive, image).unwrap();
        let rootfs = dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        assemble_image_rootfs(&archive, &rootfs).unwrap();
        dir
    }

    #[test]
    fn whiteout_dotdot_victim_cannot_escape_rootfs() {
        // `.wh...` strips to victim `..`; a naive impl would delete dest/etc/.. (the
        // rootfs) or dest/.. (the host). It must be ignored as an invalid whiteout.
        let layer = make_tar(&[("etc/keep", b"x"), ("etc/.wh...", b""), (".wh...", b"")]);
        let dir = assemble_with_host_bait(&make_image(&[("l.tar", layer)]));
        let rootfs = dir.path().join("rootfs");
        assert!(
            dir.path().join("HOSTFILE").exists(),
            "must not escape & delete host files"
        );
        assert!(rootfs.exists(), "must not delete the rootfs itself");
        assert!(
            rootfs.join("etc/keep").exists(),
            "invalid whiteout ignored; keep survives"
        );
    }

    #[test]
    fn bare_wh_marker_does_not_delete_containing_dir() {
        // A marker named exactly `.wh.` (empty victim) must NOT wipe its parent dir.
        let l1 = make_tar(&[("etc/keep", b"x"), ("etc/also", b"y")]);
        let l2 = make_tar(&[("etc/.wh.", b""), (".wh.", b"")]);
        let dir = assemble_with_host_bait(&make_image(&[("l1.tar", l1), ("l2.tar", l2)]));
        let rootfs = dir.path().join("rootfs");
        assert!(
            rootfs.join("etc/keep").exists(),
            "bare .wh. must not delete etc/*"
        );
        assert!(rootfs.join("etc/also").exists());
    }

    #[cfg(unix)]
    #[test]
    fn whiteout_cannot_delete_through_a_lower_layer_symlink() {
        // Lower layer makes `etc` an ABSOLUTE symlink to a host dir; upper layer
        // whiteouts `etc/secret` and opaque-clears `etc`. The deletions must NOT
        // resolve through the symlink and touch the host dir's contents.
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("HOSTDIR")).unwrap();
        std::fs::write(dir.path().join("HOSTDIR/secret"), "topsecret").unwrap();
        std::fs::write(dir.path().join("HOSTDIR/other"), "more").unwrap();
        let host_dir = dir.path().join("HOSTDIR");

        let l1 = make_tar_with_symlinks(&[], &[("etc", host_dir.to_str().unwrap())]);
        let l2 = make_tar(&[("etc/.wh.secret", b""), ("etc/.wh..wh..opq", b"")]);
        let image = make_image(&[("l1.tar", l1), ("l2.tar", l2)]);
        let archive = dir.path().join("image.tar");
        std::fs::write(&archive, &image).unwrap();
        let rootfs = dir.path().join("rootfs");
        std::fs::create_dir_all(&rootfs).unwrap();
        assemble_image_rootfs(&archive, &rootfs).unwrap();

        assert!(
            host_dir.join("secret").exists(),
            "whiteout must not delete through symlink"
        );
        assert!(
            host_dir.join("other").exists(),
            "opaque must not clear through symlink"
        );
        assert!(
            !std::fs::symlink_metadata(rootfs.join("etc"))
                .unwrap()
                .is_symlink(),
            "the escaping symlink should have been replaced by a real dir"
        );
    }

    #[test]
    fn same_layer_whiteout_and_file_collision_keeps_the_file() {
        // A malformed diff dir with both `foo` and `.wh.foo`: two-pass apply must
        // deterministically keep the present file (deletions run before writes).
        let dir = tempfile::tempdir().unwrap();
        let layer = dir.path().join("l/diff");
        std::fs::create_dir_all(&layer).unwrap();
        std::fs::write(layer.join("foo"), "present").unwrap();
        std::fs::write(layer.join(".wh.foo"), "").unwrap();
        // also a bare .wh. and .wh... must be ignored, not delete the dir
        std::fs::write(layer.join(".wh."), "").unwrap();
        std::fs::write(layer.join(".wh..."), "").unwrap();
        std::fs::write(layer.join("keep"), "k").unwrap();
        let rootfs = dir.path().join("rootfs");
        assemble_rootfs_from_layer_dirs(&[layer], &rootfs).unwrap();
        assert_eq!(
            std::fs::read_to_string(rootfs.join("foo")).unwrap(),
            "present"
        );
        assert!(
            rootfs.join("keep").exists(),
            "bare/invalid markers must not wipe the dir"
        );
    }

    #[cfg(unix)]
    #[test]
    fn upper_layer_dir_replaces_lower_symlink_without_escaping() {
        // Lower layer makes `usr/lib` an ABSOLUTE symlink (a classic escape vector);
        // upper layer writes `usr/lib/pkgdb`. The write must land inside the rootfs,
        // not follow the symlink out to the host.
        let dir = tempfile::tempdir().unwrap();
        let l1 = dir.path().join("l1/diff");
        let l2 = dir.path().join("l2/diff");
        std::fs::create_dir_all(l1.join("usr")).unwrap();
        std::os::unix::fs::symlink("/etc", l1.join("usr/lib")).unwrap();
        std::fs::create_dir_all(l2.join("usr/lib")).unwrap();
        std::fs::write(l2.join("usr/lib/pkgdb"), "data").unwrap();

        let rootfs = dir.path().join("rootfs");
        assemble_rootfs_from_layer_dirs(&[l1, l2], &rootfs).unwrap();

        // The file is inside the rootfs and usr/lib is now a real dir, not a symlink.
        assert_eq!(
            std::fs::read_to_string(rootfs.join("usr/lib/pkgdb")).unwrap(),
            "data"
        );
        assert!(!std::fs::symlink_metadata(rootfs.join("usr/lib"))
            .unwrap()
            .is_symlink());
    }
}
