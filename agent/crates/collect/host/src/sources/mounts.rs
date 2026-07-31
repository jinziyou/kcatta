//! Live Linux filesystem mounts from `/proc/self/mountinfo`.

use std::collections::BTreeSet;
use std::fs;

use agent_contract::{Asset, FilesystemMount};
use nix::sys::statvfs::statvfs;
use sha2::{Digest, Sha256};

use crate::root::join_root;
use crate::ScanContext;

const MAX_MOUNTS: usize = 512;

/// Collect mounted filesystems. Offline/image roots without mountinfo emit none.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let Ok(text) = fs::read_to_string(join_root(ctx, "proc/self/mountinfo")) else {
        return Vec::new();
    };
    let mut rows: Vec<FilesystemMount> = text
        .lines()
        .filter_map(|line| parse_line(ctx, line))
        .collect();
    rows.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
    rows.dedup_by(|left, right| {
        left.mount_point == right.mount_point
            && left.source == right.source
            && left.fs_type == right.fs_type
    });
    rows.truncate(MAX_MOUNTS);
    rows.into_iter().map(Asset::FilesystemMount).collect()
}

fn parse_line(ctx: &ScanContext, line: &str) -> Option<FilesystemMount> {
    let (before, after) = line.split_once(" - ")?;
    let pre: Vec<&str> = before.split_whitespace().collect();
    let post: Vec<&str> = after.split_whitespace().collect();
    if pre.len() < 6 || post.len() < 3 {
        return None;
    }
    let mount_point = unescape_mount(pre[4]);
    let fs_type = post[0].to_string();
    let source = unescape_mount(post[1]);
    let options: BTreeSet<String> = pre[5]
        .split(',')
        .chain(post[2].split(','))
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect();
    let readonly = options.contains("ro");
    let remote = is_remote(&source, &fs_type);
    let stats_path = if mount_point == "/" {
        ctx.scan_root.clone()
    } else {
        join_root(ctx, mount_point.trim_start_matches('/'))
    };
    let stats = statvfs(&stats_path).ok();
    let total_bytes = stats
        .as_ref()
        .map(|value| value.blocks().saturating_mul(value.fragment_size()));
    let available_bytes = stats.as_ref().map(|value| {
        value
            .blocks_available()
            .saturating_mul(value.fragment_size())
    });
    let total_inodes = stats.as_ref().map(|value| value.files());
    let available_inodes = stats.as_ref().map(|value| value.files_available());

    let identity = format!("{source}\0{mount_point}\0{fs_type}");
    let digest: String = Sha256::digest(identity.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some(FilesystemMount {
        asset_id: format!("mount-{}", &digest[..16]),
        parent_asset_id: None,
        source,
        mount_point,
        fs_type,
        options: options.into_iter().collect(),
        total_bytes,
        available_bytes,
        total_inodes,
        available_inodes,
        readonly,
        remote,
    })
}

fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

fn is_remote(source: &str, fs_type: &str) -> bool {
    matches!(
        fs_type,
        "nfs" | "nfs4" | "cifs" | "smb3" | "sshfs" | "ceph" | "glusterfs" | "9p" | "fuse.sshfs"
    ) || source.starts_with("//")
        || source.contains(":/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_mount_security_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("proc/self")).unwrap();
        fs::write(
            root.join("proc/self/mountinfo"),
            "36 25 0:32 / / rw,nosuid,nodev - overlay overlay rw,relatime\n\
             37 25 0:33 / /mnt/share ro - nfs4 server:/share ro,noexec\n",
        )
        .unwrap();

        let rows = collect(&ScanContext::at(root));
        assert_eq!(rows.len(), 2);
        let mounts: Vec<_> = rows
            .iter()
            .map(|row| match row {
                Asset::FilesystemMount(value) => value,
                _ => panic!("expected mount"),
            })
            .collect();
        let remote = mounts
            .iter()
            .find(|mount| mount.mount_point == "/mnt/share")
            .unwrap();
        assert!(remote.remote);
        assert!(remote.readonly);
        assert!(remote.options.iter().any(|value| value == "noexec"));
    }
}
