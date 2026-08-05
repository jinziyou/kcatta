//! Live Linux filesystem mounts from `/proc/self/mountinfo`.

#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
#[cfg(target_os = "linux")]
use std::fs;

#[cfg(target_os = "linux")]
use agent_contract::FilesystemMount;
use agent_contract::{Asset, CollectionKind, CollectionRun, CollectionRunStatus};
#[cfg(target_os = "linux")]
use nix::sys::statvfs::statvfs;
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
use crate::root::join_root;
use crate::ScanContext;

#[cfg(target_os = "linux")]
const MAX_MOUNTS: usize = 512;

/// Collect mounted filesystems and coverage from one `mountinfo` read.
/// Offline/image roots without mountinfo emit a failed zero run.
#[cfg(target_os = "linux")]
pub(crate) fn collect_with_coverage(ctx: &ScanContext) -> (Vec<Asset>, CollectionRun) {
    let Some(snapshot) = read_mounts(ctx) else {
        return (
            Vec::new(),
            collection_run(
                CollectionRunStatus::Failed,
                Some("mountinfo_unavailable"),
                0,
            ),
        );
    };
    let (status, reason) = coverage_from_snapshot(&snapshot);
    let assets = snapshot
        .rows
        .into_iter()
        .map(Asset::FilesystemMount)
        .collect::<Vec<_>>();
    let record_count = assets.len();
    (assets, collection_run(status, reason, record_count))
}

/// Windows and other non-Linux targets have no `/proc/self/mountinfo` source.
/// Keep the category visible without compiling Linux-only filesystem APIs.
#[cfg(not(target_os = "linux"))]
pub(crate) fn collect_with_coverage(_ctx: &ScanContext) -> (Vec<Asset>, CollectionRun) {
    (
        Vec::new(),
        collection_run(
            CollectionRunStatus::Failed,
            Some("mountinfo_unavailable"),
            0,
        ),
    )
}

#[cfg(target_os = "linux")]
struct MountRead {
    rows: Vec<FilesystemMount>,
    discovered_count: usize,
    malformed_rows: usize,
}

#[cfg(target_os = "linux")]
fn coverage_from_snapshot(snapshot: &MountRead) -> (CollectionRunStatus, Option<&'static str>) {
    if snapshot.malformed_rows > 0 {
        return (CollectionRunStatus::Partial, Some("mountinfo_rows_skipped"));
    }
    if snapshot.discovered_count > MAX_MOUNTS {
        return (CollectionRunStatus::Partial, Some("mount_limit_reached"));
    }
    (CollectionRunStatus::Complete, None)
}

fn collection_run(
    status: CollectionRunStatus,
    reason: Option<&str>,
    record_count: usize,
) -> CollectionRun {
    CollectionRun {
        collector: CollectionKind::FilesystemMount,
        status,
        record_count,
        reason: reason.map(str::to_string),
    }
}

#[cfg(target_os = "linux")]
fn read_mounts(ctx: &ScanContext) -> Option<MountRead> {
    let text = fs::read_to_string(join_root(ctx, "proc/self/mountinfo")).ok()?;
    let mut malformed_rows = 0;
    let mut rows: Vec<FilesystemMount> = text
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let row = parse_line(ctx, line);
            if row.is_none() {
                malformed_rows += 1;
            }
            row
        })
        .collect();
    rows.sort_by(|left, right| left.mount_point.cmp(&right.mount_point));
    rows.dedup_by(|left, right| {
        left.mount_point == right.mount_point
            && left.source == right.source
            && left.fs_type == right.fs_type
    });
    let discovered_count = rows.len();
    rows.truncate(MAX_MOUNTS);
    Some(MountRead {
        rows,
        discovered_count,
        malformed_rows,
    })
}

#[cfg(target_os = "linux")]
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

#[cfg(target_os = "linux")]
fn unescape_mount(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
}

#[cfg(target_os = "linux")]
fn is_remote(source: &str, fs_type: &str) -> bool {
    matches!(
        fs_type,
        "nfs" | "nfs4" | "cifs" | "smb3" | "sshfs" | "ceph" | "glusterfs" | "9p" | "fuse.sshfs"
    ) || source.starts_with("//")
        || source.contains(":/")
}

#[cfg(all(test, target_os = "linux"))]
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

        let (rows, run) = collect_with_coverage(&ScanContext::at(root));
        assert_eq!(run.record_count, rows.len());
        assert_eq!(run.status, CollectionRunStatus::Complete);
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

    #[test]
    fn coverage_distinguishes_missing_zero_malformed_and_limited_mountinfo() {
        let missing = tempfile::tempdir().unwrap();
        let (assets, run) = collect_with_coverage(&ScanContext::at(missing.path()));
        assert!(assets.is_empty());
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Failed);
        assert_eq!(run.reason.as_deref(), Some("mountinfo_unavailable"));

        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("proc/self")).unwrap();
        fs::write(root.path().join("proc/self/mountinfo"), "").unwrap();
        let (assets, run) = collect_with_coverage(&ScanContext::at(root.path()));
        assert!(assets.is_empty());
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Complete);
        assert!(run.reason.is_none());

        fs::write(root.path().join("proc/self/mountinfo"), "malformed\n").unwrap();
        let (assets, run) = collect_with_coverage(&ScanContext::at(root.path()));
        assert!(assets.is_empty());
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Partial);
        assert_eq!(run.reason.as_deref(), Some("mountinfo_rows_skipped"));

        let rows = (0..MAX_MOUNTS)
            .map(|index| {
                format!(
                    "{} 25 0:{} / /mnt/{index} rw - tmpfs tmpfs rw\n",
                    index + 30,
                    index + 30
                )
            })
            .collect::<String>();
        fs::write(root.path().join("proc/self/mountinfo"), rows).unwrap();
        let (assets, run) = collect_with_coverage(&ScanContext::at(root.path()));
        assert_eq!(assets.len(), MAX_MOUNTS);
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Complete);
        assert!(run.reason.is_none());

        let rows = (0..=MAX_MOUNTS)
            .map(|index| {
                format!(
                    "{} 25 0:{} / /mnt/{index} rw - tmpfs tmpfs rw\n",
                    index + 30,
                    index + 30
                )
            })
            .collect::<String>();
        fs::write(root.path().join("proc/self/mountinfo"), rows).unwrap();
        let (assets, run) = collect_with_coverage(&ScanContext::at(root.path()));
        assert_eq!(assets.len(), MAX_MOUNTS);
        assert_eq!(run.record_count, assets.len());
        assert_eq!(run.status, CollectionRunStatus::Partial);
        assert_eq!(run.reason.as_deref(), Some("mount_limit_reached"));
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod non_linux_tests {
    use super::*;

    #[test]
    fn mountinfo_source_is_explicitly_unavailable() {
        let (assets, run) = collect_with_coverage(&ScanContext::default());
        assert!(assets.is_empty());
        assert_eq!(run.collector, CollectionKind::FilesystemMount);
        assert_eq!(run.status, CollectionRunStatus::Failed);
        assert_eq!(run.reason.as_deref(), Some("mountinfo_unavailable"));
    }
}
