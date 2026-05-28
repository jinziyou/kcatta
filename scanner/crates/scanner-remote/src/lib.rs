//! Agentless remote scanning: SSH + snapshot backend + NBD channel +
//! `scanner-asset`.
//!
//! End-to-end pipeline:
//! 1. SSH into the target with connection multiplexing
//!    ([`ssh::SshSession`]).
//! 2. Probe and invoke a snapshot backend (currently [`scanner_snapshot_lvm`])
//!    to get a read-only block-device snapshot on the remote.
//! 3. Expose that snapshot via `qemu-nbd` on the remote, tunnel the port
//!    over SSH, attach it locally with `nbd-client`, mount it read-only
//!    ([`nbd::NbdMount`]).
//! 4. Hand the mount path to [`scanner_asset::run_static_scan`].
//! 5. Tear everything down in reverse on drop, even on error.

pub mod nbd;
pub mod ssh;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Context};
use scanner_asset::{run_static_scan, ScanOptions, ScanOutput, ScanTarget};
use scanner_snapshot_contract::{RemoteExec, SnapshotBackend, SnapshotRequest};
use scanner_snapshot_lvm::LvmBackend;
use uuid::Uuid;

use crate::nbd::{NbdMount, NbdOptions};
use crate::ssh::{SshOptions, SshSession};

/// User-facing options for one remote scan.
#[derive(Debug, Clone)]
pub struct RemoteScanOptions {
    pub ssh: SshOptions,
    pub backend: BackendSelection,
    /// Optional mount point on the target to `fsfreeze -f / -u` around
    /// snapshot creation for stronger crash-consistency. `None` skips.
    pub freeze_mount: Option<String>,
    pub nbd: NbdOptions,
    /// Output directory for per-asset JSON (forwarded to scanner-asset).
    pub output_dir: PathBuf,
    pub target: ScanTarget,
    /// Optional stable id for snapshot naming; auto-generated if `None`.
    pub task_id: Option<String>,
}

#[derive(Debug, Clone)]
pub enum BackendSelection {
    /// LVM snapshot of `source` (e.g. `/dev/vg0/root`).
    Lvm { source: String },
}

#[derive(Debug, Clone)]
pub struct RemoteScanReport {
    pub task_id: String,
    pub scan: ScanOutput,
}

pub fn run_remote_scan(opts: RemoteScanOptions) -> anyhow::Result<RemoteScanReport> {
    let task_id = opts
        .task_id
        .clone()
        .unwrap_or_else(|| short_id(Uuid::new_v4()));

    let session: Arc<SshSession> =
        Arc::new(SshSession::connect(opts.ssh.clone()).context("establish ssh session")?);
    let exec: Arc<dyn RemoteExec> = session.clone();

    let snapshot = match &opts.backend {
        BackendSelection::Lvm { source } => {
            let backend = LvmBackend::new();
            if !backend.probe(&*exec).context("probe LVM backend")? {
                bail!(
                    "LVM tools (lvcreate/lvremove/lvs) not found on target {}",
                    exec.target()
                );
            }
            let req = SnapshotRequest {
                source,
                freeze_mount: opts.freeze_mount.as_deref(),
                id: &task_id,
            };
            backend
                .create_snapshot(exec.clone(), &req)
                .context("create LVM snapshot")?
        }
    };

    let mount = NbdMount::establish(&session, &snapshot, &opts.nbd)
        .context("establish NBD channel")?;

    let scan_options = ScanOptions {
        root: mount.mount_path().to_path_buf(),
        target: opts.target,
    };
    let scan = run_static_scan(&scan_options, &opts.output_dir).context("run static scan")?;

    // Explicit drop order (resource-most-recent → oldest), documenting intent:
    drop(mount);
    drop(snapshot);
    drop(session);

    Ok(RemoteScanReport { task_id, scan })
}

fn short_id(uuid: Uuid) -> String {
    uuid.simple().to_string()[..8].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_id_is_eight_hex_chars() {
        let id = short_id(Uuid::nil());
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
