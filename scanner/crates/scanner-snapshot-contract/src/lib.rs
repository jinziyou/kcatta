//! Snapshot backend contract for remote block-device snapshots.
//!
//! Concrete backends (`scanner-snapshot-lvm`, future Btrfs/ZFS) implement
//! [`SnapshotBackend`]. The orchestrator (`scanner-remote`) provides a
//! [`RemoteExec`] (an SSH session) and consumes the resulting
//! [`RemoteSnapshot`], whose `Drop` impl performs idempotent cleanup.
//!
//! This crate intentionally contains **no SSH or transport code**: it stays
//! at the trait / data layer so backends can be unit-tested with mocked
//! [`RemoteExec`].

use std::sync::Arc;

/// Result of a single remote command execution.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub status: i32,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == 0
    }
}

/// Minimal remote command executor. The orchestrator implements this over SSH.
///
/// Implementations must:
/// - run `cmd` through a shell on the remote host (single string, so callers
///   are responsible for quoting),
/// - return non-zero exits as `Ok(output)` (not `Err`), so backends can probe
///   for missing commands without unwrapping panics.
pub trait RemoteExec: Send + Sync {
    fn exec(&self, cmd: &str) -> anyhow::Result<CommandOutput>;

    /// Human label (e.g. `user@host`) for logs.
    fn target(&self) -> &str;
}

/// RAII handle for a snapshot living on the remote host.
///
/// `Drop` runs `cleanup_commands` in reverse order. Failures are logged to
/// `stderr` and swallowed (drop must not panic). Backends should design
/// cleanup commands to be **idempotent** so that re-runs after a stale
/// process tolerate partially-removed state.
pub struct RemoteSnapshot {
    /// Backend identifier (`"lvm"`, `"btrfs"`, ...).
    pub backend: &'static str,
    /// Snapshot identifier (used to derive names, paths, logs).
    pub id: String,
    /// Remote block-device or file path that can be exposed to a data channel
    /// (e.g. `qemu-nbd -c /dev/nbdX <device_path>`).
    pub device_path: String,

    exec: Arc<dyn RemoteExec>,
    cleanup_commands: Vec<String>,
}

impl RemoteSnapshot {
    pub fn new(
        backend: &'static str,
        id: String,
        device_path: String,
        exec: Arc<dyn RemoteExec>,
        cleanup_commands: Vec<String>,
    ) -> Self {
        Self {
            backend,
            id,
            device_path,
            exec,
            cleanup_commands,
        }
    }

    /// Borrow the executor (for orchestrators that want to issue extra
    /// commands using the same SSH session).
    pub fn exec(&self) -> &Arc<dyn RemoteExec> {
        &self.exec
    }
}

impl std::fmt::Debug for RemoteSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSnapshot")
            .field("backend", &self.backend)
            .field("id", &self.id)
            .field("device_path", &self.device_path)
            .field("cleanup_steps", &self.cleanup_commands.len())
            .finish()
    }
}

impl Drop for RemoteSnapshot {
    fn drop(&mut self) {
        for cmd in self.cleanup_commands.iter().rev() {
            match self.exec.exec(cmd) {
                Ok(out) if out.success() => {}
                Ok(out) => eprintln!(
                    "[scanner-snapshot-{}] cleanup non-zero exit ({}) on {}: {}\nstderr: {}",
                    self.backend,
                    out.status,
                    self.exec.target(),
                    cmd,
                    out.stderr.trim(),
                ),
                Err(e) => eprintln!(
                    "[scanner-snapshot-{}] cleanup error on {}: {}: {:#}",
                    self.backend,
                    self.exec.target(),
                    cmd,
                    e,
                ),
            }
        }
    }
}

/// Backend-specific options consumed by [`SnapshotBackend::create_snapshot`].
#[derive(Debug, Clone)]
pub struct SnapshotRequest<'a> {
    /// Backend-specific source identifier:
    /// - LVM: `/dev/<vg>/<lv>`
    /// - Btrfs (future): subvolume path
    /// - ZFS (future): `pool/dataset`
    pub source: &'a str,

    /// Optional mount point on the remote host to `fsfreeze -f / -u` around
    /// snapshot creation for stronger crash-consistency. `None` skips freeze.
    pub freeze_mount: Option<&'a str>,

    /// Stable id segment (used in snapshot names; backend may further sanitize).
    pub id: &'a str,
}

/// Snapshot backend contract. One impl per snapshot technology.
pub trait SnapshotBackend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Probe whether the remote host supports this backend (required commands
    /// installed, kernel modules loadable, ...). Must not mutate remote state.
    fn probe(&self, exec: &dyn RemoteExec) -> anyhow::Result<bool>;

    /// Create a read-only snapshot of `req.source` on the remote host.
    /// The returned [`RemoteSnapshot`] cleans itself up on drop.
    fn create_snapshot(
        &self,
        exec: Arc<dyn RemoteExec>,
        req: &SnapshotRequest<'_>,
    ) -> anyhow::Result<RemoteSnapshot>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Mock executor that records issued commands and replies from a script.
    pub struct MockExec {
        pub log: Mutex<Vec<String>>,
        pub replies: Mutex<Vec<CommandOutput>>,
    }

    impl MockExec {
        pub fn new(replies: Vec<CommandOutput>) -> Self {
            Self {
                log: Mutex::new(Vec::new()),
                replies: Mutex::new(replies),
            }
        }
    }

    impl RemoteExec for MockExec {
        fn exec(&self, cmd: &str) -> anyhow::Result<CommandOutput> {
            self.log.lock().unwrap().push(cmd.to_string());
            let mut replies = self.replies.lock().unwrap();
            if replies.is_empty() {
                Ok(CommandOutput {
                    stdout: String::new(),
                    stderr: String::new(),
                    status: 0,
                })
            } else {
                Ok(replies.remove(0))
            }
        }
        fn target(&self) -> &str {
            "mock@localhost"
        }
    }

    #[test]
    fn cleanup_runs_in_reverse_on_drop() {
        let exec = Arc::new(MockExec::new(Vec::new()));
        {
            let _snap = RemoteSnapshot::new(
                "lvm",
                "abc".into(),
                "/dev/vg/snap-abc".into(),
                exec.clone(),
                vec!["step-1".into(), "step-2".into(), "step-3".into()],
            );
        }
        let log = exec.log.lock().unwrap();
        assert_eq!(*log, vec!["step-3", "step-2", "step-1"]);
    }

    #[test]
    fn cleanup_failures_are_swallowed() {
        let exec = Arc::new(MockExec::new(vec![CommandOutput {
            stdout: String::new(),
            stderr: "boom".into(),
            status: 1,
        }]));
        let snap = RemoteSnapshot::new(
            "lvm",
            "x".into(),
            "/dev/vg/snap-x".into(),
            exec.clone(),
            vec!["only-step".into()],
        );
        drop(snap);
        assert_eq!(exec.log.lock().unwrap().len(), 1);
    }
}
