//! File-integrity monitoring sensor.
//!
//! Watches the configured directories (non-recursive in v1) and emits a
//! [`Detection::Fim`] on create/modify/delete/metadata changes, with a
//! best-effort SHA-256 of the new contents. Recursive watching is deferred.
//!
//! Per-OS backend, same output:
//! - **Linux** — `inotify` (via the safe `nix` wrappers).
//! - **Windows** — `ReadDirectoryChangesW` (via the safe `notify` crate, so
//!   agent-respond stays `unsafe_code = "deny"`-clean).
//!
//! Everything downstream (decide → respond → report → `FileIntegrityEvent`) is
//! platform-neutral. FIM never triggers an active response (`Detection::Fim` has
//! no file/pid/ip subject), so it always reports `action_taken = Logged`.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use agent_contract::{FimChange, Severity};
use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
use nix::errno::Errno;
#[cfg(target_os = "linux")]
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};

use crate::sensors::{Sensor, SensorEvent};
use crate::Detection;

/// FIM sensor over a fixed set of watched directories.
pub struct FimSensor {
    paths: Vec<PathBuf>,
}

impl FimSensor {
    /// Watch the given directories.
    pub fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }
}

impl Sensor for FimSensor {
    fn name(&self) -> &'static str {
        "fim"
    }

    fn preflight(&self) -> anyhow::Result<()> {
        self.preflight_backend()
    }

    fn run(
        self: Box<Self>,
        tx: Sender<SensorEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        self.run_inner(&tx, &shutdown).inspect_err(|e| {
            eprintln!("guard: fim sensor stopped: {e}");
        })
    }
}

// ---------------------------------------------------------------- Linux (inotify)

#[cfg(target_os = "linux")]
impl FimSensor {
    fn preflight_backend(&self) -> anyhow::Result<()> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
        let mask = watch_mask();
        let mut watched = 0usize;
        for path in &self.paths {
            if !path.exists() {
                continue;
            }
            match inotify.add_watch(path.as_path(), mask) {
                Ok(_) => watched += 1,
                Err(error) => {
                    eprintln!("guard: fim cannot watch {}: {error}", path.display());
                }
            }
        }
        ensure_all_paths_watched(self.paths.len(), watched)
    }

    fn run_inner(
        &self,
        tx: &Sender<SensorEvent>,
        shutdown: &Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
        let mask = watch_mask();

        let mut watches: Vec<(WatchDescriptor, PathBuf)> = Vec::new();
        for p in &self.paths {
            if !p.exists() {
                continue;
            }
            match inotify.add_watch(p.as_path(), mask) {
                Ok(wd) => watches.push((wd, p.clone())),
                Err(e) => eprintln!("guard: fim cannot watch {}: {e}", p.display()),
            }
        }
        ensure_all_paths_watched(self.paths.len(), watches.len())?;

        while !shutdown.load(Ordering::Relaxed) {
            match inotify.read_events() {
                Ok(events) => {
                    for ev in events {
                        if let Some(reason) = invalid_watch_reason(ev.mask) {
                            return Err(anyhow::anyhow!(
                                "inotify protection degraded ({reason}); restarting to re-arm watches"
                            ));
                        }
                        let Some(base) =
                            watches.iter().find(|(wd, _)| *wd == ev.wd).map(|(_, p)| p)
                        else {
                            continue;
                        };
                        // Directory-internal events that are themselves dirs add noise; skip.
                        if ev.mask.contains(AddWatchFlags::IN_ISDIR) {
                            continue;
                        }
                        let path = match &ev.name {
                            Some(name) => base.join(name),
                            None => base.clone(),
                        };
                        let path_str = path.to_string_lossy().into_owned();
                        let detection = Detection::Fim {
                            severity: severity_for(&path_str),
                            change: change_for(ev.mask),
                            hash_after: hash_file(&path),
                            hash_before: None, // best-effort in v1; see crate docs
                            path: path_str,
                        };
                        if tx.send(detection.into()).is_err() {
                            return Ok(()); // pipeline gone → stop
                        }
                    }
                }
                Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(200)),
                Err(e) => return Err(anyhow::anyhow!("inotify read: {e}")),
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn watch_mask() -> AddWatchFlags {
    AddWatchFlags::IN_CREATE
        | AddWatchFlags::IN_MODIFY
        | AddWatchFlags::IN_DELETE
        | AddWatchFlags::IN_DELETE_SELF
        | AddWatchFlags::IN_ATTRIB
        | AddWatchFlags::IN_MOVED_TO
        | AddWatchFlags::IN_MOVED_FROM
        | AddWatchFlags::IN_MOVE_SELF
        | AddWatchFlags::IN_UNMOUNT
        | AddWatchFlags::IN_CLOSE_WRITE
}

#[cfg(target_os = "linux")]
fn invalid_watch_reason(mask: AddWatchFlags) -> Option<&'static str> {
    if mask.contains(AddWatchFlags::IN_Q_OVERFLOW) {
        Some("event queue overflow")
    } else if mask.contains(AddWatchFlags::IN_UNMOUNT) {
        Some("watched filesystem unmounted")
    } else if mask.contains(AddWatchFlags::IN_DELETE_SELF) {
        Some("watched path deleted")
    } else if mask.contains(AddWatchFlags::IN_MOVE_SELF) {
        Some("watched path moved")
    } else if mask.contains(AddWatchFlags::IN_IGNORED) {
        Some("kernel removed a watch")
    } else {
        None
    }
}

#[cfg(target_os = "linux")]
fn change_for(mask: AddWatchFlags) -> FimChange {
    if mask.intersects(AddWatchFlags::IN_CREATE | AddWatchFlags::IN_MOVED_TO) {
        FimChange::Created
    } else if mask.intersects(AddWatchFlags::IN_DELETE | AddWatchFlags::IN_MOVED_FROM) {
        FimChange::Deleted
    } else if mask.contains(AddWatchFlags::IN_ATTRIB) {
        FimChange::Metadata
    } else {
        FimChange::Modified
    }
}

/// Changes to credential / boot paths are high severity; others medium.
#[cfg(target_os = "linux")]
fn severity_for(path: &str) -> Severity {
    const HIGH: &[&str] = &["/etc/passwd", "/etc/shadow", "/etc/sudoers"];
    if HIGH.contains(&path) || path.starts_with("/boot") {
        Severity::High
    } else {
        Severity::Medium
    }
}

// ------------------------------------------------ Windows (ReadDirectoryChangesW)

#[cfg(target_os = "windows")]
impl FimSensor {
    fn preflight_backend(&self) -> anyhow::Result<()> {
        use notify::{RecursiveMode, Watcher};

        let mut watcher = notify::recommended_watcher(|_result: notify::Result<notify::Event>| {})?;
        let mut watched = 0usize;
        for path in &self.paths {
            if !path.exists() {
                continue;
            }
            match watcher.watch(path.as_path(), RecursiveMode::NonRecursive) {
                Ok(()) => watched += 1,
                Err(error) => {
                    eprintln!("guard: fim cannot watch {}: {error}", path.display());
                }
            }
        }
        ensure_all_paths_watched(self.paths.len(), watched)
    }

    fn run_inner(
        &self,
        tx: &Sender<SensorEvent>,
        shutdown: &Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        use std::sync::mpsc::RecvTimeoutError;

        use notify::{RecursiveMode, Watcher};

        // The notify watcher delivers events on its own thread; bridge them into a
        // std channel we poll with a timeout so the shutdown flag is observed
        // (an AtomicBool can't wake a blocked wait).
        let (ntx, nrx) = std::sync::mpsc::channel();
        let mut watcher = notify::recommended_watcher(move |res| {
            let _ = ntx.send(res);
        })?;

        let mut watched = 0usize;
        for p in &self.paths {
            if !p.exists() {
                continue;
            }
            // Non-recursive in v1, matching the Linux sensor.
            match watcher.watch(p.as_path(), RecursiveMode::NonRecursive) {
                Ok(()) => watched += 1,
                Err(e) => eprintln!("guard: fim cannot watch {}: {e}", p.display()),
            }
        }
        ensure_all_paths_watched(self.paths.len(), watched)?;

        while !shutdown.load(Ordering::Relaxed) {
            match nrx.recv_timeout(Duration::from_millis(200)) {
                Ok(Ok(event)) => {
                    let Some(change) = change_for(&event.kind) else {
                        continue;
                    };
                    for path in &event.paths {
                        let path_str = path.to_string_lossy().into_owned();
                        let hash_after = if matches!(change, FimChange::Deleted) {
                            None // file is gone
                        } else {
                            hash_file(path)
                        };
                        let detection = Detection::Fim {
                            severity: severity_for(&path_str),
                            change,
                            hash_after,
                            hash_before: None, // best-effort in v1; see crate docs
                            path: path_str,
                        };
                        if tx.send(detection.into()).is_err() {
                            return Ok(()); // pipeline gone → stop
                        }
                    }
                }
                // Buffer overflow / rescan-required means coverage can no
                // longer be proven complete. Restart and re-arm every watch.
                Ok(Err(e)) => return Err(anyhow::anyhow!("fim watch backend error: {e}")),
                Err(RecvTimeoutError::Timeout) => {} // re-check shutdown
                Err(RecvTimeoutError::Disconnected) => {
                    anyhow::bail!("fim watch backend disconnected unexpectedly")
                }
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "windows")]
fn change_for(kind: &notify::EventKind) -> Option<FimChange> {
    use notify::event::{ModifyKind, RenameMode};
    use notify::EventKind;

    match kind {
        EventKind::Create(_) => Some(FimChange::Created),
        EventKind::Remove(_) => Some(FimChange::Deleted),
        // ReadDirectoryChangesW reports a rename as an OLD/NEW pair; map each
        // independently (consistent with the Linux MOVED_FROM/MOVED_TO mapping).
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => Some(FimChange::Deleted),
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => Some(FimChange::Created),
        EventKind::Modify(ModifyKind::Metadata(_)) => Some(FimChange::Metadata),
        EventKind::Modify(_) => Some(FimChange::Modified),
        _ => None, // Access / Any / Other → ignore
    }
}

/// Changes to registry hives / hosts / scheduled tasks are high severity; others
/// medium. Case-insensitive (Windows paths are case-insensitive).
#[cfg(target_os = "windows")]
fn severity_for(path: &str) -> Severity {
    let lower = path.to_ascii_lowercase().replace('/', "\\");
    const HIGH_PREFIXES: &[&str] = &[
        "c:\\windows\\system32\\config\\", // SAM / SYSTEM / SECURITY hives
        "c:\\windows\\system32\\drivers\\etc\\", // hosts / lmhosts
        "c:\\windows\\system32\\tasks\\",  // scheduled tasks
    ];
    if HIGH_PREFIXES.iter().any(|p| lower.starts_with(p)) {
        Severity::High
    } else {
        Severity::Medium
    }
}

// ------------------------------------------------------------------------ shared

fn ensure_all_paths_watched(configured: usize, watched: usize) -> anyhow::Result<()> {
    anyhow::ensure!(
        configured > 0 && watched == configured,
        "fim watches {watched}/{configured} configured path(s); refusing partial protection"
    );
    Ok(())
}

/// Bound hashing work for one FIM event. Large files are still reported, only
/// the best-effort digest is omitted.
const MAX_FIM_HASH_BYTES: u64 = 64 * 1024 * 1024;

fn hash_file(path: &std::path::Path) -> Option<String> {
    use std::io::Read as _;

    let mut file = std::fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_FIM_HASH_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64)?;
        if total > MAX_FIM_HASH_BYTES {
            return None;
        }
        hasher.update(&buffer[..read]);
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
}

#[cfg(test)]
mod hash_tests {
    use super::*;

    #[test]
    fn hashes_small_files_and_skips_oversized_sparse_files() {
        let dir = tempfile::tempdir().unwrap();
        let small = dir.path().join("small");
        std::fs::write(&small, b"abc").unwrap();
        assert_eq!(
            hash_file(&small).as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );

        let large = dir.path().join("large-sparse");
        std::fs::File::create(&large)
            .unwrap()
            .set_len(MAX_FIM_HASH_BYTES + 1)
            .unwrap();
        assert!(hash_file(&large).is_none());
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn credential_and_boot_paths_are_high_severity() {
        assert_eq!(severity_for("/etc/passwd"), Severity::High);
        assert_eq!(severity_for("/etc/shadow"), Severity::High);
        assert_eq!(severity_for("/etc/sudoers"), Severity::High);
        assert_eq!(severity_for("/boot/vmlinuz"), Severity::High);
    }

    #[test]
    fn ordinary_paths_are_medium_severity() {
        assert_eq!(severity_for("/etc/hosts"), Severity::Medium);
        assert_eq!(severity_for("/usr/bin/ls"), Severity::Medium);
    }

    #[test]
    fn preflight_rejects_missing_watch_path() {
        let root = tempfile::tempdir().unwrap();
        let sensor = FimSensor::new(vec![root.path().join("missing")]);
        let error = sensor
            .preflight()
            .expect_err("missing path must fail ready preflight");
        assert!(error.to_string().contains("watches 0/1"));
    }

    #[test]
    fn change_kind_classification() {
        assert_eq!(change_for(AddWatchFlags::IN_CREATE), FimChange::Created);
        assert_eq!(change_for(AddWatchFlags::IN_MOVED_TO), FimChange::Created);
        assert_eq!(change_for(AddWatchFlags::IN_DELETE), FimChange::Deleted);
        assert_eq!(change_for(AddWatchFlags::IN_MOVED_FROM), FimChange::Deleted);
        assert_eq!(change_for(AddWatchFlags::IN_ATTRIB), FimChange::Metadata);
        assert_eq!(change_for(AddWatchFlags::IN_MODIFY), FimChange::Modified);
    }

    #[test]
    fn invalidated_or_overflowed_watch_is_fatal() {
        for mask in [
            AddWatchFlags::IN_IGNORED,
            AddWatchFlags::IN_Q_OVERFLOW,
            AddWatchFlags::IN_UNMOUNT,
            AddWatchFlags::IN_DELETE_SELF,
            AddWatchFlags::IN_MOVE_SELF,
        ] {
            assert!(invalid_watch_reason(mask).is_some());
        }
        assert!(invalid_watch_reason(AddWatchFlags::IN_MODIFY).is_none());
    }
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;
    use notify::event::{CreateKind, DataChange, ModifyKind, RemoveKind, RenameMode};
    use notify::EventKind;

    #[test]
    fn high_value_windows_paths_are_high_severity() {
        assert_eq!(
            severity_for("C:\\Windows\\System32\\config\\SAM"),
            Severity::High
        );
        assert_eq!(
            severity_for("C:\\Windows\\System32\\drivers\\etc\\hosts"),
            Severity::High
        );
        assert_eq!(severity_for("C:\\Users\\me\\file.txt"), Severity::Medium);
    }

    #[test]
    fn change_kind_classification() {
        assert_eq!(
            change_for(&EventKind::Create(CreateKind::Any)),
            Some(FimChange::Created)
        );
        assert_eq!(
            change_for(&EventKind::Remove(RemoveKind::Any)),
            Some(FimChange::Deleted)
        );
        assert_eq!(
            change_for(&EventKind::Modify(ModifyKind::Name(RenameMode::From))),
            Some(FimChange::Deleted)
        );
        assert_eq!(
            change_for(&EventKind::Modify(ModifyKind::Name(RenameMode::To))),
            Some(FimChange::Created)
        );
        assert_eq!(
            change_for(&EventKind::Modify(ModifyKind::Data(DataChange::Any))),
            Some(FimChange::Modified)
        );
    }

    // FIM smoke test (windows-latest only; needs no admin — own tempdir): the real
    // ReadDirectoryChangesW backend must produce a Detection::Fim for a file we
    // create/modify/delete under a watched directory.
    #[test]
    fn fim_smoke_detects_file_changes() {
        use std::thread;
        use std::time::Instant;

        let dir = tempfile::tempdir().unwrap();
        let watched = dir.path().to_path_buf();

        let (tx, rx) = std::sync::mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let sensor: Box<FimSensor> = Box::new(FimSensor::new(vec![watched.clone()]));
        let sd = Arc::clone(&shutdown);
        let handle = thread::spawn(move || sensor.run(tx, sd));

        // Give the watcher a moment to arm before mutating the directory.
        thread::sleep(Duration::from_millis(400));
        let probe = watched.join("probe.txt");
        std::fs::write(&probe, b"hello").unwrap();
        std::fs::write(&probe, b"hello world").unwrap();
        std::fs::remove_file(&probe).unwrap();

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut saw_probe = false;
        while Instant::now() < deadline {
            match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(event) => {
                    if let Detection::Fim { path, .. } = event.detection {
                        if path.contains("probe.txt") {
                            saw_probe = true;
                            break;
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        shutdown.store(true, Ordering::SeqCst);
        let _ = handle.join();
        assert!(saw_probe, "expected a Detection::Fim for probe.txt");
    }
}
