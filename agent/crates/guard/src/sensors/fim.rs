//! File-integrity monitoring sensor.
//!
//! Watches the configured directories (non-recursive in v1) and emits a
//! [`Detection::Fim`] on create/modify/delete/metadata changes, with a
//! best-effort SHA-256 of the new contents. Recursive watching is deferred.
//!
//! Per-OS backend, same output:
//! - **Linux** — `inotify` (via the safe `nix` wrappers).
//! - **Windows** — `ReadDirectoryChangesW` (via the safe `notify` crate, so
//!   agent-guard stays `unsafe_code = "deny"`-clean).
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

use crate::event::Detection;
use crate::sensors::Sensor;

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

    fn run(
        self: Box<Self>,
        tx: Sender<Detection>,
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
    fn run_inner(&self, tx: &Sender<Detection>, shutdown: &Arc<AtomicBool>) -> anyhow::Result<()> {
        let inotify = Inotify::init(InitFlags::IN_NONBLOCK | InitFlags::IN_CLOEXEC)?;
        let mask = AddWatchFlags::IN_CREATE
            | AddWatchFlags::IN_MODIFY
            | AddWatchFlags::IN_DELETE
            | AddWatchFlags::IN_ATTRIB
            | AddWatchFlags::IN_MOVED_TO
            | AddWatchFlags::IN_MOVED_FROM
            | AddWatchFlags::IN_CLOSE_WRITE;

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
        if watches.is_empty() {
            eprintln!("guard: fim has no watchable paths; sensor idle");
        }

        while !shutdown.load(Ordering::Relaxed) {
            match inotify.read_events() {
                Ok(events) => {
                    for ev in events {
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
                        if tx.send(detection).is_err() {
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
    fn run_inner(&self, tx: &Sender<Detection>, shutdown: &Arc<AtomicBool>) -> anyhow::Result<()> {
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
        if watched == 0 {
            eprintln!("guard: fim has no watchable paths; sensor idle");
        }

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
                        if tx.send(detection).is_err() {
                            return Ok(()); // pipeline gone → stop
                        }
                    }
                }
                // A watch-backend error (e.g. buffer overflow / rescan-required) is
                // recoverable: log and keep watching, never kill the sensor.
                Ok(Err(e)) => eprintln!("guard: fim watch error: {e}"),
                Err(RecvTimeoutError::Timeout) => {} // re-check shutdown
                Err(RecvTimeoutError::Disconnected) => return Ok(()),
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

fn hash_file(path: &std::path::Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Some(
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect(),
    )
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
    fn change_kind_classification() {
        assert_eq!(change_for(AddWatchFlags::IN_CREATE), FimChange::Created);
        assert_eq!(change_for(AddWatchFlags::IN_MOVED_TO), FimChange::Created);
        assert_eq!(change_for(AddWatchFlags::IN_DELETE), FimChange::Deleted);
        assert_eq!(change_for(AddWatchFlags::IN_MOVED_FROM), FimChange::Deleted);
        assert_eq!(change_for(AddWatchFlags::IN_ATTRIB), FimChange::Metadata);
        assert_eq!(change_for(AddWatchFlags::IN_MODIFY), FimChange::Modified);
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
                Ok(Detection::Fim { path, .. }) if path.contains("probe.txt") => {
                    saw_probe = true;
                    break;
                }
                Ok(_) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        shutdown.store(true, Ordering::SeqCst);
        let _ = handle.join();
        assert!(saw_probe, "expected a Detection::Fim for probe.txt");
    }
}
