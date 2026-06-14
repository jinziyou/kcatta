//! File-integrity monitoring sensor (inotify).
//!
//! Watches the configured directories (non-recursive in v1) and emits a
//! [`Detection::Fim`] on create/modify/delete/metadata changes, with a
//! best-effort SHA-256 of the new contents. Recursive watching is deferred.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use agent_contract::{FimChange, Severity};
use nix::errno::Errno;
use nix::sys::inotify::{AddWatchFlags, InitFlags, Inotify, WatchDescriptor};
use sha2::{Digest, Sha256};

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

impl Sensor for FimSensor {
    fn name(&self) -> &'static str {
        "fim"
    }

    fn run(self: Box<Self>, tx: Sender<Detection>, shutdown: Arc<AtomicBool>) {
        if let Err(e) = self.run_inner(&tx, &shutdown) {
            eprintln!("guard: fim sensor stopped: {e}");
        }
    }
}

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
fn severity_for(path: &str) -> Severity {
    const HIGH: &[&str] = &["/etc/passwd", "/etc/shadow", "/etc/sudoers"];
    if HIGH.contains(&path) || path.starts_with("/boot") {
        Severity::High
    } else {
        Severity::Medium
    }
}

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
