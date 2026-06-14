//! On-access malware sensor (fanotify + built-in signature scanner).
//!
//! Marks the configured mounts for open events. In enforce mode it uses
//! `FAN_OPEN_PERM` and answers `FAN_ALLOW`/`FAN_DENY` synchronously; in monitor
//! mode it uses `FAN_OPEN` (notify only). Either way it matches the opened file
//! against [`agent_host::malware`]'s signature set (the same engine the host
//! static scan uses) and emits a [`Detection::Malware`] on a hit.
//!
//! Safety (P0-2): the path **fails open** — any error or oversized file answers
//! `FAN_ALLOW` so a stalled scanner can never wedge the system. The file is read
//! via `/proc/self/fd/N` (fresh offset, on the procfs mount, so it does not
//! re-trigger the marked mount's events).

use std::os::fd::{AsRawFd, BorrowedFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use agent_contract::Severity;
use agent_host::malware::{scan_bytes, SignatureSet, DEFAULT_MAX_FILE_SIZE};
use nix::errno::Errno;
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};

use crate::config::{Mode, OnAccessConfig};
use crate::event::Detection;
use crate::sensors::Sensor;

/// On-access scan sensor.
pub struct OnAccessSensor {
    config: OnAccessConfig,
    enforce: bool,
}

impl OnAccessSensor {
    /// Build the sensor; `enforce` (mode == [`Mode::Enforce`]) selects blocking
    /// `FAN_OPEN_PERM` vs notify-only `FAN_OPEN`.
    pub fn new(config: OnAccessConfig, mode: Mode) -> Self {
        Self {
            config,
            enforce: mode == Mode::Enforce,
        }
    }

    fn run_inner(&self, tx: &Sender<Detection>, shutdown: &Arc<AtomicBool>) -> anyhow::Result<()> {
        let mut signatures = SignatureSet::builtin();
        if let Some(path) = &self.config.signatures {
            signatures.load_extra(path)?;
        }

        let group = Fanotify::init(
            InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_NONBLOCK | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY,
        )?;
        let event_mask = if self.enforce {
            MaskFlags::FAN_OPEN_PERM
        } else {
            MaskFlags::FAN_OPEN
        };

        let mut marked = 0usize;
        for path in &self.config.paths {
            match group.mark(
                MarkFlags::FAN_MARK_ADD | MarkFlags::FAN_MARK_MOUNT,
                event_mask,
                // `dirfd = AT_FDCWD` with an absolute mount path: nix 0.31's `mark`
                // takes a non-optional `AsFd` dirfd, and FAN_MARK_MOUNT resolves the
                // path against the filesystem, so AT_FDCWD is the conventional fd here.
                nix::fcntl::AT_FDCWD,
                Some(path.as_path()),
            ) {
                Ok(()) => marked += 1,
                Err(e) => eprintln!("guard: onaccess cannot mark {}: {e}", path.display()),
            }
        }
        if marked == 0 {
            eprintln!("guard: onaccess marked no paths; sensor idle");
        }

        while !shutdown.load(Ordering::Relaxed) {
            match group.read_events() {
                Ok(events) => {
                    for event in events {
                        let Some(fd) = event.fd() else { continue }; // queue overflow marker
                        let verdict = scan_fd(&signatures, fd);

                        // Answer the kernel FIRST (perm events block the opener).
                        if self.enforce {
                            let response = if verdict.is_some() {
                                Response::FAN_DENY
                            } else {
                                Response::FAN_ALLOW // fail-open on clean / error / oversize
                            };
                            let _ = group.write_response(FanotifyResponse::new(fd, response));
                        }

                        if let Some(signature) = verdict {
                            let pid = event.pid();
                            let detection = Detection::Malware {
                                severity: Severity::Critical,
                                path: fd_path(fd),
                                signature,
                                source: "kcatta-malware".into(),
                                process_id: (pid > 0).then_some(pid as u32),
                            };
                            if tx.send(detection).is_err() {
                                return Ok(());
                            }
                        }
                    }
                }
                Err(Errno::EAGAIN) => std::thread::sleep(Duration::from_millis(100)),
                Err(e) => return Err(anyhow::anyhow!("fanotify read: {e}")),
            }
        }
        Ok(())
    }
}

impl Sensor for OnAccessSensor {
    fn name(&self) -> &'static str {
        "onaccess"
    }

    fn run(self: Box<Self>, tx: Sender<Detection>, shutdown: Arc<AtomicBool>) {
        if let Err(e) = self.run_inner(&tx, &shutdown) {
            eprintln!("guard: onaccess sensor stopped: {e}");
        }
    }
}

/// Match the opened file against `signatures`; returns the signature on a hit,
/// else `None` (treated as ALLOW). Fail-open on every error path.
fn scan_fd(signatures: &SignatureSet, fd: BorrowedFd) -> Option<String> {
    let proc_path = format!("/proc/self/fd/{}", fd.as_raw_fd());
    let meta = std::fs::metadata(&proc_path).ok()?;
    if meta.len() == 0 || meta.len() > DEFAULT_MAX_FILE_SIZE {
        return None; // skip empties / oversized → ALLOW
    }
    let bytes = std::fs::read(&proc_path).ok()?;
    scan_bytes(signatures, &bytes)
}

/// Resolve the real path behind an event fd (best-effort, for reporting).
fn fd_path(fd: BorrowedFd) -> String {
    std::fs::read_link(format!("/proc/self/fd/{}", fd.as_raw_fd()))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "<unknown>".to_string())
}
