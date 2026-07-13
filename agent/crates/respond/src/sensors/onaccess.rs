//! On-access malware sensor (fanotify + built-in signature scanner).
//!
//! Marks the configured mounts for open events. In enforce mode it uses
//! `FAN_OPEN_PERM` and answers `FAN_ALLOW`/`FAN_DENY` synchronously; in monitor
//! mode it uses `FAN_OPEN` (notify only). Either way it matches the opened file
//! against [`agent_detect::malware`]'s signature set (the same engine the host
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

use agent_contract::{ActionTaken, Outcome, Severity};
use agent_detect::malware::{scan_bytes, SignatureSet, DEFAULT_MAX_FILE_SIZE};
use nix::errno::Errno;
use nix::sys::fanotify::{
    EventFFlags, Fanotify, FanotifyResponse, InitFlags, MarkFlags, MaskFlags, Response,
};

use crate::config::{GuardConfig, Mode};
use crate::decide::{decide_block_open, Action};
use crate::safety;
use crate::sensors::{Sensor, SensorEvent};
use crate::Detection;

/// On-access scan sensor.
pub struct OnAccessSensor {
    config: GuardConfig,
}

impl OnAccessSensor {
    /// Build the sensor with the complete policy needed for the synchronous
    /// open-permission decision.
    pub fn new(config: GuardConfig) -> Self {
        Self { config }
    }

    /// Permission events are requested only after the explicit action gate is
    /// enabled. Enforce mode by itself remains notify-only and cannot stall or
    /// deny an opener.
    fn permission_events_enabled(&self) -> bool {
        self.config.mode == Mode::Enforce && self.config.response.allow_block_open
    }

    fn run_inner(
        &self,
        tx: &Sender<SensorEvent>,
        shutdown: &Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        let mut signatures = SignatureSet::builtin();
        if let Some(path) = &self.config.onaccess.signatures {
            signatures.load_extra(path)?;
        }

        let group = Fanotify::init(
            InitFlags::FAN_CLASS_CONTENT | InitFlags::FAN_NONBLOCK | InitFlags::FAN_CLOEXEC,
            EventFFlags::O_RDONLY,
        )?;
        let permission_events = self.permission_events_enabled();
        let event_mask = if permission_events {
            MaskFlags::FAN_OPEN_PERM
        } else {
            MaskFlags::FAN_OPEN
        };

        let mut marked = 0usize;
        for path in &self.config.onaccess.paths {
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
        if self.config.onaccess.paths.is_empty() || marked != self.config.onaccess.paths.len() {
            anyhow::bail!(
                "onaccess marked {marked}/{} configured path(s); refusing partial protection",
                self.config.onaccess.paths.len()
            );
        }

        while !shutdown.load(Ordering::Relaxed) {
            match group.read_events() {
                Ok(events) => {
                    for event in events {
                        let Some(fd) = event.fd() else { continue }; // queue overflow marker
                        let verdict = scan_fd(&signatures, fd);

                        if let Some(signature) = verdict {
                            let pid = event.pid();
                            let detection = Detection::Malware {
                                severity: Severity::Critical,
                                path: fd_path(fd),
                                signature,
                                source: "kcatta-malware".into(),
                                process_id: (pid > 0).then_some(pid as u32),
                            };

                            let sensor_event = if permission_events {
                                let action = decide_block_open(&detection, &self.config);
                                let should_block = match &action {
                                    Action::BlockOpen { .. } => {
                                        if let Some(reason) = safety::veto(
                                            &action,
                                            &self.config.response,
                                            std::process::id(),
                                        ) {
                                            eprintln!(
                                                "guard: vetoed block open {}: {reason}",
                                                detection.file_path().unwrap_or("<unknown>")
                                            );
                                            false
                                        } else {
                                            true
                                        }
                                    }
                                    _ => false,
                                };

                                // Answer the kernel before enqueueing the event:
                                // the opener is blocked until this write completes.
                                match answer_permission_event(should_block, |response| {
                                    group.write_response(FanotifyResponse::new(fd, response))
                                })? {
                                    Some((action_taken, outcome)) => {
                                        SensorEvent::pre_applied(detection, action_taken, outcome)
                                    }
                                    None => detection.into(),
                                }
                            } else {
                                detection.into()
                            };

                            if tx.send(sensor_event).is_err() {
                                return Ok(());
                            }
                        } else if permission_events {
                            // Clean, unreadable, empty, or oversized files always
                            // fail open. No detection is emitted for these cases.
                            answer_permission_event(false, |response| {
                                group.write_response(FanotifyResponse::new(fd, response))
                            })?;
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

    fn run(
        self: Box<Self>,
        tx: Sender<SensorEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        self.run_inner(&tx, &shutdown).inspect_err(|e| {
            eprintln!("guard: onaccess sensor stopped: {e}");
        })
    }
}

/// Write the synchronous permission response and return an already-applied
/// result only when a deny was attempted. A failed deny is immediately followed
/// by an allow attempt, preserving fail-open behavior as far as the kernel fd
/// remains writable.
fn answer_permission_event(
    should_block: bool,
    mut write: impl FnMut(Response) -> Result<(), Errno>,
) -> anyhow::Result<Option<(ActionTaken, Outcome)>> {
    if !should_block {
        write(Response::FAN_ALLOW)
            .map_err(|error| anyhow::anyhow!("onaccess FAN_ALLOW response failed: {error}"))?;
        return Ok(None);
    }

    match write(Response::FAN_DENY) {
        Ok(()) => Ok(Some((ActionTaken::BlockedOpen, Outcome::Success))),
        Err(deny_error) => {
            eprintln!(
                "guard: onaccess FAN_DENY response failed ({deny_error}); attempting FAN_ALLOW"
            );
            write(Response::FAN_ALLOW).map_err(|allow_error| {
                anyhow::anyhow!(
                    "onaccess FAN_DENY failed ({deny_error}) and fallback FAN_ALLOW failed ({allow_error})"
                )
            })?;
            Ok(Some((ActionTaken::BlockedOpen, Outcome::Failure)))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_success_is_reported_as_blocked_open() {
        let mut responses = Vec::new();
        let result = answer_permission_event(true, |response| {
            responses.push(response);
            Ok(())
        })
        .unwrap();

        assert_eq!(result, Some((ActionTaken::BlockedOpen, Outcome::Success)));
        assert_eq!(responses.len(), 1);
        assert!(responses[0].contains(Response::FAN_DENY));
    }

    #[test]
    fn deny_failure_attempts_allow_and_reports_failure() {
        let mut responses = Vec::new();
        let result = answer_permission_event(true, |response| {
            responses.push(response);
            if responses.len() == 1 {
                Err(Errno::EIO)
            } else {
                Ok(())
            }
        })
        .unwrap();

        assert_eq!(result, Some((ActionTaken::BlockedOpen, Outcome::Failure)));
        assert_eq!(responses.len(), 2);
        assert!(responses[0].contains(Response::FAN_DENY));
        assert!(responses[1].contains(Response::FAN_ALLOW));
    }

    #[test]
    fn unauthorized_hit_is_allowed_and_not_marked_pre_applied() {
        let mut responses = Vec::new();
        let result = answer_permission_event(false, |response| {
            responses.push(response);
            Ok(())
        })
        .unwrap();

        assert_eq!(result, None);
        assert_eq!(responses.len(), 1);
        assert!(responses[0].contains(Response::FAN_ALLOW));
    }

    #[test]
    fn allow_write_failure_is_fatal_to_the_sensor() {
        let error = answer_permission_event(false, |_response| Err(Errno::EIO))
            .expect_err("failed FAN_ALLOW must stop the sensor");
        assert!(error.to_string().contains("FAN_ALLOW response failed"));
    }

    #[test]
    fn deny_and_fallback_allow_failure_is_fatal_to_the_sensor() {
        let error = answer_permission_event(true, |_response| Err(Errno::EIO))
            .expect_err("double response failure must stop the sensor");
        assert!(error.to_string().contains("fallback FAN_ALLOW failed"));
    }
}
