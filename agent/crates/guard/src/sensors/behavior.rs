//! Process / behavior sensor (`/proc` polling).
//!
//! v1 evaluates a small rule set each tick and emits a [`Detection::Process`]
//! the first time a (pid, rule) pair matches. The netlink proc connector
//! (real-time exec/exit) is deferred to v2.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use agent_contract::Severity;

use crate::event::Detection;
use crate::sensors::Sensor;

/// Behavior sensor polling `/proc` at a fixed cadence.
pub struct BehaviorSensor {
    poll_interval: Duration,
}

impl BehaviorSensor {
    /// Poll every `poll_interval_ms` milliseconds.
    pub fn new(poll_interval_ms: u64) -> Self {
        Self {
            poll_interval: Duration::from_millis(poll_interval_ms.max(100)),
        }
    }

    fn run_inner(&self, tx: &Sender<Detection>, shutdown: &Arc<AtomicBool>) {
        // Network tools that are suspicious when spawned by an interactive shell.
        const NET_TOOLS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat"];
        const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "sshd"];

        let mut seen: HashSet<(u32, &'static str)> = HashSet::new();

        while !shutdown.load(Ordering::Relaxed) {
            for pid in proc_pids() {
                let Some(comm) = read_comm(pid) else { continue };

                // Rule 1: a running process whose executable was deleted on disk
                // (classic in-memory / post-exploitation pattern).
                if exe_deleted(pid) && seen.insert((pid, "exe_deleted_running")) {
                    emit(
                        tx,
                        Detection::Process {
                            severity: Severity::High,
                            pid,
                            process_name: comm.clone(),
                            behavior: "exe_deleted_running".into(),
                            rule_id: "guard.proc.exe_deleted".into(),
                            evidence: Some("process executable unlinked while running".into()),
                            parent_pid: read_ppid(pid),
                            parent_name: read_ppid(pid).and_then(read_comm),
                        },
                    );
                }

                // Rule 2: a network tool spawned directly by an interactive shell.
                if NET_TOOLS.contains(&comm.as_str()) {
                    if let Some(ppid) = read_ppid(pid) {
                        if let Some(pcomm) = read_comm(ppid) {
                            if SHELLS.contains(&pcomm.as_str())
                                && seen.insert((pid, "shell_spawned_net_tool"))
                            {
                                emit(
                                    tx,
                                    Detection::Process {
                                        severity: Severity::Medium,
                                        pid,
                                        process_name: comm.clone(),
                                        behavior: "shell_spawned_net_tool".into(),
                                        rule_id: "guard.proc.shell_net_tool".into(),
                                        evidence: Some(format!("{pcomm} -> {comm}")),
                                        parent_pid: Some(ppid),
                                        parent_name: Some(pcomm),
                                    },
                                );
                            }
                        }
                    }
                }
            }

            // Sleep in small slices so shutdown is observed promptly.
            let mut slept = Duration::ZERO;
            while slept < self.poll_interval && !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(100));
                slept += Duration::from_millis(100);
            }
        }
    }
}

impl Sensor for BehaviorSensor {
    fn name(&self) -> &'static str {
        "behavior"
    }

    fn run(self: Box<Self>, tx: Sender<Detection>, shutdown: Arc<AtomicBool>) {
        self.run_inner(&tx, &shutdown);
    }
}

fn emit(tx: &Sender<Detection>, detection: Detection) {
    let _ = tx.send(detection);
}

/// Numeric PIDs currently under `/proc`.
fn proc_pids() -> Vec<u32> {
    let mut pids = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        if let Some(name) = entry.file_name().to_str() {
            if let Ok(pid) = name.parse::<u32>() {
                pids.push(pid);
            }
        }
    }
    pids
}

fn read_comm(pid: u32) -> Option<String> {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

fn exe_deleted(pid: u32) -> bool {
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(target) => target.to_string_lossy().ends_with(" (deleted)"),
        Err(_) => false,
    }
}
