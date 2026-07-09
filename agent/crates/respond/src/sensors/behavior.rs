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
        let mut seen: HashSet<(u32, &'static str)> = HashSet::new();

        while !shutdown.load(Ordering::Relaxed) {
            let pids = proc_pids();
            let live: HashSet<u32> = pids.iter().copied().collect();
            for &pid in &pids {
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
                            if shell_spawned_net_tool(&comm, Some(&pcomm))
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

            // Forget PIDs that no longer exist: bounds the dedup set's memory and
            // ensures a reused PID is re-evaluated rather than silently skipped
            // because an earlier, unrelated process held the same (pid, rule) key.
            seen.retain(|(pid, _)| live.contains(pid));

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

    fn run(
        self: Box<Self>,
        tx: Sender<Detection>,
        shutdown: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        self.run_inner(&tx, &shutdown);
        Ok(())
    }
}

/// Network tools that are suspicious when spawned by an interactive shell.
const NET_TOOLS: &[&str] = &["curl", "wget", "nc", "ncat", "netcat"];
/// Parent process names treated as interactive shells for rule 2.
const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "sshd"];

/// Rule 2 predicate (pure, unit-tested): a network tool whose parent is a shell.
fn shell_spawned_net_tool(comm: &str, parent_comm: Option<&str>) -> bool {
    NET_TOOLS.contains(&comm) && parent_comm.is_some_and(|p| SHELLS.contains(&p))
}

/// Rule 1 predicate (pure, unit-tested): the kernel marks an unlinked exe with a
/// trailing " (deleted)" on the `/proc/<pid>/exe` symlink target.
fn exe_link_is_deleted(target: &str) -> bool {
    target.ends_with(" (deleted)")
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
        Ok(target) => exe_link_is_deleted(&target.to_string_lossy()),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn net_tool_under_shell_is_flagged() {
        assert!(shell_spawned_net_tool("curl", Some("bash")));
        assert!(shell_spawned_net_tool("nc", Some("sh")));
        assert!(shell_spawned_net_tool("wget", Some("sshd")));
    }

    #[test]
    fn net_tool_under_nonshell_or_orphan_is_not_flagged() {
        // A net tool spawned by a non-shell (e.g. a package manager) is normal,
        // and one with no known parent must not fire.
        assert!(!shell_spawned_net_tool("curl", Some("apt")));
        assert!(!shell_spawned_net_tool("curl", None));
    }

    #[test]
    fn nonnet_tool_under_shell_is_not_flagged() {
        assert!(!shell_spawned_net_tool("ls", Some("bash")));
        assert!(!shell_spawned_net_tool("vim", Some("zsh")));
    }

    #[test]
    fn exe_deleted_marker_parsing() {
        assert!(exe_link_is_deleted("/usr/bin/python3.11 (deleted)"));
        assert!(!exe_link_is_deleted("/usr/bin/python3.11"));
        assert!(!exe_link_is_deleted("/usr/bin/some(deleted)tool"));
    }
}
