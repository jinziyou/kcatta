//! Response stage: apply a decided [`Action`] (after a safety veto + idempotency
//! check) and report what was attempted and how it turned out.
//!
//! Every action is gated upstream by [`crate::decide`]; here we add the safety
//! veto, an idempotency ledger (so re-detecting an already-handled target is a
//! no-op, breaking thrash loops), and the actual side effect.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use agent_contract::{ActionTaken, Outcome};

use crate::config::ResponsePolicy;
use crate::decide::Action;
use crate::safety;

/// Applies decided actions with safety vetoes and idempotency.
pub struct Responder {
    policy: ResponsePolicy,
    self_pid: u32,
    ledger: HashSet<String>,
}

impl Responder {
    /// Build a responder bound to `policy`, never targeting the current process.
    pub fn new(policy: ResponsePolicy) -> Self {
        Self {
            policy,
            self_pid: std::process::id(),
            ledger: HashSet::new(),
        }
    }

    /// Decide-then-do: returns the `(action_taken, outcome)` to report.
    ///
    /// `Action::None`, a safety veto, or a gated-off path all degrade to
    /// [`ActionTaken::Logged`] — the detection is still reported, nothing is
    /// destroyed. An already-applied target short-circuits to success.
    pub fn apply(&mut self, action: &Action) -> (ActionTaken, Outcome) {
        if matches!(action, Action::None) {
            return (ActionTaken::Logged, Outcome::Success);
        }
        if let Some(reason) = safety::veto(action, &self.policy, self.self_pid) {
            eprintln!("guard: vetoed {}: {reason}", describe(action));
            return (ActionTaken::Logged, Outcome::Success);
        }

        let key = ledger_key(action);
        if self.ledger.contains(&key) {
            // Already applied (e.g. FIM firing on our own quarantine move).
            return (action_taken_for(action), Outcome::Success);
        }

        let outcome = execute(action, &self.policy);
        if outcome == Outcome::Success {
            self.ledger.insert(key);
        }
        (action_taken_for(action), outcome)
    }
}

fn action_taken_for(action: &Action) -> ActionTaken {
    match action {
        Action::None => ActionTaken::Logged,
        Action::Quarantine { .. } => ActionTaken::Quarantined,
        Action::BlockConnection { .. } => ActionTaken::BlockedConnection,
        Action::Kill { .. } => ActionTaken::Killed,
    }
}

fn describe(action: &Action) -> String {
    match action {
        Action::None => "none".into(),
        Action::Quarantine { path } => format!("quarantine {path}"),
        Action::BlockConnection { dst_ip } => format!("block {dst_ip}"),
        Action::Kill { pid } => format!("kill {pid}"),
    }
}

fn ledger_key(action: &Action) -> String {
    match action {
        Action::None => "none".into(),
        Action::Quarantine { path } => format!("quarantine:{path}"),
        Action::BlockConnection { dst_ip } => format!("netblock:{dst_ip}"),
        Action::Kill { pid } => format!("kill:{pid}"),
    }
}

fn execute(action: &Action, policy: &ResponsePolicy) -> Outcome {
    match action {
        Action::None => Outcome::Success,
        Action::Quarantine { path } => quarantine_file(path, &policy.vault_dir),
        Action::BlockConnection { dst_ip } => netblock(dst_ip),
        Action::Kill { pid } => kill_process(*pid),
    }
}

/// Move `path` into `vault` and strip its permissions. Reversible (the original
/// bytes are preserved in the vault); **never deletes**.
fn quarantine_file(path: &str, vault: &Path) -> Outcome {
    if let Err(e) = std::fs::create_dir_all(vault) {
        eprintln!("guard: cannot create vault {}: {e}", vault.display());
        return Outcome::Failure;
    }
    let src = Path::new(path);
    let stem = src
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("quarantined");
    let dest = vault.join(format!("{stem}.{}", uuid::Uuid::new_v4()));

    // Prefer a same-filesystem rename; fall back to copy + remove across mounts.
    let moved = match std::fs::rename(src, &dest) {
        Ok(()) => true,
        Err(_) => match std::fs::copy(src, &dest) {
            Ok(_) => std::fs::remove_file(src).is_ok(),
            Err(e) => {
                eprintln!("guard: quarantine copy failed for {path}: {e}");
                false
            }
        },
    };
    if !moved {
        return Outcome::Failure;
    }

    strip_permissions(&dest);
    append_manifest(vault, path, &dest);
    Outcome::Success
}

#[cfg(unix)]
fn strip_permissions(dest: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Err(e) = std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o000)) {
        eprintln!("guard: chmod 000 failed for {}: {e}", dest.display());
    }
}

#[cfg(not(unix))]
fn strip_permissions(_dest: &Path) {}

fn append_manifest(vault: &Path, original: &str, dest: &Path) {
    use std::io::Write;
    let line = format!("{}\t{}\n", original, dest.display());
    let manifest = vault.join("manifest.tsv");
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&manifest)
    {
        Ok(mut f) => {
            let _ = f.write_all(line.as_bytes());
        }
        Err(e) => eprintln!("guard: cannot write quarantine manifest: {e}"),
    }
}

fn netblock(dst_ip: &str) -> Outcome {
    // Best-effort: insert a tagged drop rule so shutdown/reload can clean it up.
    let status = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "filter",
            "output",
            "ip",
            "daddr",
            dst_ip,
            "drop",
            "comment",
            "agent-guard",
        ])
        .status();
    match status {
        Ok(s) if s.success() => Outcome::Success,
        Ok(s) => {
            eprintln!("guard: nft drop for {dst_ip} exited {s}");
            Outcome::Failure
        }
        Err(e) => {
            eprintln!("guard: nft unavailable ({e}); cannot block {dst_ip}");
            Outcome::Failure
        }
    }
}

#[cfg(target_os = "linux")]
fn kill_process(pid: u32) -> Outcome {
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    match kill(Pid::from_raw(pid as i32), Signal::SIGKILL) {
        Ok(()) => Outcome::Success,
        Err(e) => {
            eprintln!("guard: kill {pid} failed: {e}");
            Outcome::Failure
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn kill_process(_pid: u32) -> Outcome {
    Outcome::Failure
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quarantine_moves_and_strips_then_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault");
        let target = dir.path().join("bad.bin");
        std::fs::write(&target, b"malicious").unwrap();

        let mut policy = ResponsePolicy {
            allow_quarantine: true,
            vault_dir: vault.clone(),
            // Keep the default critical/system guards but clear the allowlist so
            // the temp target isn't matched (it lives under a temp dir anyway).
            allowlist_paths: vec![],
            ..ResponsePolicy::default()
        };
        policy.critical_paths.clear();

        let mut responder = Responder::new(policy);
        let action = Action::Quarantine {
            path: target.to_string_lossy().into_owned(),
        };

        let (taken, outcome) = responder.apply(&action);
        assert_eq!(taken, ActionTaken::Quarantined);
        assert_eq!(outcome, Outcome::Success);
        assert!(!target.exists(), "original file was moved out");
        assert!(vault.join("manifest.tsv").exists(), "manifest written");

        // Re-applying the same target is a no-op success (idempotent), even
        // though the file is already gone.
        let (taken2, outcome2) = responder.apply(&action);
        assert_eq!(taken2, ActionTaken::Quarantined);
        assert_eq!(outcome2, Outcome::Success);
    }

    #[test]
    fn vetoed_action_degrades_to_logged() {
        let policy = ResponsePolicy {
            allow_quarantine: true,
            ..ResponsePolicy::default()
        };
        let mut responder = Responder::new(policy);
        // /etc/passwd is a critical path → veto → logged, file untouched.
        let (taken, outcome) = responder.apply(&Action::Quarantine {
            path: "/etc/passwd".into(),
        });
        assert_eq!(taken, ActionTaken::Logged);
        assert_eq!(outcome, Outcome::Success);
    }

    #[test]
    fn none_action_is_logged() {
        let mut responder = Responder::new(ResponsePolicy::default());
        assert_eq!(
            responder.apply(&Action::None),
            (ActionTaken::Logged, Outcome::Success)
        );
    }
}
