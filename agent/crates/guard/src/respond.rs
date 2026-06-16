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
    /// eBPF egress blocker, lazily loaded on first `BlockConnection` (feature `ebpf`).
    #[cfg(feature = "ebpf")]
    ebpf: EbpfBackend,
}

/// Lazy state of the optional eBPF netblock backend.
#[cfg(feature = "ebpf")]
enum EbpfBackend {
    /// Not yet attempted.
    Untried,
    /// Loaded and attached to the cgroup.
    Active(Box<crate::ebpf_block::EbpfNetblock>),
    /// Load/attach failed; `nft` is used instead.
    Unavailable,
}

impl Responder {
    /// Build a responder bound to `policy`, never targeting the current process.
    pub fn new(policy: ResponsePolicy) -> Self {
        Self {
            policy,
            self_pid: std::process::id(),
            ledger: HashSet::new(),
            #[cfg(feature = "ebpf")]
            ebpf: EbpfBackend::Untried,
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

        let outcome = self.execute(action);
        if outcome == Outcome::Success {
            self.ledger.insert(key);
        }
        (action_taken_for(action), outcome)
    }

    /// Dispatch the side effect for a (vetted, non-duplicate) action.
    fn execute(&mut self, action: &Action) -> Outcome {
        match action {
            Action::None => Outcome::Success,
            Action::Quarantine { path } => quarantine_file(path, &self.policy.vault_dir),
            Action::BlockConnection { dst_ip } => self.netblock(dst_ip),
            Action::Kill { pid } => kill_process(*pid),
        }
    }

    /// Block an egress destination: kernel eBPF (cgroup-connect) when the `ebpf`
    /// feature is built and loadable, otherwise the `nft` userspace fallback.
    #[cfg(feature = "ebpf")]
    fn netblock(&mut self, dst_ip: &str) -> Outcome {
        use std::net::IpAddr;
        if matches!(self.ebpf, EbpfBackend::Untried) {
            self.ebpf = match crate::ebpf_block::EbpfNetblock::load_default() {
                Ok(backend) => EbpfBackend::Active(Box::new(backend)),
                Err(e) => {
                    eprintln!("guard: eBPF netblock unavailable ({e}); using nft fallback");
                    EbpfBackend::Unavailable
                }
            };
        }
        if let EbpfBackend::Active(backend) = &mut self.ebpf {
            match dst_ip.parse::<IpAddr>() {
                Ok(ip) => match backend.block(ip) {
                    Ok(()) => return Outcome::Success,
                    Err(e) => eprintln!("guard: eBPF block {dst_ip} failed ({e}); nft fallback"),
                },
                Err(_) => eprintln!("guard: invalid block target {dst_ip}; nft fallback"),
            }
        }
        netblock_nft(dst_ip)
    }

    /// Block an egress destination via the `nft` fallback (eBPF feature off).
    #[cfg(not(feature = "ebpf"))]
    fn netblock(&mut self, dst_ip: &str) -> Outcome {
        netblock_nft(dst_ip)
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

/// The dedicated nft table the guard owns end-to-end, so blocks can be managed
/// (deduplicated, reset, unblocked) without touching the host's other rules.
const NFT_TABLE: &str = "kcatta_guard";

/// Declarative ruleset (re)creating the guard's table with two named sets and a
/// single drop rule per family. Membership is set-based, so re-blocking an IP is
/// idempotent — no duplicate rules accumulate.
const NFT_RULESET: &str = "table inet kcatta_guard {\n\
\x20   set blocked4 { type ipv4_addr; }\n\
\x20   set blocked6 { type ipv6_addr; }\n\
\x20   chain output {\n\
\x20       type filter hook output priority 0; policy accept;\n\
\x20       ip daddr @blocked4 drop\n\
\x20       ip6 daddr @blocked6 drop\n\
\x20   }\n\
}\n";

/// Drop and recreate the guard's nft table, clearing any stale blocks left by a
/// previous run. Called at startup (when netblock is enabled) so drop rules are
/// lifetime-scoped and cannot accumulate or persist permanently across restarts.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn netblock_reset() {
    // Remove any leftover table first (idempotent; ignore error when absent).
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .status();
    match nft_apply_stdin(NFT_RULESET) {
        Ok(s) if s.success() => {}
        Ok(s) => eprintln!("guard: nft netblock table setup exited {s}"),
        Err(e) => eprintln!("guard: nft unavailable for netblock setup ({e})"),
    }
}

/// Feed a ruleset to `nft -f -` via stdin.
fn nft_apply_stdin(ruleset: &str) -> std::io::Result<std::process::ExitStatus> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(ruleset.as_bytes())?;
    }
    child.wait()
}

fn netblock_nft(dst_ip: &str) -> Outcome {
    // Adding to the set is idempotent. If the table/set is missing (reset was not
    // run), create it once and retry.
    let first = add_block_element(dst_ip);
    if first == Outcome::Success {
        return first;
    }
    netblock_reset();
    add_block_element(dst_ip)
}

fn block_set_for(dst_ip: &str) -> Option<&'static str> {
    use std::net::IpAddr;
    match dst_ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Some("blocked4"),
        Ok(IpAddr::V6(_)) => Some("blocked6"),
        Err(_) => None,
    }
}

fn add_block_element(dst_ip: &str) -> Outcome {
    let Some(set) = block_set_for(dst_ip) else {
        eprintln!("guard: nft invalid block target {dst_ip}");
        return Outcome::Failure;
    };
    let status = Command::new("nft")
        .args(["add", "element", "inet", NFT_TABLE, set, "{", dst_ip, "}"])
        .status();
    match status {
        Ok(s) if s.success() => Outcome::Success,
        Ok(s) => {
            eprintln!("guard: nft block {dst_ip} exited {s}");
            Outcome::Failure
        }
        Err(e) => {
            eprintln!("guard: nft unavailable ({e}); cannot block {dst_ip}");
            Outcome::Failure
        }
    }
}

/// Remove a single IP from the guard's nft deny sets (reverses a netblock).
pub(crate) fn netblock_unblock(dst_ip: &str) -> anyhow::Result<()> {
    let set =
        block_set_for(dst_ip).ok_or_else(|| anyhow::anyhow!("invalid IP address {dst_ip}"))?;
    let status = Command::new("nft")
        .args([
            "delete", "element", "inet", NFT_TABLE, set, "{", dst_ip, "}",
        ])
        .status()
        .map_err(|e| anyhow::anyhow!("nft unavailable: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        anyhow::bail!("nft delete element for {dst_ip} exited {status}")
    }
}

/// Flush all IPs from the guard's nft deny sets (reverses every netblock).
pub(crate) fn netblock_unblock_all() -> anyhow::Result<()> {
    let mut ok = true;
    for set in ["blocked4", "blocked6"] {
        match Command::new("nft")
            .args(["flush", "set", "inet", NFT_TABLE, set])
            .status()
        {
            Ok(s) if s.success() => {}
            Ok(s) => {
                eprintln!("guard: nft flush set {set} exited {s}");
                ok = false;
            }
            Err(e) => {
                eprintln!("guard: nft unavailable: {e}");
                ok = false;
            }
        }
    }
    if ok {
        Ok(())
    } else {
        anyhow::bail!("nft flush did not fully succeed (table may not exist)")
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
