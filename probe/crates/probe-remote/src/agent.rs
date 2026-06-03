//! Agent-mode remote scan: ship a static `probe-asset` binary to the
//! target, run it in place against the live filesystem, pull the JSON back,
//! then remove all traces.
//!
//! Pipeline:
//! 1. [`bootstrap::ensure_key_auth`] (password → key on first run).
//! 2. [`crate::ssh::SshSession`] over multiplexed OpenSSH.
//! 3. Probe target arch; reject if it cannot match the shipped binary.
//! 4. Pick a writable, non-`noexec` work dir; create it (RAII cleanup).
//! 5. `scp` the binary up, `chmod +x`, sha256-verify.
//! 6. Run `probe-asset -r <root> -t <target> -o <work>/out`.
//! 7. `scp` the per-asset JSON files back into `output_dir`.
//! 8. `rm -rf` the work dir on drop, even on error.
//!
//! This needs **no** snapshot, qemu-nbd, or nbd kernel module — only SSH and
//! a writable directory on the target.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use probe_asset::ScanTarget;

use crate::bootstrap;
use crate::sh_quote;
use crate::shared::{expected_files, parse_marked_exit, sha256_file, target_arg};
use crate::ssh::{SshOptions, SshSession};
use probe_runtime::WindowsPackageProfile;

/// Optional ClamAV scan run on the target after asset collection.
#[derive(Debug, Clone)]
pub struct MalwareAgentOptions {
    /// Local static `probe-malware` binary to ship.
    pub binary: PathBuf,
    /// Parallel `clamd` workers on the target.
    pub jobs: usize,
    /// `clamd` Unix socket path **on the target** (auto-detect when unset).
    pub clamd_socket: Option<String>,
}

/// Candidate work-dir parents, in priority order. First that is writable and
/// not mounted `noexec` wins. `{id}` is replaced with the task id.
const WORKDIR_CANDIDATES: &[&str] = &["/var/lib/scdr", "/opt/scdr", "/root/.cache/scdr", "/tmp"];

/// Options for [`run_agent_scan`].
#[derive(Debug, Clone)]
pub struct AgentScanOptions {
    /// SSH connection parameters (`user@host`, port, identity).
    pub ssh: SshOptions,
    /// One-shot password (only used if key auth fails on first run).
    pub password: Option<String>,
    /// Local static `probe-asset` binary to ship (musl recommended).
    pub asset_binary: PathBuf,
    /// Filesystem root to scan on the target (default `/`).
    pub scan_root: String,
    /// What to collect (`host`, `all`, …) — forwarded to remote `probe-asset -t`.
    pub target: ScanTarget,
    /// Local output directory for the per-asset JSON files.
    pub output_dir: PathBuf,
    /// Optional stable task id; auto-generated if `None`.
    pub task_id: Option<String>,
    /// When set, ship and run `probe-malware` on the target (needs `clamd` there).
    pub malware: Option<MalwareAgentOptions>,
    /// Windows package scope forwarded to `--windows-packages` on the target binary.
    pub windows_packages: WindowsPackageProfile,
}

/// Result of a successful remote agent scan.
#[derive(Debug, Clone)]
pub struct AgentScanReport {
    /// Task id used for the remote work directory (also in logs).
    pub task_id: String,
    /// Local paths of JSON files pulled back from the target.
    pub files: Vec<PathBuf>,
}

/// Run the full agent pipeline: bootstrap auth, upload binary, exec scan, pull JSON, cleanup.
///
/// The remote work directory is removed on drop, even when this function returns an error
/// after the directory was created.
pub fn run_agent_scan(mut opts: AgentScanOptions) -> anyhow::Result<AgentScanReport> {
    let task_id = opts
        .task_id
        .clone()
        .unwrap_or_else(|| crate::short_id(uuid::Uuid::new_v4()));

    if !opts.asset_binary.is_file() {
        bail!(
            "asset binary not found: {} \n\
             build it first:\n  \
             rustup target add x86_64-unknown-linux-musl\n  \
             cargo build -p probe-asset --target x86_64-unknown-linux-musl --release",
            opts.asset_binary.display()
        );
    }

    let key_path = bootstrap::ensure_key_auth(
        &opts.ssh.target,
        opts.ssh.port,
        opts.ssh.identity.as_deref(),
        opts.password.as_deref(),
    )
    .context("ensure key-based ssh auth")?;
    opts.ssh.identity = Some(key_path);
    opts.password.take();

    let session = SshSession::connect(opts.ssh.clone()).context("establish ssh session")?;

    probe_arch_compatible(&session).context("probe target architecture")?;

    let workdir = RemoteWorkdir::create(&session, &task_id).context("create remote work dir")?;
    let remote_bin = format!("{}/probe-asset", workdir.path());
    let remote_out = format!("{}/out", workdir.path());

    session
        .scp_upload(&opts.asset_binary, &remote_bin)
        .context("upload probe-asset binary")?;

    verify_upload(&session, &opts.asset_binary, &remote_bin)
        .context("verify uploaded binary integrity")?;

    let packages_flag = format!(" --windows-packages {}", opts.windows_packages.as_cli_str());
    let run = session.exec(&format!(
        "chmod +x {remote_bin} && mkdir -p {remote_out} && \
         {remote_bin} -r {root} -t {target}{packages_flag} -o {remote_out}; echo __exit=$?",
        root = sh_quote(&opts.scan_root),
        target = target_arg(opts.target),
        packages_flag = packages_flag,
    ))?;
    let exit = parse_marked_exit(&run.stdout);
    if exit != Some(0) {
        bail!(
            "remote probe-asset failed (exit {:?})\nstdout: {}\nstderr: {}",
            exit,
            run.stdout.trim(),
            run.stderr.trim()
        );
    }

    std::fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("create local output dir {}", opts.output_dir.display()))?;

    let mut files = Vec::new();
    for fname in expected_files(opts.target) {
        let remote_file = format!("{remote_out}/{fname}");
        if !remote_exists(&session, &remote_file)? {
            continue;
        }
        let local_file = opts.output_dir.join(fname);
        session
            .scp_download(&remote_file, &local_file)
            .with_context(|| format!("download {fname}"))?;
        files.push(local_file);
    }

    if files.is_empty() {
        bail!(
            "remote scan produced no JSON files under {remote_out} \
             (target={:?}); nothing pulled back",
            opts.target
        );
    }

    if let Some(malware) = &opts.malware {
        run_remote_malware(
            &session,
            &workdir,
            &remote_out,
            &opts.scan_root,
            malware,
            &opts.output_dir,
            &mut files,
        )
        .context("remote malware scan")?;
    }

    drop(workdir); // explicit: rm -rf remote work dir
    Ok(AgentScanReport { task_id, files })
}

fn run_remote_malware(
    session: &SshSession,
    workdir: &RemoteWorkdir<'_>,
    remote_out: &str,
    scan_root: &str,
    malware: &MalwareAgentOptions,
    output_dir: &Path,
    files: &mut Vec<PathBuf>,
) -> anyhow::Result<()> {
    if !malware.binary.is_file() {
        bail!(
            "malware binary not found: {}\n\
             build it first:\n  \
             rustup target add x86_64-unknown-linux-musl\n  \
             cargo build -p probe-malware --target x86_64-unknown-linux-musl --release",
            malware.binary.display()
        );
    }

    let remote_bin = format!("{}/probe-malware", workdir.path());
    session
        .scp_upload(&malware.binary, &remote_bin)
        .context("upload probe-malware binary")?;
    verify_upload(session, &malware.binary, &remote_bin)
        .context("verify uploaded malware binary integrity")?;

    let mut cmd = format!(
        "chmod +x {remote_bin} && {remote_bin} -r {root} -o {remote_out} -j {jobs}",
        root = sh_quote(scan_root),
        jobs = malware.jobs.max(1),
    );
    if let Some(sock) = &malware.clamd_socket {
        cmd.push_str(&format!(" --clamd-socket {}", sh_quote(sock)));
    }
    cmd.push_str("; echo __exit=$?");

    let run = session.exec(&cmd)?;
    let exit = parse_marked_exit(&run.stdout);
    if exit != Some(0) {
        bail!(
            "remote probe-malware failed (exit {:?})\nstdout: {}\nstderr: {}",
            exit,
            run.stdout.trim(),
            run.stderr.trim()
        );
    }

    let remote_json = format!("{remote_out}/malware.json");
    if remote_exists(session, &remote_json)? {
        let local = output_dir.join("malware.json");
        session
            .scp_download(&remote_json, &local)
            .context("download malware.json")?;
        files.push(local);
    }
    Ok(())
}

/// RAII guard: `rm -rf` the remote work dir on drop, plus the `scdr` parent we
/// created (when it ends up empty) so a scan leaves no trace.
struct RemoteWorkdir<'a> {
    session: &'a SshSession,
    path: String,
    /// Chosen candidate parent dir (e.g. `/var/lib/scdr`).
    parent: String,
    /// Whether **we** created `parent` (vs. it pre-existing); only then is it
    /// removed on cleanup.
    created_parent: bool,
}

impl<'a> RemoteWorkdir<'a> {
    fn create(session: &'a SshSession, task_id: &str) -> anyhow::Result<Self> {
        let (parent, created_parent) = pick_workdir_parent(session)?;
        let path = format!("{parent}/scan-{task_id}");
        let out = session.exec(&format!(
            "mkdir -p {p} && chmod 700 {p} && echo __ok",
            p = sh_quote(&path)
        ))?;
        if !out.success() || !out.stdout.contains("__ok") {
            bail!(
                "failed to create remote work dir {path}: {}",
                out.stderr.trim()
            );
        }
        Ok(Self {
            session,
            path,
            parent,
            created_parent,
        })
    }

    fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for RemoteWorkdir<'_> {
    fn drop(&mut self) {
        // Guard against empty/wildcard paths before rm -rf.
        if self.path.starts_with('/') && self.path.contains("/scan-") {
            if let Err(e) = self
                .session
                .exec(&format!("rm -rf {}", sh_quote(&self.path)))
            {
                eprintln!(
                    "[probe-remote/agent] cleanup rm -rf {} failed: {e:#}",
                    self.path
                );
            }
            // If we created the `scdr` parent, remove it too — but only when
            // empty (`rmdir` fails harmlessly otherwise, e.g. a concurrent
            // scan). The `ends_with("/scdr")` guard ensures we never touch a
            // system dir such as `/tmp`.
            if self.created_parent && self.parent.starts_with('/') && self.parent.ends_with("/scdr")
            {
                let _ = self
                    .session
                    .exec(&format!("rmdir {} 2>/dev/null", sh_quote(&self.parent)));
            }
        }
    }
}

/// Find the first writable, non-`noexec` candidate parent dir on the target.
/// Returns `(dir, created)`, where `created` is `true` when the dir did not
/// pre-exist and we had to create it — so cleanup can remove it again.
fn pick_workdir_parent(session: &SshSession) -> anyhow::Result<(String, bool)> {
    // One round-trip: for each candidate, record whether it pre-existed, try to
    // create it, and check the mount options of the backing fs for `noexec`.
    let script = WORKDIR_CANDIDATES
        .iter()
        .map(|c| {
            format!(
                "pre=1; [ -d {c} ] || pre=0; \
                 if mkdir -p {c} 2>/dev/null && [ -w {c} ]; then \
                   opts=$(awk -v d={c} '$2==d || (index(d,$2)==1 && length($2)>best){{best=length($2);o=$4}} END{{print o}}' /proc/self/mounts); \
                   case \",$opts,\" in *,noexec,*) : ;; *) echo \"{c} $pre\"; exit 0;; esac; \
                 fi"
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let out = session.exec(&script)?;
    let chosen = out.stdout.trim().lines().next().unwrap_or("").trim();
    if chosen.is_empty() {
        bail!(
            "no writable non-noexec work dir among {:?} on {}",
            WORKDIR_CANDIDATES,
            session.target()
        );
    }
    // Parse "<dir> <pre>" (candidates contain no spaces). Default to "created =
    // false" if the flag is somehow missing, so we never remove a dir we are
    // unsure about.
    let (dir, pre) = chosen.rsplit_once(' ').unwrap_or((chosen, "1"));
    Ok((dir.trim().to_string(), pre.trim() == "0"))
}

fn probe_arch_compatible(session: &SshSession) -> anyhow::Result<()> {
    let out = session.exec("uname -m")?;
    let arch = out.stdout.trim();
    // MVP ships x86_64 only. Reject obvious mismatches early with a clear msg.
    match arch {
        "x86_64" | "amd64" => Ok(()),
        other => bail!(
            "target arch {other:?} not supported by the shipped binary \
             (MVP builds x86_64-unknown-linux-musl). Build a matching target."
        ),
    }
}

fn verify_upload(session: &SshSession, local: &Path, remote_path: &str) -> anyhow::Result<()> {
    let local_sum = sha256_file(local)?;
    let out = session.exec(&format!("sha256sum {} 2>/dev/null", sh_quote(remote_path)))?;
    let remote_sum = out
        .stdout
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();
    if remote_sum.is_empty() {
        // sha256sum missing on target: skip with a warning rather than fail.
        eprintln!("[probe-remote/agent] sha256sum unavailable on target; skipping integrity check");
        return Ok(());
    }
    if remote_sum != local_sum {
        bail!("uploaded binary sha256 mismatch (local {local_sum}, remote {remote_sum})");
    }
    Ok(())
}

fn remote_exists(session: &SshSession, path: &str) -> anyhow::Result<bool> {
    let out = session.exec(&format!("test -f {} && echo __y", sh_quote(path)))?;
    Ok(out.stdout.contains("__y"))
}
