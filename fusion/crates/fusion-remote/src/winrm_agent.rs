//! WinRM agent-mode remote scan: ship `fusion-asset.exe`, run, pull JSON, cleanup.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use fusion_asset::ScanTarget;
use fusion_runtime::WindowsPackageProfile;

use crate::agent::AgentScanReport;
use crate::shared::{expected_files, parse_marked_exit, sha256_file, target_arg};
use crate::winrm::{WinRmOptions, WinRmSession};

/// Options for [`run_winrm_agent_scan`].
#[derive(Debug, Clone)]
pub struct WinRmAgentScanOptions {
    /// WinRM connection (user, host, password, TLS).
    pub winrm: WinRmOptions,
    /// Local `fusion-asset.exe` to ship.
    pub asset_binary: PathBuf,
    /// Filesystem root on the target (e.g. `C:\`).
    pub scan_root: String,
    /// Scan target forwarded to remote `fusion-asset -t`.
    pub target: ScanTarget,
    /// Local directory for pulled JSON files.
    pub output_dir: PathBuf,
    /// Stable task id; auto-generated when unset.
    pub task_id: Option<String>,
    /// Windows package scope forwarded to `--windows-packages`.
    pub windows_packages: WindowsPackageProfile,
}

/// Run the WinRM agent pipeline: upload binary, exec scan, pull JSON, cleanup.
pub fn run_winrm_agent_scan(opts: WinRmAgentScanOptions) -> anyhow::Result<AgentScanReport> {
    let task_id = opts
        .task_id
        .clone()
        .unwrap_or_else(|| crate::short_id(uuid::Uuid::new_v4()));

    if !opts.asset_binary.is_file() {
        bail!(
            "asset binary not found: {}\n\
             build it first:\n  \
             rustup target add x86_64-pc-windows-msvc\n  \
             cargo build -p fusion-asset --target x86_64-pc-windows-msvc --release",
            opts.asset_binary.display()
        );
    }

    let session = WinRmSession::connect(opts.winrm).context("establish WinRM session")?;
    let workdir = WinRmWorkdir::create(&session, &task_id).context("create remote work dir")?;
    let remote_bin = format!("{}\\fusion-asset.exe", workdir.path());
    let remote_out = format!("{}\\out", workdir.path());

    session
        .upload_file(&opts.asset_binary, &remote_bin)
        .context("upload fusion-asset.exe")?;

    verify_upload(&session, &opts.asset_binary, &remote_bin)
        .context("verify uploaded binary integrity")?;

    let packages_flag = format!(" --windows-packages {}", opts.windows_packages.as_cli_str());
    let run = session.exec(&format!(
        "New-Item -ItemType Directory -Force -Path '{remote_out}' | Out-Null; \
         & '{remote_bin}' -r '{root}' -t {target}{packages_flag} -o '{remote_out}'; \
         Write-Output \"__exit=$LASTEXITCODE\"",
        root = escape_ps_single(&opts.scan_root),
        target = target_arg(opts.target),
        packages_flag = packages_flag,
    ))?;
    let exit = parse_marked_exit(&run.stdout);
    if exit != Some(0) {
        bail!(
            "remote fusion-asset failed (exit {:?})\nstdout: {}\nstderr: {}",
            exit,
            run.stdout.trim(),
            run.stderr.trim()
        );
    }

    std::fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("create local output dir {}", opts.output_dir.display()))?;

    let mut files = Vec::new();
    for fname in expected_files(opts.target) {
        let remote_file = format!("{remote_out}\\{fname}");
        if !remote_exists(&session, &remote_file)? {
            continue;
        }
        let local_file = opts.output_dir.join(fname);
        session
            .download_file(&remote_file, &local_file)
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

    drop(workdir);
    Ok(AgentScanReport { task_id, files })
}

struct WinRmWorkdir<'a> {
    session: &'a WinRmSession,
    path: String,
}

impl<'a> WinRmWorkdir<'a> {
    fn create(session: &'a WinRmSession, task_id: &str) -> anyhow::Result<Self> {
        let out = session.exec(&format!(
            "$p = Join-Path $env:TEMP 'scdr-scan-{task_id}'; \
             New-Item -ItemType Directory -Force -Path $p | Out-Null; \
             Write-Output $p"
        ))?;
        let resolved = out.stdout.trim().lines().last().unwrap_or("").trim();
        if resolved.is_empty() {
            bail!("failed to create remote work dir: {}", out.stderr.trim());
        }
        Ok(Self {
            session,
            path: resolved.to_string(),
        })
    }

    fn path(&self) -> &str {
        &self.path
    }
}

impl Drop for WinRmWorkdir<'_> {
    fn drop(&mut self) {
        if self.path.contains("scdr-scan-") {
            if let Err(e) = self.session.exec(&format!(
                "Remove-Item -LiteralPath '{}' -Recurse -Force -ErrorAction SilentlyContinue",
                escape_ps_single(&self.path)
            )) {
                eprintln!(
                    "[fusion-remote/winrm] cleanup Remove-Item {} failed: {e:#}",
                    self.path
                );
            }
        }
    }
}

fn verify_upload(session: &WinRmSession, local: &Path, remote_path: &str) -> anyhow::Result<()> {
    let local_sum = sha256_file(local)?;
    let out = session.exec(&format!(
        "(Get-FileHash -Algorithm SHA256 -LiteralPath '{}').Hash.ToLower()",
        escape_ps_single(remote_path)
    ))?;
    let remote_sum = out
        .stdout
        .trim()
        .lines()
        .last()
        .unwrap_or("")
        .trim()
        .to_lowercase();
    if remote_sum.is_empty() {
        eprintln!("[fusion-remote/winrm] Get-FileHash returned empty; skipping integrity check");
        return Ok(());
    }
    if remote_sum != local_sum {
        bail!("uploaded binary sha256 mismatch (local {local_sum}, remote {remote_sum})");
    }
    Ok(())
}

fn remote_exists(session: &WinRmSession, path: &str) -> anyhow::Result<bool> {
    let out = session.exec(&format!(
        "if (Test-Path -LiteralPath '{}') {{ Write-Output __y }}",
        escape_ps_single(path)
    ))?;
    Ok(out.stdout.contains("__y"))
}

fn escape_ps_single(s: &str) -> String {
    s.replace('\'', "''")
}
