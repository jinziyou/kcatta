//! `probe-remote`: agent-mode remote scanner front-end.
//!
//! Ships a static `probe-asset` to the target over SSH or WinRM, runs it in place,
//! pulls the JSON back, and cleans up.

use std::io::{BufRead, IsTerminal};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use probe_asset::ScanTarget;
use probe_ingest::upload_report;
use probe_malware::default_workers;
use probe_remote::{
    finalize_asset_report, run_agent_scan, run_winrm_agent_scan, ssh::SshOptions,
    write_asset_report, AgentScanOptions, MalwareAgentOptions, WinRmAgentScanOptions,
    WinRmOptions,
};
use probe_runtime::WindowsPackageProfile;

#[derive(Debug, Clone, Copy, ValueEnum, Default, PartialEq, Eq)]
enum Transport {
    /// OpenSSH upload/exec (Linux targets, or Windows with OpenSSH Server).
    #[default]
    Ssh,
    /// PowerShell remoting via local `pwsh`/`powershell` (Windows targets).
    Winrm,
}

#[derive(Debug, Parser)]
#[command(
    name = "probe-remote",
    version,
    about = "cyber-posture remote scanner: ship probe-asset, run on target, pull JSON back"
)]
struct Args {
    /// Target host as `user@host` (SSH or WinRM depending on `--transport`).
    #[arg(long, value_name = "USER@HOST")]
    ssh_host: String,

    /// Remote transport: `ssh` (Linux / OpenSSH on Windows) or `winrm`.
    #[arg(long, value_enum, default_value_t = Transport::Ssh)]
    transport: Transport,

    /// SSH port (ignored when `--transport winrm`).
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,

    /// SSH identity (private key) file. If omitted, a managed key under
    /// `~/.config/scdr/probe-remote/keys/` is used (auto-generated).
    #[arg(long, value_name = "PATH")]
    ssh_identity: Option<PathBuf>,

    /// SSH password — used **once** to install the public key into the
    /// target's `~/.ssh/authorized_keys`, then dropped from memory.
    /// Prefer `--ssh-password-stdin` or `SCDR_SSH_PASSWORD` to keep secrets
    /// out of process listings.
    #[arg(
        long,
        value_name = "PWD",
        env = "SCDR_SSH_PASSWORD",
        hide_env_values = true,
        conflicts_with = "ssh_password_stdin"
    )]
    ssh_password: Option<String>,

    /// Read SSH password from stdin (single line).
    #[arg(long, default_value_t = false)]
    ssh_password_stdin: bool,

    /// WinRM password (`PROBE_WINRM_PASSWORD` env). Falls back to `--ssh-password`
    /// when unset. Required for `--transport winrm`.
    #[arg(
        long,
        value_name = "PWD",
        env = "PROBE_WINRM_PASSWORD",
        hide_env_values = true
    )]
    winrm_password: Option<String>,

    /// WinRM listener port (5985 HTTP, 5986 HTTPS).
    #[arg(long, default_value_t = 5986)]
    winrm_port: u16,

    /// Use WinRM over HTTP (port 5985) instead of HTTPS.
    #[arg(long, default_value_t = false)]
    winrm_insecure: bool,

    /// Skip TLS certificate validation for WinRM HTTPS.
    #[arg(long, default_value_t = false)]
    winrm_skip_cert_check: bool,

    /// Revoke (remove) the managed public key from the target's
    /// `~/.ssh/authorized_keys` and exit — no scan. Leaves the target as it was
    /// before bootstrap, and deletes the local managed keypair.
    #[arg(long)]
    revoke_key: bool,

    /// Scan target forwarded to probe-asset: `host` | `packages` | `sbom` |
    /// `services` | `accounts` | `credentials` | `identity` | `all`.
    #[arg(long, short = 't', default_value = "host")]
    target: String,

    /// Output directory for per-asset JSON files.
    #[arg(long, short = 'o', default_value = ".")]
    output: PathBuf,

    /// Stable task id. Auto-generated if omitted.
    #[arg(long)]
    task_id: Option<String>,

    /// Local static `probe-asset` binary to ship.
    /// Default: musl Linux binary for SSH, Windows `.exe` for WinRM.
    #[arg(long, value_name = "PATH")]
    asset_binary: Option<PathBuf>,

    /// Filesystem root to scan on the target (`/` on Linux, `C:\` on Windows).
    #[arg(long, value_name = "DIR")]
    scan_root: Option<String>,

    /// Windows package scope forwarded to remote `--windows-packages`.
    #[arg(long, value_name = "PROFILE", default_value = "apps")]
    windows_packages: String,

    /// Upload assembled AssetReport to form after pull (`/ingest/asset-report`).
    /// Requires `host.json` (`--target host` or `all`).
    #[arg(long, value_name = "URL")]
    upload: Option<String>,

    /// Also run ClamAV scan on the target (SSH/Linux only; requires `clamd`).
    #[arg(long)]
    malware: bool,

    /// Local static `probe-malware` binary to ship when `--malware`.
    #[arg(
        long,
        value_name = "PATH",
        default_value = "target/x86_64-unknown-linux-musl/release/probe-malware"
    )]
    malware_binary: PathBuf,

    /// Parallel clamd workers for remote malware scan.
    #[arg(long, default_value_t = default_workers())]
    malware_jobs: usize,

    /// clamd Unix socket on the target (overrides auto-detection there).
    #[arg(long, value_name = "PATH")]
    clamd_socket: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let target = ScanTarget::parse(&args.target).context("parse --target")?;
    let windows_packages = WindowsPackageProfile::parse(&args.windows_packages)
        .context("parse --windows-packages")?;

    if args.revoke_key {
        if args.transport != Transport::Ssh {
            bail!("--revoke-key is only supported with --transport ssh");
        }
        let password = resolve_password(args.ssh_password, args.ssh_password_stdin)?;
        return revoke_managed_key(
            &args.ssh_host,
            args.ssh_port,
            args.ssh_identity.as_deref(),
            password.as_deref(),
        );
    }

    if args.malware && args.transport == Transport::Winrm {
        bail!("--malware is not supported with --transport winrm (Linux/clamd only)");
    }

    let asset_binary = args.asset_binary.clone().unwrap_or_else(|| default_asset_binary(args.transport));
    let scan_root = args
        .scan_root
        .clone()
        .unwrap_or_else(|| default_scan_root(args.transport));

    let output_dir = args.output.clone();
    let task_id = args.task_id.clone();

    let report = match args.transport {
        Transport::Ssh => {
            let password = resolve_password(args.ssh_password, args.ssh_password_stdin)?;
            let mut ssh = SshOptions::new(&args.ssh_host);
            ssh.port = args.ssh_port;
            ssh.identity = args.ssh_identity;
            ssh.control_persist = Duration::from_secs(120);

            let opts = AgentScanOptions {
                ssh,
                password,
                asset_binary,
                scan_root,
                target,
                output_dir: args.output,
                task_id,
                malware: args.malware.then(|| MalwareAgentOptions {
                    binary: args.malware_binary,
                    jobs: args.malware_jobs,
                    clamd_socket: args.clamd_socket.as_ref().map(|p| p.display().to_string()),
                }),
                windows_packages,
            };
            run_agent_scan(opts).context("run SSH agent scan")?
        }
        Transport::Winrm => {
            let password = resolve_winrm_password(
                args.winrm_password,
                args.ssh_password,
                args.ssh_password_stdin,
            )?;
            let winrm_port = if args.winrm_insecure && args.winrm_port == 5986 {
                5985
            } else {
                args.winrm_port
            };
            let winrm = WinRmOptions::from_user_host(
                &args.ssh_host,
                password,
                winrm_port,
                !args.winrm_insecure,
                args.winrm_skip_cert_check,
            )
            .context("parse WinRM target")?;
            let opts = WinRmAgentScanOptions {
                winrm,
                asset_binary,
                scan_root,
                target,
                output_dir: args.output,
                task_id,
                windows_packages,
            };
            run_winrm_agent_scan(opts).context("run WinRM agent scan")?
        }
    };

    eprintln!("task-id {}", report.task_id);
    for p in &report.files {
        eprintln!("wrote {}", p.display());
    }

    if args.upload.is_some() || needs_asset_report(&args.target) {
        let asset_report = finalize_asset_report(&output_dir).context("assemble asset report")?;
        let report_path =
            write_asset_report(&output_dir, &asset_report).context("write asset_report.json")?;
        eprintln!("wrote {}", report_path.display());

        if let Some(form_base) = &args.upload {
            upload_report(&asset_report, form_base).context("upload to form")?;
            eprintln!("uploaded report to {form_base}");
        }
    }

    Ok(())
}

fn default_asset_binary(transport: Transport) -> PathBuf {
    match transport {
        Transport::Ssh => PathBuf::from("target/x86_64-unknown-linux-musl/release/probe-asset"),
        Transport::Winrm => {
            PathBuf::from("target/x86_64-pc-windows-msvc/release/probe-asset.exe")
        }
    }
}

fn default_scan_root(transport: Transport) -> String {
    match transport {
        Transport::Ssh => "/".into(),
        Transport::Winrm => r"C:\".into(),
    }
}

/// Targets that include `host.json`, required to build an AssetReport.
fn needs_asset_report(target: &str) -> bool {
    matches!(target, "host" | "all")
}

fn resolve_password(arg: Option<String>, from_stdin: bool) -> Result<Option<String>> {
    if from_stdin {
        let mut line = String::new();
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            eprint!("ssh password: ");
        }
        stdin
            .lock()
            .read_line(&mut line)
            .context("read password from stdin")?;
        let pw = line.trim_end_matches(['\n', '\r']).to_string();
        if pw.is_empty() {
            anyhow::bail!("--ssh-password-stdin given but stdin was empty");
        }
        return Ok(Some(pw));
    }
    Ok(arg.filter(|s| !s.is_empty()))
}

fn resolve_winrm_password(
    winrm: Option<String>,
    ssh: Option<String>,
    from_stdin: bool,
) -> Result<String> {
    if let Some(pw) = winrm.filter(|s| !s.is_empty()) {
        return Ok(pw);
    }
    if let Some(pw) = ssh.filter(|s| !s.is_empty()) {
        return Ok(pw);
    }
    if from_stdin {
        return resolve_password(None, true)?
            .ok_or_else(|| anyhow::anyhow!("WinRM password required (--winrm-password or stdin)"));
    }
    anyhow::bail!(
        "WinRM password required: set PROBE_WINRM_PASSWORD, pass --winrm-password, \
         or reuse --ssh-password / --ssh-password-stdin"
    );
}

/// Remove the managed key from the target's `authorized_keys` and delete the
/// local managed keypair (unless a user-supplied `--ssh-identity` was used).
fn revoke_managed_key(
    ssh_host: &str,
    ssh_port: u16,
    ssh_identity: Option<&Path>,
    password: Option<&str>,
) -> Result<()> {
    let removed = probe_remote::bootstrap::revoke_key(ssh_host, ssh_port, ssh_identity, password)
        .context("revoke managed key on target")?;
    eprintln!(
        "{}",
        if removed {
            format!("revoked managed key from {ssh_host} authorized_keys")
        } else {
            format!("no managed key found on {ssh_host} (already clean)")
        }
    );

    // Drop the local managed keypair too — but never a user-supplied identity.
    if ssh_identity.is_none() {
        match probe_remote::bootstrap::managed_key_path(ssh_host, ssh_port) {
            Ok(priv_key) => {
                let mut pub_os = priv_key.clone().into_os_string();
                pub_os.push(".pub");
                for p in [priv_key, PathBuf::from(pub_os)] {
                    if p.exists() {
                        match std::fs::remove_file(&p) {
                            Ok(()) => eprintln!("removed local {}", p.display()),
                            Err(e) => eprintln!("warning: remove local {}: {e}", p.display()),
                        }
                    }
                }
            }
            Err(e) => eprintln!("warning: resolve local managed key: {e:#}"),
        }
    }
    Ok(())
}
