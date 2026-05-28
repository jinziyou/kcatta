//! `scanner-remote`: agentless SSH+LVM+NBD scanner front-end.

use std::io::{BufRead, IsTerminal};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use scanner_asset::ScanTarget;
use scanner_remote::{
    nbd::NbdOptions,
    run_remote_scan,
    ssh::SshOptions,
    BackendSelection, RemoteScanOptions,
};

#[derive(Debug, Parser)]
#[command(
    name = "scanner-remote",
    version,
    about = "cyber-posture agentless scanner: ssh + LVM snapshot + NBD + scanner-asset"
)]
struct Args {
    /// Target host as `user@host`.
    #[arg(long, value_name = "USER@HOST")]
    ssh_host: String,

    /// SSH port.
    #[arg(long, default_value_t = 22)]
    ssh_port: u16,

    /// SSH identity (private key) file. If omitted, a managed key under
    /// `~/.config/scdr/scanner-remote/keys/` is used (auto-generated).
    #[arg(long, value_name = "PATH")]
    ssh_identity: Option<PathBuf>,

    /// SSH password — used **once** to install the public key into the
    /// target's `~/.ssh/authorized_keys`, then dropped from memory.
    /// Subsequent runs use the key. Prefer `--ssh-password-stdin` or the
    /// `SCDR_SSH_PASSWORD` env var to keep secrets out of process listings.
    #[arg(
        long,
        value_name = "PWD",
        env = "SCDR_SSH_PASSWORD",
        hide_env_values = true,
        conflicts_with = "ssh_password_stdin"
    )]
    ssh_password: Option<String>,

    /// Read SSH password from stdin (single line, newline-terminated).
    #[arg(long, default_value_t = false)]
    ssh_password_stdin: bool,

    /// LVM source logical volume on the target, e.g. `/dev/vg0/root`.
    #[arg(long, value_name = "DEV")]
    lv: String,

    /// Optional mount point on the target to `fsfreeze` around snapshot
    /// creation, e.g. `/`.
    #[arg(long, value_name = "MOUNT")]
    freeze_mount: Option<String>,

    /// Scan target forwarded to scanner-asset: `host` | `packages` | `all`.
    #[arg(long, short = 't', default_value = "host")]
    target: String,

    /// Output directory for per-asset JSON files.
    #[arg(long, short = 'o', default_value = ".")]
    output: PathBuf,

    /// Local NBD device to attach.
    #[arg(long, default_value = "/dev/nbd0", value_name = "DEV")]
    nbd_device: PathBuf,

    /// TCP port for the SSH-forwarded NBD tunnel.
    #[arg(long, default_value_t = 10809)]
    nbd_port: u16,

    /// Local mount base directory; the scan is mounted at `<base>/scdr-scan-<id>`.
    #[arg(long, default_value = "/mnt", value_name = "DIR")]
    mount_base: PathBuf,

    /// Optional filesystem type hint for `mount -t <type>`.
    #[arg(long, value_name = "FSTYPE")]
    fs_type: Option<String>,

    /// Stable task id (used in snapshot name and mount path). Auto-generated if omitted.
    #[arg(long)]
    task_id: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let target = ScanTarget::parse(&args.target).context("parse --target")?;

    let mut ssh = SshOptions::new(&args.ssh_host);
    ssh.port = args.ssh_port;
    ssh.identity = args.ssh_identity;
    ssh.control_persist = Duration::from_secs(120);

    let nbd = NbdOptions {
        local_nbd: args.nbd_device,
        port: args.nbd_port,
        mount_base: args.mount_base,
        fs_type: args.fs_type,
        ..NbdOptions::default()
    };

    let password = resolve_password(args.ssh_password, args.ssh_password_stdin)?;

    let opts = RemoteScanOptions {
        ssh,
        backend: BackendSelection::Lvm { source: args.lv },
        freeze_mount: args.freeze_mount,
        nbd,
        output_dir: args.output,
        target,
        task_id: args.task_id,
        password,
    };

    let report = run_remote_scan(opts).context("run remote scan")?;
    eprintln!("task-id {}", report.task_id);
    if let Some(p) = &report.scan.host {
        eprintln!("wrote {}", p.display());
    }
    if let Some(p) = &report.scan.packages {
        eprintln!("wrote {}", p.display());
    }
    Ok(())
}

fn resolve_password(arg: Option<String>, from_stdin: bool) -> Result<Option<String>> {
    if from_stdin {
        let mut line = String::new();
        let stdin = std::io::stdin();
        if stdin.is_terminal() {
            eprint!("ssh password: ");
        }
        stdin.lock().read_line(&mut line).context("read password from stdin")?;
        let pw = line.trim_end_matches(['\n', '\r']).to_string();
        if pw.is_empty() {
            anyhow::bail!("--ssh-password-stdin given but stdin was empty");
        }
        return Ok(Some(pw));
    }
    Ok(arg.filter(|s| !s.is_empty()))
}
