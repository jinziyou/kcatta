//! WinRM remoting via local PowerShell (`pwsh` / `powershell`) and `Invoke-Command`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{bail, Context, Result};
use base64::Engine;

/// WinRM connection parameters.
#[derive(Debug, Clone)]
pub struct WinRmOptions {
    /// Windows account name.
    pub user: String,
    /// Target hostname or IP (no `user@` prefix).
    pub host: String,
    /// Account password (passed via env to the local PowerShell process).
    pub password: String,
    /// WinRM listener port (5985 HTTP, 5986 HTTPS).
    pub port: u16,
    /// Use HTTPS (`UseSSL` on `New-PSSession`).
    pub use_ssl: bool,
    /// Skip TLS certificate checks (lab / self-signed).
    pub skip_cert_check: bool,
}

impl WinRmOptions {
    /// Parse `user@host` plus password and TLS options.
    pub fn from_user_host(
        target: &str,
        password: String,
        port: u16,
        use_ssl: bool,
        skip_cert_check: bool,
    ) -> Result<Self> {
        let (user, host) = parse_user_host(target)?;
        Ok(Self {
            user,
            host,
            password,
            port,
            use_ssl,
            skip_cert_check,
        })
    }
}

/// Result of a remote PowerShell invocation.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    /// Remote stdout (decoded UTF-8).
    pub stdout: String,
    /// Remote stderr (decoded UTF-8).
    pub stderr: String,
    /// Whether the local PowerShell process exited successfully.
    pub success: bool,
}

/// Active WinRM session (local PowerShell wrapper around `New-PSSession`).
pub struct WinRmSession {
    opts: WinRmOptions,
    ps: PathBuf,
}

impl WinRmSession {
    /// Open a session and verify connectivity.
    pub fn connect(opts: WinRmOptions) -> Result<Self> {
        let ps = locate_powershell()?;
        let session = Self { opts, ps };
        let out = session.invoke_raw("Write-Output __ok")?;
        if !out.stdout.contains("__ok") {
            bail!(
                "WinRM connectivity check failed\nstdout: {}\nstderr: {}",
                out.stdout.trim(),
                out.stderr.trim()
            );
        }
        Ok(session)
    }

    /// Run a PowerShell script block on the remote host.
    pub fn exec(&self, ps_script: &str) -> Result<CommandOutput> {
        self.invoke_raw(ps_script)
    }

    /// Upload a local file to an absolute remote path (chunked base64 over WinRM).
    pub fn upload_file(&self, local: &Path, remote: &str) -> Result<()> {
        let bytes =
            std::fs::read(local).with_context(|| format!("read local file {}", local.display()))?;
        let remote_ps = ps_single_quote(remote);
        const CHUNK: usize = 192 * 1024;
        for (i, chunk) in bytes.chunks(CHUNK).enumerate() {
            let b64 = base64::engine::general_purpose::STANDARD.encode(chunk);
            let script = if i == 0 {
                format!(
                    "[IO.File]::WriteAllBytes({remote_ps}, [Convert]::FromBase64String('{b64}'))"
                )
            } else {
                format!(
                    "$fs = [IO.File]::Open({remote_ps}, [IO.FileMode]::Append, [IO.FileAccess]::Write); \
                     try {{ $b = [Convert]::FromBase64String('{b64}'); $fs.Write($b, 0, $b.Length) }} \
                     finally {{ $fs.Close() }}"
                )
            };
            let out = self.invoke_raw(&script)?;
            if !out.success {
                bail!(
                    "upload chunk {i} to {remote} failed\nstdout: {}\nstderr: {}",
                    out.stdout.trim(),
                    out.stderr.trim()
                );
            }
        }
        Ok(())
    }

    /// Download a remote file to a local path.
    pub fn download_file(&self, remote: &str, local: &Path) -> Result<()> {
        let remote_ps = ps_single_quote(remote);
        let out = self.invoke_raw(&format!(
            "$b = [IO.File]::ReadAllBytes({remote_ps}); \
             Write-Output '__b64_begin__'; \
             Write-Output ([Convert]::ToBase64String($b)); \
             Write-Output '__b64_end__'"
        ))?;
        if !out.success {
            bail!(
                "download {remote} failed\nstdout: {}\nstderr: {}",
                out.stdout.trim(),
                out.stderr.trim()
            );
        }
        let b64 = extract_b64_payload(&out.stdout)
            .with_context(|| format!("parse base64 payload for {remote}"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64.trim())
            .context("decode downloaded base64")?;
        if let Some(parent) = local.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        std::fs::write(local, &bytes).with_context(|| format!("write {}", local.display()))?;
        Ok(())
    }

    /// Target hostname or IP for this session.
    pub fn target(&self) -> &str {
        &self.opts.host
    }

    fn invoke_raw(&self, ps_script: &str) -> Result<CommandOutput> {
        let script_b64 = base64::engine::general_purpose::STANDARD.encode(ps_script.as_bytes());
        let wrapper = build_wrapper_script();
        let mut cmd = Command::new(&self.ps);
        cmd.arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-ExecutionPolicy")
            .arg("Bypass")
            .arg("-Command")
            .arg(&wrapper)
            .env("PROBE_WINRM_HOST", &self.opts.host)
            .env("PROBE_WINRM_USER", &self.opts.user)
            .env("PROBE_WINRM_PASSWORD", &self.opts.password)
            .env("PROBE_WINRM_PORT", self.opts.port.to_string())
            .env(
                "PROBE_WINRM_USE_SSL",
                if self.opts.use_ssl { "1" } else { "0" },
            )
            .env(
                "PROBE_WINRM_SKIP_CERT",
                if self.opts.skip_cert_check { "1" } else { "0" },
            )
            .env("PROBE_WINRM_SCRIPT_B64", script_b64);
        map_output(cmd.output().context("spawn local PowerShell for WinRM")?)
    }
}

pub(crate) fn parse_user_host(target: &str) -> Result<(String, String)> {
    let (user, host) = target
        .rsplit_once('@')
        .with_context(|| format!("expected user@host, got {target:?}"))?;
    if user.is_empty() || host.is_empty() {
        bail!("expected user@host, got {target:?}");
    }
    Ok((user.to_string(), host.to_string()))
}

fn locate_powershell() -> Result<PathBuf> {
    for candidate in ["pwsh", "powershell"] {
        if which(candidate)? {
            return Ok(PathBuf::from(candidate));
        }
    }
    bail!(
        "pwsh or powershell not found on PATH — required for WinRM transport \
         (install PowerShell: https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux)"
    );
}

fn which(name: &str) -> Result<bool> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name} >/dev/null 2>&1"))
        .status()
        .with_context(|| format!("locate {name}"))?;
    Ok(out.success())
}

fn build_wrapper_script() -> String {
    r#"
$ErrorActionPreference = 'Stop'
$HostName = $env:PROBE_WINRM_HOST
$User = $env:PROBE_WINRM_USER
$Password = ConvertTo-SecureString $env:PROBE_WINRM_PASSWORD -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential($User, $Password)
$Port = [int]$env:PROBE_WINRM_PORT
$UseSSL = $env:PROBE_WINRM_USE_SSL -eq '1'
$SkipCert = $env:PROBE_WINRM_SKIP_CERT -eq '1'
$SessionOption = New-PSSessionOption -SkipCACheck:$SkipCert -SkipCNCheck:$SkipCert -SkipRevocationCheck:$SkipCert
$Session = New-PSSession -ComputerName $HostName -Credential $Cred -Port $Port -UseSSL:$UseSSL -SessionOption $SessionOption -ErrorAction Stop
try {
  $Block = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:PROBE_WINRM_SCRIPT_B64))
  $Result = Invoke-Command -Session $Session -ScriptBlock ([scriptblock]::Create($Block))
  if ($null -ne $Result) {
    $Result | ForEach-Object { Write-Output $_ }
  }
} finally {
  Remove-PSSession $Session -ErrorAction SilentlyContinue
}
"#
    .trim()
    .to_string()
}

fn ps_single_quote(s: &str) -> String {
    let escaped = s.replace('\'', "''");
    format!("'{escaped}'")
}

fn extract_b64_payload(stdout: &str) -> Result<String> {
    let mut in_payload = false;
    let mut lines = Vec::new();
    for line in stdout.lines() {
        let t = line.trim();
        if t == "__b64_begin__" {
            in_payload = true;
            continue;
        }
        if t == "__b64_end__" {
            break;
        }
        if in_payload {
            lines.push(t);
        }
    }
    if lines.is_empty() {
        bail!("missing __b64_begin__/__b64_end__ markers in WinRM stdout");
    }
    Ok(lines.join(""))
}

fn map_output(out: Output) -> Result<CommandOutput> {
    Ok(CommandOutput {
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        success: out.status.success(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_user_host_splits() {
        let (u, h) = parse_user_host("admin@win10.lab").unwrap();
        assert_eq!(u, "admin");
        assert_eq!(h, "win10.lab");
    }

    #[test]
    fn extract_b64_payload_joins_lines() {
        let stdout = "noise\n__b64_begin__\nYWJj\nZGVm\n__b64_end__\n";
        assert_eq!(extract_b64_payload(stdout).unwrap(), "YWJjZGVm");
    }
}
