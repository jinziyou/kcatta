//! Password → key authentication bootstrap.
//!
//! The rest of fusion-remote uses OpenSSH's ControlMaster pipeline with
//! `BatchMode=yes`, which **does not accept passwords**. This module makes
//! the first connection ergonomic for users who only know a password:
//!
//! 1. Pick or generate a managed ed25519 keypair on the scanner host
//!    (default `~/.config/scdr/fusion-remote/keys/<user>@<host>-<port>.ed25519`).
//! 2. Try key-based login (via `ssh2`). If it works, return that path.
//! 3. Otherwise use the password (via `ssh2`) to append the public key to
//!    the remote `~/.ssh/authorized_keys`, then verify key login.
//! 4. Hand the verified key path back; everything downstream uses keys
//!    only — the password is dropped from memory.

use std::fs;
use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context};
use ssh2::Session;

use crate::sh_quote;

const HANDSHAKE_TIMEOUT_MS: u32 = 10_000;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default managed-key path on the scanner host.
pub fn default_key_path(user: &str, host: &str, port: u16) -> anyhow::Result<PathBuf> {
    let base = dirs::config_dir().ok_or_else(|| anyhow!("cannot resolve user config dir"))?;
    let dir = base.join("scdr/fusion-remote/keys");
    fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let name = format!("{}@{}-{port}.ed25519", sanitize(user), sanitize(host));
    Ok(dir.join(name))
}

/// Ensure key-based SSH login works against `user@host:port`, installing
/// `~/.ssh/authorized_keys` over a one-shot password session if needed.
///
/// Returns the verified private key path.
pub fn ensure_key_auth(
    target: &str,
    port: u16,
    identity: Option<&Path>,
    password: Option<&str>,
) -> anyhow::Result<PathBuf> {
    let (user, host) = parse_target(target)?;

    let key = match identity {
        Some(p) => p.to_path_buf(),
        None => default_key_path(&user, &host, port)?,
    };
    let pub_key = pub_path(&key);

    if !key.exists() {
        generate_keypair(&key, &user, &host)
            .with_context(|| format!("generate ed25519 keypair at {}", key.display()))?;
    } else if !pub_key.exists() {
        bail!(
            "private key {} exists but matching .pub file is missing",
            key.display()
        );
    }

    if key_auth_succeeds(&user, &host, port, &key)? {
        return Ok(key);
    }

    let pw = password.ok_or_else(|| {
        anyhow!(
            "key authentication failed for {user}@{host}:{port} and no password \
             provided; pass --ssh-password / --ssh-password-stdin / set \
             SCDR_SSH_PASSWORD env"
        )
    })?;

    let pub_line =
        fs::read_to_string(&pub_key).with_context(|| format!("read {}", pub_key.display()))?;
    install_public_key(&host, port, &user, pw, pub_line.trim())
        .context("install public key via password ssh")?;

    if !key_auth_succeeds(&user, &host, port, &key)? {
        bail!(
            "public key appended to authorized_keys but key login still \
             fails on {user}@{host}:{port}"
        );
    }
    Ok(key)
}

fn parse_target(t: &str) -> anyhow::Result<(String, String)> {
    let (u, h) = t
        .split_once('@')
        .ok_or_else(|| anyhow!("ssh target must be user@host, got {t:?}"))?;
    if u.is_empty() || h.is_empty() {
        bail!("ssh target has empty user or host: {t:?}");
    }
    Ok((u.to_string(), h.to_string()))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn generate_keypair(path: &Path, user: &str, host: &str) -> anyhow::Result<()> {
    // ssh-keygen will not overwrite, but path is guaranteed not to exist.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let out = Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-N", "", "-q"])
        .arg("-f")
        .arg(path)
        .arg("-C")
        .arg(format!("fusion-remote@{user}@{host}"))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("spawn ssh-keygen (is openssh-client installed?)")?;
    if !out.status.success() {
        bail!(
            "ssh-keygen failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn open_session(host: &str, port: u16, timeout: Duration) -> anyhow::Result<Session> {
    let addr = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("resolve {host}:{port}"))?
        .next()
        .ok_or_else(|| anyhow!("no address for {host}:{port}"))?;
    let tcp = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("tcp connect {addr}"))?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;
    let mut sess = Session::new().context("ssh2 session")?;
    sess.set_tcp_stream(tcp);
    sess.set_timeout(HANDSHAKE_TIMEOUT_MS);
    sess.handshake().context("ssh2 handshake")?;
    Ok(sess)
}

fn key_auth_succeeds(user: &str, host: &str, port: u16, key: &Path) -> anyhow::Result<bool> {
    let sess = match open_session(host, port, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    let pub_key = pub_path(key);
    let pub_arg = if pub_key.exists() {
        Some(pub_key.as_path())
    } else {
        None
    };
    Ok(sess
        .userauth_pubkey_file(user, pub_arg, key, None)
        .map(|()| sess.authenticated())
        .unwrap_or(false))
}

fn install_public_key(
    host: &str,
    port: u16,
    user: &str,
    password: &str,
    pubkey_line: &str,
) -> anyhow::Result<()> {
    let sess = open_session(host, port, CONNECT_TIMEOUT)?;
    sess.userauth_password(user, password)
        .context("ssh password authentication")?;
    if !sess.authenticated() {
        bail!("ssh password auth ok but session not authenticated");
    }

    let q = sh_quote(pubkey_line);
    let cmd = format!(
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && \
         touch ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && \
         (grep -qxF {q} ~/.ssh/authorized_keys || echo {q} >> ~/.ssh/authorized_keys)"
    );

    let mut channel = sess.channel_session().context("open exec channel")?;
    channel.exec(&cmd).context("exec authorized_keys install")?;

    let mut stdout = String::new();
    let _ = channel.read_to_string(&mut stdout);
    let mut stderr = String::new();
    let _ = channel.stderr().read_to_string(&mut stderr);
    channel.wait_close().context("wait_close exec channel")?;
    let exit = channel
        .exit_status()
        .context("read exit_status from exec channel")?;
    if exit != 0 {
        bail!(
            "authorized_keys install exit {exit}\nstdout: {}\nstderr: {}",
            stdout.trim(),
            stderr.trim()
        );
    }
    Ok(())
}

/// `ssh-keygen` writes the public key as `<priv>.pub` — appended, not
/// extension-replaced. `Path::with_extension` is wrong here.
fn pub_path(key: &Path) -> PathBuf {
    let mut p = key.as_os_str().to_owned();
    p.push(".pub");
    PathBuf::from(p)
}

/// Resolve the tool-managed private-key path for `target` (`user@host`) and
/// `port` — the key [`ensure_key_auth`] generates/uses when no explicit
/// identity is given. Useful for cleaning up local state after a revoke.
pub fn managed_key_path(target: &str, port: u16) -> anyhow::Result<PathBuf> {
    let (user, host) = parse_target(target)?;
    default_key_path(&user, &host, port)
}

/// Remove the managed public key this tool installed from the target's
/// `~/.ssh/authorized_keys`, and report whether a line was actually removed
/// (`false` = already absent).
///
/// The inverse of [`ensure_key_auth`]'s key install: it leaves the target's
/// SSH setup as it was before bootstrap. To minimize footprint, **only the
/// exact key line is removed** (whole-line fixed-string match) — every other
/// authorized key is untouched, the file keeps its mode/owner, and `~/.ssh`
/// and `authorized_keys` are left in place (we cannot know whether they
/// pre-existed). Authenticates with the managed key when it still works,
/// falling back to `password`.
pub fn revoke_key(
    target: &str,
    port: u16,
    identity: Option<&Path>,
    password: Option<&str>,
) -> anyhow::Result<bool> {
    let (user, host) = parse_target(target)?;
    let key = match identity {
        Some(p) => p.to_path_buf(),
        None => default_key_path(&user, &host, port)?,
    };
    let pub_key = pub_path(&key);
    let pub_line = fs::read_to_string(&pub_key)
        .with_context(|| format!("read managed public key {}", pub_key.display()))?
        .trim()
        .to_string();
    if pub_line.is_empty() {
        bail!("managed public key {} is empty", pub_key.display());
    }

    let sess = authenticated_session(&user, &host, port, &key, password)?;
    remove_authorized_key(&sess, &pub_line)
}

/// Open an ssh2 session authenticated by `key` if it still works, else by
/// `password`. A session that failed auth cannot be reused, so password auth
/// opens a fresh connection.
fn authenticated_session(
    user: &str,
    host: &str,
    port: u16,
    key: &Path,
    password: Option<&str>,
) -> anyhow::Result<Session> {
    if key.exists() {
        let sess = open_session(host, port, CONNECT_TIMEOUT)?;
        let pub_key = pub_path(key);
        let pub_arg = if pub_key.exists() {
            Some(pub_key.as_path())
        } else {
            None
        };
        if sess
            .userauth_pubkey_file(user, pub_arg, key, None)
            .map(|()| sess.authenticated())
            .unwrap_or(false)
        {
            return Ok(sess);
        }
    }

    let pw = password.ok_or_else(|| {
        anyhow!(
            "cannot authenticate to {user}@{host}:{port} to revoke: managed key \
             auth failed and no password provided (pass --ssh-password or set \
             SCDR_SSH_PASSWORD)"
        )
    })?;
    let sess = open_session(host, port, CONNECT_TIMEOUT)?;
    sess.userauth_password(user, pw)
        .context("ssh password authentication for revoke")?;
    if !sess.authenticated() {
        bail!("ssh password auth ok but session not authenticated");
    }
    Ok(sess)
}

/// Delete exactly `pub_line` from the remote `~/.ssh/authorized_keys`,
/// preserving the file's mode and owner and leaving every other entry intact.
/// Returns `false` when the file or line is absent (nothing changed).
fn remove_authorized_key(sess: &Session, pub_line: &str) -> anyhow::Result<bool> {
    let q = sh_quote(pub_line);
    // Whole-line, fixed-string match (`grep -xF`) so only our exact entry is
    // touched. Rewrite through a temp file in the same directory, then copy the
    // bytes back into the original file so it keeps its inode, mode, and owner.
    let cmd = format!(
        "f=\"$HOME/.ssh/authorized_keys\"; \
         [ -f \"$f\" ] || {{ echo __absent; exit 0; }}; \
         if grep -qxF {q} \"$f\"; then \
           tmp=$(mktemp \"$f.XXXXXX\") || exit 1; \
           grep -vxF {q} \"$f\" > \"$tmp\" || true; \
           cat \"$tmp\" > \"$f\"; rm -f \"$tmp\"; \
           echo __removed; \
         else echo __absent; fi"
    );
    let (stdout, stderr, code) = exec_capture(sess, &cmd)?;
    if code != 0 {
        bail!("revoke command failed (exit {code}): {}", stderr.trim());
    }
    Ok(stdout.contains("__removed"))
}

/// Run `cmd` over an authenticated ssh2 session; capture stdout, stderr, exit.
fn exec_capture(sess: &Session, cmd: &str) -> anyhow::Result<(String, String, i32)> {
    let mut channel = sess.channel_session().context("open exec channel")?;
    channel.exec(cmd).context("exec remote command")?;
    let mut stdout = String::new();
    channel.read_to_string(&mut stdout).ok();
    let mut stderr = String::new();
    channel.stderr().read_to_string(&mut stderr).ok();
    channel.wait_close().context("wait_close exec channel")?;
    let code = channel.exit_status().context("read exit_status")?;
    Ok((stdout, stderr, code))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_target_basic() {
        assert_eq!(
            parse_target("root@10.0.0.1").unwrap(),
            ("root".into(), "10.0.0.1".into())
        );
    }

    #[test]
    fn parse_target_rejects_bad() {
        assert!(parse_target("no-at").is_err());
        assert!(parse_target("@host").is_err());
        assert!(parse_target("user@").is_err());
    }

    #[test]
    fn sanitize_replaces_path_chars() {
        assert_eq!(sanitize("user/with:dots."), "user_with_dots.");
        assert_eq!(sanitize("OK_42"), "OK_42");
    }

    #[test]
    fn pub_path_appends_suffix_not_replace() {
        let key = Path::new("/tmp/k.ed25519");
        assert_eq!(pub_path(key), Path::new("/tmp/k.ed25519.pub"));
        let key2 = Path::new("/tmp/k");
        assert_eq!(pub_path(key2), Path::new("/tmp/k.pub"));
    }

    #[test]
    fn default_key_path_uses_sanitized_names() {
        let p = default_key_path("u/x", "h:1", 22).unwrap();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name, "u_x@h_1-22.ed25519");
    }
}
