//! Metadata-only SSH/PAM/sudo/su authentication log follower.
//!
//! Raw log records never leave this module. The parser selects normalized
//! identity, source, method, session, and executable-only command fields.

use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use agent_contract::{
    AuthenticationEventType, Detection, PrivilegeEventType, PrivilegeMechanism, Severity,
};

use super::{Sensor, SensorEvent};
use crate::config::AuthLogConfig;

pub(crate) struct AuthLogSensor {
    config: AuthLogConfig,
}

enum AuthBackend {
    File(PathBuf),
    Journal,
}

impl AuthLogSensor {
    pub(crate) fn new(config: AuthLogConfig) -> Self {
        Self { config }
    }

    fn select_path(&self) -> anyhow::Result<PathBuf> {
        self.config
            .paths
            .iter()
            .find(|path| fs::File::open(path).is_ok())
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no readable authentication log among {}",
                    self.config
                        .paths
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    fn select_backend(&self) -> anyhow::Result<AuthBackend> {
        if let Ok(path) = self.select_path() {
            return Ok(AuthBackend::File(path));
        }
        anyhow::ensure!(
            journal_readable(),
            "no readable authentication file and journalctl authpriv access is unavailable"
        );
        Ok(AuthBackend::Journal)
    }
}

impl Sensor for AuthLogSensor {
    fn name(&self) -> &'static str {
        "auth_log"
    }

    fn preflight(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.config.poll_interval_ms > 0,
            "auth_log.poll_interval_ms must be greater than zero"
        );
        let _ = self.select_backend()?;
        Ok(())
    }

    fn run(
        self: Box<Self>,
        tx: Sender<SensorEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        match self.select_backend()? {
            AuthBackend::File(path) => run_file(path, &self.config, tx, shutdown),
            AuthBackend::Journal => run_journal(&self.config, tx, shutdown),
        }
    }
}

fn run_file(
    path: PathBuf,
    config: &AuthLogConfig,
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut identity = file_identity(&path)?;
    let mut offset = if config.start_at_end {
        fs::metadata(&path)?.len()
    } else {
        0
    };
    let poll = Duration::from_millis(config.poll_interval_ms.max(50));

    while !shutdown.load(Ordering::Acquire) {
        let current = file_identity(&path)?;
        let length = fs::metadata(&path)?.len();
        if current != identity || length < offset {
            identity = current;
            offset = 0;
        }
        let mut file = fs::File::open(&path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(file);
        let mut line = String::new();
        loop {
            line.clear();
            let bytes = reader.read_line(&mut line)?;
            if bytes == 0 {
                break;
            }
            offset = offset.saturating_add(bytes as u64);
            if line.len() > 64 * 1024 {
                continue;
            }
            if let Some(detection) = parse_line(&line) {
                if tx.send(detection.into()).is_err() {
                    return Ok(());
                }
            }
        }
        sleep_interruptible(poll, &shutdown);
    }
    Ok(())
}

fn journal_readable() -> bool {
    Command::new("journalctl")
        .args([
            "--no-pager",
            "-n",
            "0",
            "-o",
            "short-iso",
            "SYSLOG_FACILITY=10",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn run_journal(
    config: &AuthLogConfig,
    tx: Sender<SensorEvent>,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    let mut command = Command::new("journalctl");
    command.args(["--no-pager", "-f", "-o", "short-iso"]);
    if config.start_at_end {
        command.args(["-n", "0"]);
    }
    command.arg("SYSLOG_FACILITY=10");
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("journalctl stdout was not piped"))?;
    let (line_tx, line_rx) = mpsc::sync_channel::<String>(256);
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else {
                break;
            };
            if line.len() <= 64 * 1024 && line_tx.send(line).is_err() {
                break;
            }
        }
    });
    let poll = Duration::from_millis(config.poll_interval_ms.max(50));
    let mut disconnected = false;
    while !shutdown.load(Ordering::Acquire) {
        match line_rx.recv_timeout(poll) {
            Ok(line) => {
                if let Some(detection) = parse_line(&line) {
                    if tx.send(detection.into()).is_err() {
                        break;
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                disconnected = true;
                break;
            }
        }
    }
    let _ = child.kill();
    let status = child.wait()?;
    let _ = reader.join();
    anyhow::ensure!(
        shutdown.load(Ordering::Acquire) || !disconnected || status.success(),
        "journalctl authentication follower exited unexpectedly"
    );
    Ok(())
}

fn parse_line(line: &str) -> Option<Detection> {
    parse_ssh(line)
        .or_else(|| parse_sudo(line))
        .or_else(|| parse_su(line))
        .or_else(|| parse_account_change(line))
}

fn parse_ssh(line: &str) -> Option<Detection> {
    let pid = daemon_pid(line, "sshd[");
    let session_id = pid.map(|value| format!("sshd-{value}"));
    if let Some(rest) = line.split_once("Accepted ").map(|(_, rest)| rest) {
        let (method, rest) = rest.split_once(" for ")?;
        let (username, rest) = rest.split_once(" from ")?;
        let source_ip = rest.split_whitespace().next().map(safe_ip);
        let fingerprint = rest
            .split_whitespace()
            .find(|token| token.starts_with("SHA256:"))
            .map(safe_identifier);
        return Some(Detection::Authentication {
            severity: if username == "root" {
                Severity::Low
            } else {
                Severity::Info
            },
            event_type: AuthenticationEventType::LoginSuccess,
            username: safe_identifier(username),
            source_ip,
            authentication_method: Some(safe_identifier(method)),
            public_key_fingerprint: fingerprint,
            session_id,
            daemon_pid: pid,
        });
    }
    if let Some(rest) = line.split_once("Failed ").map(|(_, rest)| rest) {
        let (method, rest) = rest.split_once(" for ")?;
        let rest = rest.strip_prefix("invalid user ").unwrap_or(rest);
        let (username, rest) = rest.split_once(" from ")?;
        return Some(Detection::Authentication {
            severity: Severity::Medium,
            event_type: AuthenticationEventType::LoginFailure,
            username: safe_identifier(username),
            source_ip: rest.split_whitespace().next().map(safe_ip),
            authentication_method: Some(safe_identifier(method)),
            public_key_fingerprint: None,
            session_id,
            daemon_pid: pid,
        });
    }
    for (marker, event_type) in [
        (
            "pam_unix(sshd:session): session opened for user ",
            AuthenticationEventType::SessionOpen,
        ),
        (
            "pam_unix(sshd:session): session closed for user ",
            AuthenticationEventType::SessionClose,
        ),
    ] {
        if let Some(rest) = line.split_once(marker).map(|(_, rest)| rest) {
            return Some(Detection::Authentication {
                severity: Severity::Info,
                event_type,
                username: safe_identifier(first_identity(rest)?),
                source_ip: None,
                authentication_method: Some("pam".to_string()),
                public_key_fingerprint: None,
                session_id,
                daemon_pid: pid,
            });
        }
    }
    None
}

fn parse_sudo(line: &str) -> Option<Detection> {
    if line.contains("pam_unix(sudo:auth): authentication failure") {
        return Some(Detection::Privilege {
            severity: Severity::Medium,
            mechanism: PrivilegeMechanism::Sudo,
            event_type: PrivilegeEventType::Failure,
            actor: key_value(line, "user=").map(safe_identifier),
            target_user: None,
            source_ip: key_value(line, "rhost=")
                .filter(|value| !value.is_empty())
                .map(safe_ip),
            tty: key_value(line, "tty=")
                .filter(|value| !value.is_empty())
                .map(safe_identifier),
            command: None,
            command_redacted: false,
            session_id: None,
        });
    }
    let (_, rest) = line.split_once("sudo:")?;
    if !rest.contains("COMMAND=") {
        return None;
    }
    let actor = rest
        .split_once(" : ")
        .map(|(value, _)| safe_identifier(value.trim()));
    let raw_command = semicolon_value(rest, "COMMAND=");
    let (command, command_redacted) = raw_command.map(command_summary).unwrap_or((None, false));
    Some(Detection::Privilege {
        severity: Severity::Low,
        mechanism: PrivilegeMechanism::Sudo,
        event_type: PrivilegeEventType::Success,
        actor,
        target_user: semicolon_value(rest, "USER=").map(safe_identifier),
        source_ip: None,
        tty: semicolon_value(rest, "TTY=").map(safe_identifier),
        command,
        command_redacted,
        session_id: daemon_pid(line, "sudo[").map(|value| format!("sudo-{value}")),
    })
}

fn parse_su(line: &str) -> Option<Detection> {
    let (event_type, marker, severity) =
        if line.contains("pam_unix(su:auth): authentication failure") {
            (
                PrivilegeEventType::Failure,
                "pam_unix(su:auth): authentication failure",
                Severity::Medium,
            )
        } else if line.contains("pam_unix(su:session): session opened for user ") {
            (
                PrivilegeEventType::Success,
                "pam_unix(su:session): session opened for user ",
                Severity::Low,
            )
        } else {
            return None;
        };
    let rest = line.split_once(marker).map(|(_, rest)| rest).unwrap_or("");
    let target_user = if event_type == PrivilegeEventType::Success {
        first_identity(rest).map(safe_identifier)
    } else {
        key_value(line, "user=").map(safe_identifier)
    };
    let actor = rest
        .split_once(" by ")
        .and_then(|(_, value)| first_identity(value))
        .map(safe_identifier)
        .or_else(|| key_value(line, "ruser=").map(safe_identifier));
    Some(Detection::Privilege {
        severity,
        mechanism: PrivilegeMechanism::Su,
        event_type,
        actor,
        target_user,
        source_ip: key_value(line, "rhost=")
            .filter(|value| !value.is_empty())
            .map(safe_ip),
        tty: key_value(line, "tty=")
            .filter(|value| !value.is_empty())
            .map(safe_identifier),
        command: None,
        command_redacted: false,
        session_id: daemon_pid(line, "su[").map(|value| format!("su-{value}")),
    })
}

fn parse_account_change(line: &str) -> Option<Detection> {
    let (mechanism, program) =
        if line.contains(" useradd[") || line.contains(" usermod[") || line.contains(" userdel[") {
            (
                PrivilegeMechanism::Account,
                ["useradd[", "usermod[", "userdel["]
                    .into_iter()
                    .find(|value| line.contains(value))?,
            )
        } else if line.contains(" groupadd[")
            || line.contains(" groupmod[")
            || line.contains(" groupdel[")
        {
            (
                PrivilegeMechanism::Group,
                ["groupadd[", "groupmod[", "groupdel["]
                    .into_iter()
                    .find(|value| line.contains(value))?,
            )
        } else {
            return None;
        };
    let target = ["name=", "user '", "group '"]
        .into_iter()
        .find_map(|marker| {
            let value = line.split_once(marker)?.1;
            let value = if marker.ends_with('\'') {
                value.split('\'').next()?
            } else {
                value.split([',', ' ', ';']).next()?
            };
            safe_name(value).then(|| safe_identifier(value))
        });
    Some(Detection::Privilege {
        severity: Severity::Medium,
        mechanism,
        event_type: PrivilegeEventType::Change,
        actor: Some("root".to_string()),
        target_user: target,
        source_ip: None,
        tty: None,
        command: Some(program.trim_end_matches('[').to_string()),
        command_redacted: true,
        session_id: daemon_pid(line, program).map(|value| format!("identity-{value}")),
    })
}

fn command_summary(raw: &str) -> (Option<String>, bool) {
    let mut tokens = raw.split_whitespace().filter(|token| !token.is_empty());
    let first = loop {
        let token = tokens.next();
        match token {
            Some(value) if is_environment(value) => continue,
            other => break other,
        }
    };
    let Some(first) = first else {
        return (None, false);
    };
    let executable: String = first
        .chars()
        .filter(|ch| !ch.is_control())
        .take(512)
        .collect();
    if executable.is_empty() {
        return (None, false);
    }
    if tokens.next().is_some() || raw.trim() != executable {
        (Some(format!("{executable} <arguments-redacted>")), true)
    } else {
        (Some(executable), false)
    }
}

fn semicolon_value<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    text.split_once(marker)?
        .1
        .split(';')
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn key_value<'a>(text: &'a str, marker: &str) -> Option<&'a str> {
    text.split_once(marker)?
        .1
        .split_whitespace()
        .next()
        .map(|value| value.trim_matches([',', ';']))
}

fn first_identity(text: &str) -> Option<&str> {
    text.split_whitespace()
        .next()
        .map(|value| value.split('(').next().unwrap_or(value))
        .filter(|value| safe_name(value))
}

fn safe_identifier(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':' | '@'))
        .take(512)
        .collect()
}

fn safe_ip(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit() || matches!(ch, '.' | ':' | '%'))
        .take(128)
        .collect()
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
}

fn is_environment(value: &str) -> bool {
    value
        .split_once('=')
        .is_some_and(|(name, _)| safe_name(name))
}

fn daemon_pid(line: &str, marker: &str) -> Option<u32> {
    line.split_once(marker)?.1.split(']').next()?.parse().ok()
}

fn sleep_interruptible(duration: Duration, shutdown: &AtomicBool) {
    let mut remaining = duration;
    while !remaining.is_zero() && !shutdown.load(Ordering::Acquire) {
        let slice = remaining.min(Duration::from_millis(100));
        std::thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
}

fn file_identity(path: &Path) -> anyhow::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(path)?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::mpsc;

    #[test]
    fn parses_ssh_and_privilege_metadata_without_raw_command_arguments() {
        let accepted = parse_line(
            "Jul 31 host sshd[42]: Accepted publickey for sysentry from 10.22.0.100 port 456 ssh2: ED25519 SHA256:abc",
        )
        .unwrap();
        assert!(matches!(
            accepted,
            Detection::Authentication {
                event_type: AuthenticationEventType::LoginSuccess,
                username,
                source_ip: Some(source),
                public_key_fingerprint: Some(fingerprint),
                session_id: Some(session),
                ..
            } if username == "sysentry"
                && source == "10.22.0.100"
                && fingerprint == "SHA256:abc"
                && session == "sshd-42"
        ));

        let sudo = parse_line(
            "Jul 31 host sudo: sysentry : TTY=pts/0 ; PWD=/home/sysentry ; USER=root ; COMMAND=PGPASSWORD=hunter2 /usr/bin/psql --password secret",
        )
        .unwrap();
        let Detection::Privilege {
            command,
            command_redacted,
            ..
        } = sudo
        else {
            panic!("expected privilege event");
        };
        let command = command.unwrap();
        assert!(command_redacted);
        assert_eq!(command, "/usr/bin/psql <arguments-redacted>");
        assert!(!command.contains("hunter2"));
        assert!(!command.contains("secret"));
    }

    #[test]
    fn follower_starts_at_end_and_emits_new_record() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("secure");
        fs::write(
            &path,
            "old sshd[1]: Failed password for old from 192.0.2.1 port 22 ssh2\n",
        )
        .unwrap();
        let sensor = AuthLogSensor::new(AuthLogConfig {
            enabled: true,
            paths: vec![path.clone()],
            poll_interval_ms: 50,
            start_at_end: true,
        });
        sensor.preflight().unwrap();
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || Box::new(sensor).run(tx, worker_shutdown).unwrap());
        std::thread::sleep(Duration::from_millis(100));
        let mut file = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writeln!(
            file,
            "now sshd[2]: Failed password for root from 198.51.100.9 port 22 ssh2"
        )
        .unwrap();
        let event = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
        assert!(matches!(
            event.detection,
            Detection::Authentication {
                event_type: AuthenticationEventType::LoginFailure,
                username,
                ..
            } if username == "root"
        ));
        assert!(
            rx.try_recv().is_err(),
            "historical log records must not replay"
        );
    }
}
