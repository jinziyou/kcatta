//! Live Linux process inventory from `/proc`.
//!
//! The collector is metadata-only. Command lines are redacted before they enter
//! an [`Asset`], and environment files are never read.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::Path;

use agent_contract::{Asset, ProcessAsset};
use sha2::{Digest, Sha256};

use crate::root::join_root;
use crate::ScanContext;

const MAX_PROCESSES: usize = 2_048;
const MAX_EXECUTABLE_BYTES: u64 = 256 * 1024 * 1024;

/// Collect a bounded, deterministic snapshot of live processes.
pub fn collect(ctx: &ScanContext) -> Vec<Asset> {
    let usernames = account_names(ctx);
    let mut executable_hashes: HashMap<String, Option<String>> = HashMap::new();
    let Ok(entries) = fs::read_dir(join_root(ctx, "proc")) else {
        return Vec::new();
    };
    let mut pids: Vec<u32> = entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .collect();
    pids.sort_unstable();
    pids.truncate(MAX_PROCESSES);

    pids.into_iter()
        .filter_map(|pid| collect_one(ctx, pid, &usernames, &mut executable_hashes))
        .map(Asset::Process)
        .collect()
}

fn collect_one(
    ctx: &ScanContext,
    pid: u32,
    usernames: &HashMap<u32, String>,
    executable_hashes: &mut HashMap<String, Option<String>>,
) -> Option<ProcessAsset> {
    let dir = join_root(ctx, &format!("proc/{pid}"));
    let status = fs::read_to_string(dir.join("status")).ok();
    let name = status
        .as_deref()
        .and_then(|text| status_value(text, "Name"))
        .map(str::to_string)
        .or_else(|| {
            fs::read_to_string(dir.join("comm"))
                .ok()
                .map(|value| value.trim().to_string())
        })
        .filter(|value| !value.is_empty())?;
    let uid = status
        .as_deref()
        .and_then(|text| status_value(text, "Uid"))
        .and_then(|value| value.split_whitespace().next())
        .and_then(|value| value.parse::<u32>().ok());
    let ppid = fs::read_to_string(dir.join("stat"))
        .ok()
        .and_then(|value| parse_ppid(&value));
    let exe_path = fs::read_link(dir.join("exe"))
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let executable_sha256 = exe_path.as_ref().and_then(|path| {
        executable_hashes
            .entry(path.clone())
            .or_insert_with(|| hash_executable(&dir.join("exe")))
            .clone()
    });
    let raw_args = fs::read(dir.join("cmdline")).unwrap_or_default();
    let (command_line, command_line_redacted) = redact_cmdline(&raw_args);
    let cgroup = fs::read_to_string(dir.join("cgroup")).unwrap_or_default();
    let (systemd_unit, container_id) = parse_cgroup(&cgroup);

    Some(ProcessAsset {
        asset_id: format!("process-{pid}"),
        parent_asset_id: None,
        pid,
        ppid,
        name,
        exe_path,
        executable_sha256,
        uid,
        username: uid.and_then(|value| usernames.get(&value).cloned()),
        command_line,
        command_line_redacted,
        systemd_unit,
        container_id,
        started_at: None,
    })
}

fn account_names(ctx: &ScanContext) -> HashMap<u32, String> {
    let Ok(text) = fs::read_to_string(join_root(ctx, "etc/passwd")) else {
        return HashMap::new();
    };
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split(':');
            let name = fields.next()?.to_string();
            let _password = fields.next()?;
            let uid = fields.next()?.parse::<u32>().ok()?;
            Some((uid, name))
        })
        .collect()
}

fn status_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        (name == key).then(|| value.trim())
    })
}

fn parse_ppid(stat: &str) -> Option<u32> {
    let end = stat.rfind(')')?;
    stat.get(end + 1..)?.split_whitespace().nth(1)?.parse().ok()
}

fn hash_executable(path: &Path) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_EXECUTABLE_BYTES {
        return None;
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

fn redact_cmdline(raw: &[u8]) -> (Option<String>, bool) {
    let mut args: Vec<String> = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    if args.is_empty() {
        return (None, false);
    }

    let mut redacted = false;
    let mut redact_next = false;
    for arg in &mut args {
        *arg = arg
            .chars()
            .map(|ch| if ch.is_control() { ' ' } else { ch })
            .collect();
        if redact_next {
            *arg = "<redacted>".to_string();
            redacted = true;
            redact_next = false;
            continue;
        }

        let lower = arg.to_ascii_lowercase();
        if lower == "bearer" {
            redact_next = true;
            continue;
        }
        if let Some((key, _value)) = arg.split_once('=') {
            if sensitive_key(key) {
                *arg = format!("{key}=<redacted>");
                redacted = true;
                continue;
            }
        }
        if sensitive_key(arg) {
            redact_next = true;
            continue;
        }
        if let Some(value) = redact_url_userinfo(arg) {
            *arg = value;
            redacted = true;
        }
    }
    (Some(args.join(" ")), redacted)
}

fn sensitive_key(value: &str) -> bool {
    let key = value
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    matches!(
        key.as_str(),
        "password"
            | "passwd"
            | "passphrase"
            | "token"
            | "access-token"
            | "auth-token"
            | "authorization"
            | "secret"
            | "client-secret"
            | "api-key"
            | "access-key"
            | "secret-key"
            | "private-key"
            | "connection-string"
            | "database-url"
            | "db-url"
            | "dsn"
            | "pgpassword"
            | "redis-password"
    )
}

fn redact_url_userinfo(value: &str) -> Option<String> {
    let scheme = value.find("://")?;
    let authority_start = scheme + 3;
    let authority = value.get(authority_start..)?;
    let at = authority.find('@')?;
    let userinfo = authority.get(..at)?;
    if !userinfo.contains(':') {
        return None;
    }
    Some(format!(
        "{}<redacted>@{}",
        &value[..authority_start],
        &authority[at + 1..]
    ))
}

fn parse_cgroup(text: &str) -> (Option<String>, Option<String>) {
    let mut unit = None;
    let mut container = None;
    for component in text
        .lines()
        .filter_map(|line| line.rsplit_once(':').map(|(_, path)| path))
        .flat_map(|path| path.split('/'))
    {
        if unit.is_none() && (component.ends_with(".service") || component.ends_with(".scope")) {
            unit = Some(component.to_string());
        }
        if container.is_none() {
            container = container_id(component);
        }
    }
    (unit, container)
}

fn container_id(component: &str) -> Option<String> {
    let without_scope = component.strip_suffix(".scope").unwrap_or(component);
    let candidate = ["docker-", "cri-containerd-", "libpod-"]
        .into_iter()
        .find_map(|prefix| without_scope.strip_prefix(prefix))
        .unwrap_or(without_scope);
    (candidate.len() >= 12
        && candidate.len() <= 64
        && candidate.chars().all(|ch| ch.is_ascii_hexdigit()))
    .then(|| candidate.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn command_line_redacts_secrets_and_url_userinfo() {
        let raw = b"app\0--password\0hunter2\0--api-key=abc\0postgres://u:p@db/x\0";
        let (value, redacted) = redact_cmdline(raw);
        let value = value.unwrap();
        assert!(redacted);
        assert!(!value.contains("hunter2"));
        assert!(!value.contains("abc"));
        assert!(!value.contains("u:p"));
        assert!(value.contains("--password <redacted>"));
        assert!(value.contains("--api-key=<redacted>"));
        assert!(value.contains("postgres://<redacted>@db/x"));
    }

    #[test]
    fn collects_process_metadata_without_environment() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("proc/42")).unwrap();
        fs::create_dir_all(root.join("etc")).unwrap();
        fs::write(
            root.join("etc/passwd"),
            "svc:x:1001:1001::/:/sbin/nologin\n",
        )
        .unwrap();
        fs::write(
            root.join("proc/42/status"),
            "Name:\tpostgres\nUid:\t1001\t1001\t1001\t1001\n",
        )
        .unwrap();
        fs::write(
            root.join("proc/42/stat"),
            "42 (postgres worker) S 1 0 0 0\n",
        )
        .unwrap();
        fs::write(
            root.join("proc/42/cmdline"),
            b"postgres\0-D\0/var/lib/pgsql/data\0--password=secret\0",
        )
        .unwrap();
        fs::write(
            root.join("proc/42/cgroup"),
            "0::/system.slice/postgresql.service\n",
        )
        .unwrap();
        symlink("/usr/bin/postgres", root.join("proc/42/exe")).unwrap();

        let rows = collect(&ScanContext::at(root));
        let Asset::Process(process) = &rows[0] else {
            panic!("expected process");
        };
        assert_eq!(process.ppid, Some(1));
        assert_eq!(process.username.as_deref(), Some("svc"));
        assert_eq!(process.systemd_unit.as_deref(), Some("postgresql.service"));
        assert!(process.command_line_redacted);
        assert!(!process.command_line.as_deref().unwrap().contains("secret"));
    }
}
