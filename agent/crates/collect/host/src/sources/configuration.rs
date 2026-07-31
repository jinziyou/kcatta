//! Metadata-only inventory of sensitive configuration and persistence.
//!
//! The collector walks only allowlisted roots, never follows symlinks, hashes
//! bounded regular files, and never serializes file contents. Persistence
//! commands are reduced to an executable plus an explicit redaction marker.

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use agent_contract::{
    Asset, PersistenceEntry, PersistenceType, SensitiveFile, SensitiveFileCategory,
};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use walkdir::{DirEntry, WalkDir};

use crate::root::join_root;
use crate::ScanContext;

const MAX_FILES: usize = 1_024;
const MAX_HASH_BYTES: u64 = 16 * 1024 * 1024;
const MAX_PARSE_BYTES: u64 = 1024 * 1024;
const MAX_PERSISTENCE: usize = 2_048;

/// Collect allowlisted sensitive-file metadata and startup/access persistence.
pub fn collect(ctx: &ScanContext) -> (Vec<Asset>, Vec<Asset>) {
    let files = sensitive_files(ctx);
    let persistence = persistence_entries(ctx, &files);
    (
        files.into_iter().map(Asset::SensitiveFile).collect(),
        persistence
            .into_iter()
            .map(Asset::PersistenceEntry)
            .collect(),
    )
}

fn sensitive_files(ctx: &ScanContext) -> Vec<SensitiveFile> {
    let mut rows: BTreeMap<String, SensitiveFile> = BTreeMap::new();
    for (relative, category) in [
        ("etc/passwd", SensitiveFileCategory::Identity),
        ("etc/group", SensitiveFileCategory::Identity),
        ("etc/shadow", SensitiveFileCategory::Identity),
        ("etc/gshadow", SensitiveFileCategory::Identity),
        ("etc/nsswitch.conf", SensitiveFileCategory::Identity),
        ("etc/pam.d", SensitiveFileCategory::Identity),
        ("etc/ssh/sshd_config", SensitiveFileCategory::Ssh),
        ("etc/ssh/sshd_config.d", SensitiveFileCategory::Ssh),
        ("etc/sudoers", SensitiveFileCategory::Privilege),
        ("etc/sudoers.d", SensitiveFileCategory::Privilege),
        ("etc/systemd/system", SensitiveFileCategory::Service),
        ("etc/crontab", SensitiveFileCategory::Scheduler),
        ("etc/cron.d", SensitiveFileCategory::Scheduler),
        ("etc/cron.hourly", SensitiveFileCategory::Scheduler),
        ("etc/cron.daily", SensitiveFileCategory::Scheduler),
        ("etc/cron.weekly", SensitiveFileCategory::Scheduler),
        ("etc/cron.monthly", SensitiveFileCategory::Scheduler),
        ("var/spool/cron", SensitiveFileCategory::Scheduler),
        ("var/spool/at", SensitiveFileCategory::Scheduler),
        ("etc/profile", SensitiveFileCategory::Scheduler),
        ("etc/profile.d", SensitiveFileCategory::Scheduler),
        ("etc/modules-load.d", SensitiveFileCategory::Scheduler),
        ("etc/postgresql", SensitiveFileCategory::Database),
        ("var/lib/pgsql", SensitiveFileCategory::Database),
        ("etc/my.cnf", SensitiveFileCategory::Database),
        ("etc/my.cnf.d", SensitiveFileCategory::Database),
        ("etc/mysql", SensitiveFileCategory::Database),
        ("etc/mongod.conf", SensitiveFileCategory::Database),
        ("etc/redis", SensitiveFileCategory::Database),
        ("etc/rabbitmq", SensitiveFileCategory::Database),
        ("etc/kafka", SensitiveFileCategory::Database),
        ("etc/clickhouse-server", SensitiveFileCategory::Database),
        ("etc/neo4j", SensitiveFileCategory::Database),
        ("etc/nginx", SensitiveFileCategory::Application),
        ("etc/httpd", SensitiveFileCategory::Application),
    ] {
        collect_root(ctx, relative, category, &mut rows);
        if rows.len() >= MAX_FILES {
            break;
        }
    }
    for (path, owner) in user_security_files(ctx) {
        if rows.len() >= MAX_FILES {
            break;
        }
        let category = if is_authorized_keys(&display_path(ctx, &path)) {
            SensitiveFileCategory::Ssh
        } else {
            SensitiveFileCategory::Scheduler
        };
        if let Some(mut row) = metadata_row(ctx, &path, category) {
            row.asset_id = stable_id("sensitive-file", &format!("{owner}:{}", row.path));
            rows.insert(row.path.clone(), row);
        }
    }
    rows.into_values().take(MAX_FILES).collect()
}

fn collect_root(
    ctx: &ScanContext,
    relative: &str,
    category: SensitiveFileCategory,
    rows: &mut BTreeMap<String, SensitiveFile>,
) {
    let root = join_root(ctx, relative);
    if root.is_file() {
        if allow_file(category, &root) {
            if let Some(row) = metadata_row(ctx, &root, category) {
                rows.insert(row.path.clone(), row);
            }
        }
        return;
    }
    if !root.is_dir() {
        return;
    }
    for entry in WalkDir::new(&root)
        .follow_links(false)
        .max_depth(6)
        .into_iter()
        .filter_map(Result::ok)
        .filter(regular_file)
        .filter(|entry| allow_file(category, entry.path()))
    {
        if rows.len() >= MAX_FILES {
            break;
        }
        if let Some(row) = metadata_row(ctx, entry.path(), category) {
            rows.insert(row.path.clone(), row);
        }
    }
}

fn regular_file(entry: &DirEntry) -> bool {
    entry.file_type().is_file() && !entry.file_type().is_symlink()
}

fn allow_file(category: SensitiveFileCategory, path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    match category {
        SensitiveFileCategory::Identity => true,
        SensitiveFileCategory::Ssh => {
            name == "sshd_config"
                || name == "authorized_keys"
                || name == "administrators_authorized_keys"
                || extension == "conf"
        }
        SensitiveFileCategory::Privilege => true,
        SensitiveFileCategory::Service => matches!(
            extension.as_str(),
            "service" | "timer" | "socket" | "path" | "target" | "mount"
        ),
        SensitiveFileCategory::Scheduler => true,
        SensitiveFileCategory::Database => {
            matches!(
                name.as_str(),
                "postgresql.conf"
                    | "postgresql.auto.conf"
                    | "pg_hba.conf"
                    | "pg_ident.conf"
                    | "my.cnf"
                    | "mongod.conf"
                    | "mongodb.conf"
                    | "advanced.config"
                    | "enabled_plugins"
            ) || matches!(
                extension.as_str(),
                "conf" | "cnf" | "config" | "properties" | "yaml" | "yml" | "json" | "xml"
            )
        }
        SensitiveFileCategory::Application => matches!(
            extension.as_str(),
            "conf" | "config" | "properties" | "yaml" | "yml" | "json" | "xml"
        ),
    }
}

fn metadata_row(
    ctx: &ScanContext,
    path: &Path,
    category: SensitiveFileCategory,
) -> Option<SensitiveFile> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let display = display_path(ctx, path);
    let mode = unix_mode(&metadata);
    Some(SensitiveFile {
        asset_id: stable_id("sensitive-file", &display),
        parent_asset_id: None,
        path: display,
        category,
        owner_uid: unix_uid(&metadata),
        owner_gid: unix_gid(&metadata),
        mode,
        size_bytes: Some(metadata.len()),
        modified_at: metadata.modified().ok().map(system_time),
        sha256: hash_file(path, MAX_HASH_BYTES),
        world_writable: mode.is_some_and(|value| value & 0o002 != 0),
        group_writable: mode.is_some_and(|value| value & 0o020 != 0),
        setuid: mode.is_some_and(|value| value & 0o4000 != 0),
        setgid: mode.is_some_and(|value| value & 0o2000 != 0),
        acl_risk: None,
    })
}

fn persistence_entries(ctx: &ScanContext, files: &[SensitiveFile]) -> Vec<PersistenceEntry> {
    let mut rows: BTreeMap<String, PersistenceEntry> = BTreeMap::new();
    for file in files {
        match file.category {
            SensitiveFileCategory::Service => collect_systemd(ctx, file, &mut rows),
            SensitiveFileCategory::Scheduler => collect_scheduler(ctx, file, &mut rows),
            SensitiveFileCategory::Ssh if is_authorized_keys(&file.path) => {
                push_entry(
                    &mut rows,
                    entry_from_file(
                        file,
                        PersistenceType::AuthorizedKey,
                        file_name(&file.path),
                        owner_for_authorized_keys(&file.path),
                        None,
                        None,
                    ),
                );
            }
            _ => {}
        }
        if rows.len() >= MAX_PERSISTENCE {
            break;
        }
    }
    collect_systemd_enablement(ctx, &mut rows);
    rows.into_values().take(MAX_PERSISTENCE).collect()
}

fn collect_systemd(
    ctx: &ScanContext,
    file: &SensitiveFile,
    rows: &mut BTreeMap<String, PersistenceEntry>,
) {
    let entry_type = match Path::new(&file.path)
        .extension()
        .and_then(|value| value.to_str())
    {
        Some("service") => PersistenceType::SystemdService,
        Some("timer") => PersistenceType::SystemdTimer,
        _ => return,
    };
    let raw_path = join_root(ctx, file.path.trim_start_matches('/'));
    let text = read_bounded_text(&raw_path).unwrap_or_default();
    let directive = if entry_type == PersistenceType::SystemdService {
        setting(&text, "ExecStart")
    } else {
        setting(&text, "OnCalendar").or_else(|| setting(&text, "OnBootSec"))
    };
    let (command, redacted) = directive.map(command_summary).unwrap_or((None, false));
    let mut entry = entry_from_file(
        file,
        entry_type,
        file_name(&file.path),
        setting(&text, "User").map(safe_label),
        command,
        None,
    );
    entry.command_redacted = redacted;
    add_permission_risks(file, &mut entry.risk_flags);
    push_entry(rows, entry);
}

fn collect_scheduler(
    ctx: &ScanContext,
    file: &SensitiveFile,
    rows: &mut BTreeMap<String, PersistenceEntry>,
) {
    if file.path.contains("/modules-load.d/") {
        let text = read_bounded_text(&join_root(ctx, file.path.trim_start_matches('/')))
            .unwrap_or_default();
        for module in text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.split_whitespace().next().unwrap_or(""))
            .filter(|name| safe_name(name))
            .take(128)
        {
            let mut entry = entry_from_file(
                file,
                PersistenceType::KernelModule,
                module.to_string(),
                Some("root".to_string()),
                None,
                Some(true),
            );
            add_permission_risks(file, &mut entry.risk_flags);
            push_entry(rows, entry);
        }
        return;
    }
    if file.path == "/etc/profile"
        || file.path.contains("/profile.d/")
        || file.path.ends_with("/.profile")
        || file.path.ends_with("/.bashrc")
    {
        let mut entry = entry_from_file(
            file,
            PersistenceType::ShellProfile,
            file_name(&file.path),
            owner_for_home_file(&file.path),
            None,
            Some(true),
        );
        add_permission_risks(file, &mut entry.risk_flags);
        push_entry(rows, entry);
        return;
    }
    if file.path.contains("/var/spool/at/") {
        let mut entry = entry_from_file(
            file,
            PersistenceType::AtJob,
            file_name(&file.path),
            None,
            None,
            Some(true),
        );
        add_permission_risks(file, &mut entry.risk_flags);
        push_entry(rows, entry);
        return;
    }
    if !is_cron_path(&file.path) {
        return;
    }
    let text =
        read_bounded_text(&join_root(ctx, file.path.trim_start_matches('/'))).unwrap_or_default();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || looks_like_environment(line) {
            continue;
        }
        let Some((principal, raw_command)) = parse_cron_line(&file.path, line) else {
            continue;
        };
        let (command, command_redacted) = command_summary(raw_command);
        let mut entry = entry_from_file(
            file,
            PersistenceType::Cron,
            format!("{}:{}", file_name(&file.path), index + 1),
            principal,
            command,
            Some(true),
        );
        entry.command_redacted = command_redacted;
        add_permission_risks(file, &mut entry.risk_flags);
        push_entry(rows, entry);
    }
}

fn collect_systemd_enablement(ctx: &ScanContext, rows: &mut BTreeMap<String, PersistenceEntry>) {
    let root = join_root(ctx, "etc/systemd/system");
    if !root.is_dir() {
        return;
    }
    for entry in WalkDir::new(&root)
        .follow_links(false)
        .max_depth(4)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_symlink())
        .take(MAX_PERSISTENCE)
    {
        let path = display_path(ctx, entry.path());
        let entry_type = if path.ends_with(".timer") {
            PersistenceType::SystemdTimer
        } else if path.ends_with(".service") {
            PersistenceType::SystemdService
        } else {
            continue;
        };
        let name = file_name(&path);
        let key = stable_id("persistence", &format!("{entry_type:?}:{path}"));
        rows.entry(key.clone()).or_insert(PersistenceEntry {
            asset_id: key,
            parent_asset_id: None,
            entry_type,
            name,
            source_path: path,
            principal: None,
            command: None,
            command_redacted: false,
            enabled: Some(true),
            content_sha256: None,
            modified_at: fs::symlink_metadata(entry.path())
                .ok()
                .and_then(|metadata| metadata.modified().ok())
                .map(system_time),
            risk_flags: Vec::new(),
        });
    }
}

fn entry_from_file(
    file: &SensitiveFile,
    entry_type: PersistenceType,
    name: String,
    principal: Option<String>,
    command: Option<String>,
    enabled: Option<bool>,
) -> PersistenceEntry {
    PersistenceEntry {
        asset_id: stable_id(
            "persistence",
            &format!("{entry_type:?}:{}:{name}", file.path),
        ),
        parent_asset_id: None,
        entry_type,
        name,
        source_path: file.path.clone(),
        principal,
        command,
        command_redacted: false,
        enabled,
        content_sha256: file.sha256.clone(),
        modified_at: file.modified_at,
        risk_flags: Vec::new(),
    }
}

fn push_entry(rows: &mut BTreeMap<String, PersistenceEntry>, entry: PersistenceEntry) {
    if rows.len() < MAX_PERSISTENCE {
        rows.insert(entry.asset_id.clone(), entry);
    }
}

fn add_permission_risks(file: &SensitiveFile, flags: &mut Vec<String>) {
    if file.world_writable {
        flags.push("world_writable_source".to_string());
    }
    if file.group_writable {
        flags.push("group_writable_source".to_string());
    }
    if file.owner_uid.is_some_and(|uid| uid != 0) && file.path.starts_with("/etc/") {
        flags.push("non_root_owned_system_source".to_string());
    }
}

fn parse_cron_line<'a>(path: &str, line: &'a str) -> Option<(Option<String>, &'a str)> {
    if line.starts_with('@') {
        let mut fields = line.splitn(3, char::is_whitespace);
        let _schedule = fields.next()?;
        if path == "/etc/crontab" || path.contains("/etc/cron.d/") {
            let principal = fields.next().filter(|value| safe_name(value))?.to_string();
            return Some((Some(principal), fields.next()?.trim()));
        }
        return Some((owner_for_home_file(path), fields.next()?.trim()));
    }
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return None;
    }
    let system = path == "/etc/crontab" || path.contains("/etc/cron.d/");
    let command_index = if system { 6 } else { 5 };
    if fields.len() <= command_index {
        return None;
    }
    let principal = system
        .then(|| fields[5])
        .filter(|value| safe_name(value))
        .map(str::to_string)
        .or_else(|| owner_for_home_file(path));
    let command = line
        .splitn(command_index + 1, char::is_whitespace)
        .nth(command_index)?;
    Some((principal, command.trim()))
}

fn command_summary(raw: &str) -> (Option<String>, bool) {
    let mut tokens = raw.split_whitespace().filter(|token| !token.is_empty());
    let first = loop {
        let token = tokens.next();
        match token {
            Some(value) if looks_like_environment(value) => continue,
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

fn setting<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn read_bounded_text(path: &Path) -> Option<String> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_PARSE_BYTES {
        return None;
    }
    fs::read_to_string(path).ok()
}

fn hash_file(path: &Path, max_bytes: u64) -> Option<String> {
    let mut file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > max_bytes {
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
    Some(hex_bytes(&hasher.finalize()))
}

fn user_security_files(ctx: &ScanContext) -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    let Ok(passwd) = fs::read_to_string(join_root(ctx, "etc/passwd")) else {
        return paths;
    };
    for line in passwd.lines().take(4_096) {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 6 || !fields[5].starts_with('/') {
            continue;
        }
        let home = fields[5].trim_start_matches('/');
        for relative in [
            format!("{home}/.ssh/authorized_keys"),
            format!("{home}/.profile"),
            format!("{home}/.bashrc"),
        ] {
            let path = join_root(ctx, &relative);
            if path.is_file() {
                paths.push((path, fields[0].to_string()));
            }
        }
    }
    paths
}

fn is_authorized_keys(path: &str) -> bool {
    path.ends_with("/authorized_keys") || path.ends_with("/administrators_authorized_keys")
}

fn is_cron_path(path: &str) -> bool {
    path == "/etc/crontab" || path.contains("/etc/cron.") || path.contains("/var/spool/cron/")
}

fn looks_like_environment(value: &str) -> bool {
    let Some((name, _)) = value.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
}

fn safe_label(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | '@'))
        .take(256)
        .collect()
}

fn owner_for_authorized_keys(path: &str) -> Option<String> {
    owner_for_home_file(path).or_else(|| path.starts_with("/root/").then(|| "root".to_string()))
}

fn owner_for_home_file(path: &str) -> Option<String> {
    path.strip_prefix("/home/")
        .and_then(|rest| rest.split('/').next())
        .filter(|name| safe_name(name))
        .map(str::to_string)
}

fn file_name(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or(path)
        .to_string()
}

fn display_path(ctx: &ScanContext, path: &Path) -> String {
    let relative = path.strip_prefix(&ctx.scan_root).unwrap_or(path);
    format!("/{}", relative.to_string_lossy().trim_start_matches('/'))
}

fn stable_id(prefix: &str, value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    format!("{prefix}-{}", hex_bytes(&digest))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn system_time(value: SystemTime) -> DateTime<Utc> {
    value.into()
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.mode() & 0o7777)
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn unix_uid(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.uid())
}

#[cfg(not(unix))]
fn unix_uid(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(unix)]
fn unix_gid(metadata: &fs::Metadata) -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    Some(metadata.gid())
}

#[cfg(not(unix))]
fn unix_gid(_metadata: &fs::Metadata) -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collects_metadata_and_redacts_persistence_commands() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("etc/systemd/system")).unwrap();
        fs::create_dir_all(root.join("etc/cron.d")).unwrap();
        fs::create_dir_all(root.join("home/alice/.ssh")).unwrap();
        fs::write(
            root.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
        )
        .unwrap();
        fs::write(
            root.join("etc/systemd/system/db.service"),
            "[Service]\nUser=postgres\nExecStart=/usr/bin/postgres --password hunter2\n",
        )
        .unwrap();
        fs::write(
            root.join("etc/cron.d/backup"),
            "0 1 * * * root PGPASSWORD=hunter2 /usr/bin/pg_dump app\n",
        )
        .unwrap();
        fs::write(
            root.join("home/alice/.ssh/authorized_keys"),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest alice@test\n",
        )
        .unwrap();

        let (files, persistence) = collect(&ScanContext::at(root));
        assert!(files.iter().any(|asset| matches!(
            asset,
            Asset::SensitiveFile(file) if file.path == "/etc/systemd/system/db.service"
                && file.sha256.is_some()
        )));
        let serialized = serde_json::to_string(&persistence).unwrap();
        assert!(!serialized.contains("hunter2"));
        assert!(serialized.contains("<arguments-redacted>"));
        assert!(persistence.iter().any(|asset| matches!(
            asset,
            Asset::PersistenceEntry(entry)
                if entry.entry_type == PersistenceType::AuthorizedKey
        )));
    }

    #[test]
    fn database_relation_files_are_not_allowlisted() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        fs::create_dir_all(root.join("var/lib/pgsql/data/base/1")).unwrap();
        fs::write(root.join("var/lib/pgsql/data/postgresql.conf"), "ssl=on\n").unwrap();
        fs::write(root.join("var/lib/pgsql/data/base/1/16384"), b"row bytes").unwrap();
        let (files, _) = collect(&ScanContext::at(root));
        let paths: Vec<&str> = files
            .iter()
            .filter_map(|asset| match asset {
                Asset::SensitiveFile(file) => Some(file.path.as_str()),
                _ => None,
            })
            .collect();
        assert!(paths.contains(&"/var/lib/pgsql/data/postgresql.conf"));
        assert!(!paths.iter().any(|path| path.ends_with("/16384")));
    }
}
