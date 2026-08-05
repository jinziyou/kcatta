//! Metadata-only inventory of sensitive configuration and persistence.
//!
//! The collector walks only allowlisted roots, never follows symlinks, hashes
//! bounded regular files, and never serializes file contents. Persistence
//! commands are reduced to an executable plus an explicit redaction marker.

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Read};
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
const SENSITIVE_MAX_DEPTH: usize = 6;
const SYSTEMD_ENABLEMENT_MAX_DEPTH: usize = 4;

/// Same-pass diagnostics for categories derived from security-sensitive files.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct ConfigurationCoverage {
    sensitive_file_incomplete: bool,
    persistence_entry_incomplete: bool,
}

impl ConfigurationCoverage {
    pub(crate) fn sensitive_file_incomplete(self) -> bool {
        self.sensitive_file_incomplete
    }

    pub(crate) fn persistence_entry_incomplete(self) -> bool {
        self.persistence_entry_incomplete || self.sensitive_file_incomplete
    }
}

pub(crate) fn sensitive_file_limit_reached(record_count: usize) -> bool {
    record_count >= MAX_FILES
}

pub(crate) fn persistence_limit_reached(record_count: usize) -> bool {
    record_count >= MAX_PERSISTENCE
}

/// Collect allowlisted sensitive-file metadata and startup/access persistence.
#[allow(dead_code)] // Compatibility wrapper for crate-local callers outside the scan runner.
pub fn collect(ctx: &ScanContext) -> (Vec<Asset>, Vec<Asset>) {
    let (files, persistence, _) = collect_with_coverage(ctx);
    (files, persistence)
}

/// Collect configuration assets and the read diagnostics from the same pass.
pub(crate) fn collect_with_coverage(
    ctx: &ScanContext,
) -> (Vec<Asset>, Vec<Asset>, ConfigurationCoverage) {
    let mut coverage = ConfigurationCoverage::default();
    let files = sensitive_files(ctx, &mut coverage);
    let persistence = persistence_entries(ctx, &files, &mut coverage);
    (
        files.into_iter().map(Asset::SensitiveFile).collect(),
        persistence
            .into_iter()
            .map(Asset::PersistenceEntry)
            .collect(),
        coverage,
    )
}

fn sensitive_files(ctx: &ScanContext, coverage: &mut ConfigurationCoverage) -> Vec<SensitiveFile> {
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
        collect_root(ctx, relative, category, &mut rows, coverage);
        if rows.len() >= MAX_FILES {
            break;
        }
    }
    for (path, owner) in user_security_files(ctx, coverage) {
        if rows.len() >= MAX_FILES {
            break;
        }
        let category = if is_authorized_keys(&display_path(ctx, &path)) {
            SensitiveFileCategory::Ssh
        } else {
            SensitiveFileCategory::Scheduler
        };
        if let Some(mut row) = metadata_row(ctx, &path, category, coverage) {
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
    coverage: &mut ConfigurationCoverage,
) {
    let root = join_root(ctx, relative);
    let metadata = match fs::symlink_metadata(&root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(_) => {
            coverage.sensitive_file_incomplete = true;
            return;
        }
    };
    if metadata.file_type().is_file() {
        if allow_file(category, &root) {
            if let Some(row) = metadata_row(ctx, &root, category, coverage) {
                rows.insert(row.path.clone(), row);
            }
        }
        return;
    }
    if !metadata.file_type().is_dir() {
        return;
    }
    for item in WalkDir::new(&root)
        .follow_links(false)
        .max_depth(SENSITIVE_MAX_DEPTH)
        .into_iter()
    {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                coverage.sensitive_file_incomplete = true;
                continue;
            }
        };
        if entry.depth() == SENSITIVE_MAX_DEPTH
            && entry.file_type().is_dir()
            && directory_has_omitted_children(entry.path())
        {
            coverage.sensitive_file_incomplete = true;
        }
        if !regular_file(&entry) || !allow_file(category, entry.path()) {
            continue;
        }
        if rows.len() >= MAX_FILES {
            break;
        }
        if let Some(row) = metadata_row(ctx, entry.path(), category, coverage) {
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
    coverage: &mut ConfigurationCoverage,
) -> Option<SensitiveFile> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => {
            coverage.sensitive_file_incomplete = true;
            return None;
        }
    };
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return None;
    }
    let display = display_path(ctx, path);
    let mode = unix_mode(&metadata);
    let modified_at = match metadata.modified() {
        Ok(value) => Some(system_time(value)),
        Err(_) => {
            coverage.sensitive_file_incomplete = true;
            None
        }
    };
    let sha256 = match hash_file(path, MAX_HASH_BYTES) {
        Ok(Some(value)) => Some(value),
        Ok(None) => {
            coverage.sensitive_file_incomplete = true;
            None
        }
        Err(_) => {
            coverage.sensitive_file_incomplete = true;
            None
        }
    };
    Some(SensitiveFile {
        asset_id: stable_id("sensitive-file", &display),
        parent_asset_id: None,
        path: display,
        category,
        owner_uid: unix_uid(&metadata),
        owner_gid: unix_gid(&metadata),
        mode,
        size_bytes: Some(metadata.len()),
        modified_at,
        sha256,
        world_writable: mode.is_some_and(|value| value & 0o002 != 0),
        group_writable: mode.is_some_and(|value| value & 0o020 != 0),
        setuid: mode.is_some_and(|value| value & 0o4000 != 0),
        setgid: mode.is_some_and(|value| value & 0o2000 != 0),
        acl_risk: None,
    })
}

fn persistence_entries(
    ctx: &ScanContext,
    files: &[SensitiveFile],
    coverage: &mut ConfigurationCoverage,
) -> Vec<PersistenceEntry> {
    let mut rows: BTreeMap<String, PersistenceEntry> = BTreeMap::new();
    for file in files {
        match file.category {
            SensitiveFileCategory::Service => collect_systemd(ctx, file, &mut rows, coverage),
            SensitiveFileCategory::Scheduler => collect_scheduler(ctx, file, &mut rows, coverage),
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
    collect_systemd_enablement(ctx, &mut rows, coverage);
    rows.into_values().take(MAX_PERSISTENCE).collect()
}

fn collect_systemd(
    ctx: &ScanContext,
    file: &SensitiveFile,
    rows: &mut BTreeMap<String, PersistenceEntry>,
    coverage: &mut ConfigurationCoverage,
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
    let text = persistence_text(&raw_path, coverage);
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
    coverage: &mut ConfigurationCoverage,
) {
    if file.path.contains("/modules-load.d/") {
        let text = persistence_text(&join_root(ctx, file.path.trim_start_matches('/')), coverage);
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
    let text = persistence_text(&join_root(ctx, file.path.trim_start_matches('/')), coverage);
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

fn collect_systemd_enablement(
    ctx: &ScanContext,
    rows: &mut BTreeMap<String, PersistenceEntry>,
    coverage: &mut ConfigurationCoverage,
) {
    let root = join_root(ctx, "etc/systemd/system");
    match fs::symlink_metadata(&root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return,
        Err(_) => {
            coverage.persistence_entry_incomplete = true;
            return;
        }
    }
    for item in WalkDir::new(&root)
        .follow_links(false)
        .max_depth(SYSTEMD_ENABLEMENT_MAX_DEPTH)
        .into_iter()
    {
        let entry = match item {
            Ok(entry) => entry,
            Err(_) => {
                coverage.persistence_entry_incomplete = true;
                continue;
            }
        };
        if entry.depth() == SYSTEMD_ENABLEMENT_MAX_DEPTH
            && entry.file_type().is_dir()
            && directory_has_omitted_children(entry.path())
        {
            coverage.persistence_entry_incomplete = true;
        }
        if !entry.file_type().is_symlink() {
            continue;
        }
        if rows.len() >= MAX_PERSISTENCE {
            break;
        }
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
        let modified_at = match fs::symlink_metadata(entry.path()) {
            Ok(metadata) => match metadata.modified() {
                Ok(value) => Some(system_time(value)),
                Err(_) => {
                    coverage.persistence_entry_incomplete = true;
                    None
                }
            },
            Err(_) => {
                coverage.persistence_entry_incomplete = true;
                None
            }
        };
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
            modified_at,
            risk_flags: Vec::new(),
        });
    }
}

fn directory_has_omitted_children(path: &Path) -> bool {
    match fs::read_dir(path) {
        Ok(mut children) => children.next().is_some(),
        Err(_) => true,
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

fn persistence_text(path: &Path, coverage: &mut ConfigurationCoverage) -> String {
    match read_bounded_text(path) {
        Ok(Some(text)) => text,
        Ok(None) | Err(_) => {
            coverage.persistence_entry_incomplete = true;
            String::new()
        }
    }
}

fn read_bounded_text(path: &Path) -> io::Result<Option<String>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_PARSE_BYTES {
        return Ok(None);
    }
    fs::read_to_string(path).map(Some)
}

fn hash_file(path: &Path, max_bytes: u64) -> io::Result<Option<String>> {
    let mut file = fs::File::open(path)?;
    if file.metadata()?.len() > max_bytes {
        return Ok(None);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Some(hex_bytes(&hasher.finalize())))
}

fn user_security_files(
    ctx: &ScanContext,
    coverage: &mut ConfigurationCoverage,
) -> Vec<(PathBuf, String)> {
    let mut paths = Vec::new();
    let passwd_path = join_root(ctx, "etc/passwd");
    let passwd = match fs::read_to_string(&passwd_path) {
        Ok(passwd) => passwd,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return paths,
        Err(_) => {
            coverage.sensitive_file_incomplete = true;
            return paths;
        }
    };
    let mut lines = passwd.lines();
    for line in lines.by_ref().take(4_096) {
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
            match fs::symlink_metadata(&path) {
                Ok(metadata)
                    if metadata.file_type().is_file() && !metadata.file_type().is_symlink() =>
                {
                    paths.push((path, fields[0].to_string()));
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(_) => coverage.sensitive_file_incomplete = true,
            }
        }
    }
    if lines.next().is_some() {
        coverage.sensitive_file_incomplete = true;
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

    #[test]
    fn coverage_marks_traversal_metadata_and_persistence_read_failures() {
        let blocked = tempfile::tempdir().unwrap();
        fs::write(blocked.path().join("etc"), b"not a directory").unwrap();
        let (_, _, coverage) = collect_with_coverage(&ScanContext::at(blocked.path()));
        assert!(coverage.sensitive_file_incomplete());
        assert!(coverage.persistence_entry_incomplete());

        let unreadable = tempfile::tempdir().unwrap();
        fs::create_dir_all(unreadable.path().join("etc/systemd/system")).unwrap();
        fs::write(
            unreadable.path().join("etc/systemd/system/bad.service"),
            [0xff, 0xfe],
        )
        .unwrap();
        let (files, persistence, coverage) =
            collect_with_coverage(&ScanContext::at(unreadable.path()));
        assert!(files.iter().any(|asset| matches!(
            asset,
            Asset::SensitiveFile(file) if file.path.ends_with("bad.service")
        )));
        assert!(persistence.iter().any(|asset| matches!(
            asset,
            Asset::PersistenceEntry(entry) if entry.source_path.ends_with("bad.service")
        )));
        assert!(!coverage.sensitive_file_incomplete());
        assert!(coverage.persistence_entry_incomplete());
    }

    #[test]
    fn coverage_marks_bounded_walk_depth_truncation() {
        let sensitive = tempfile::tempdir().unwrap();
        let deep_sensitive = sensitive.path().join("etc/pam.d/1/2/3/4/5/6/omitted.conf");
        fs::create_dir_all(deep_sensitive.parent().unwrap()).unwrap();
        fs::write(&deep_sensitive, "auth required test.so\n").unwrap();
        let (_, _, coverage) = collect_with_coverage(&ScanContext::at(sensitive.path()));
        assert!(coverage.sensitive_file_incomplete());

        let persistence = tempfile::tempdir().unwrap();
        let deep_enablement = persistence
            .path()
            .join("etc/systemd/system/1/2/3/4/omitted.service");
        fs::create_dir_all(deep_enablement.parent().unwrap()).unwrap();
        fs::write(&deep_enablement, "[Service]\nExecStart=/bin/true\n").unwrap();
        let (_, _, coverage) = collect_with_coverage(&ScanContext::at(persistence.path()));
        assert!(coverage.persistence_entry_incomplete());
    }
}
