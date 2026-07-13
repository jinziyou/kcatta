//! Durable on-disk spool for telemetry that could not be delivered.
//!
//! The collectors are collect-only and `agentd` is the sole uploader, so if
//! Form is unreachable the umbrella is the only place that can keep an
//! envelope safe until it recovers. Before this, [`crate::ingest`] dropped a
//! batch once its in-memory retries were exhausted (a ~1.4s window): any host /
//! trace cycle landing during a Form restart was lost with no record.
//!
//! This spool closes that gap with a bounded, FIFO, file-per-item queue:
//!   * **durable** — each undelivered upload is written to its own file, so a
//!     crash or shutdown never loses what was already queued;
//!   * **FIFO** — files are named by a zero-padded timestamp so a lexical sort
//!     replays them oldest-first, preserving delivery order on recovery;
//!   * **bounded** — a byte budget caps disk use; the oldest items are evicted
//!     first (a ring), and a single item larger than the whole budget is
//!     dead-lettered rather than evicting everything to make room;
//!   * **self-healing** — items that fail *permanently* on replay (for example,
//!     contract validation) are moved to a `deadletter/` subdir for operator
//!     triage instead of looping forever. Authentication failures remain queued
//!     because certificate/token rotation can repair them.
//!
//! Re-delivery can double-send (a crash between POST and file removal, or two
//! threads draining at once); the downstream id-based idempotency guard collapses
//! those duplicates, so the two mechanisms are deliberately complementary.

#[cfg(any(unix, test))]
use std::fs::DirBuilder;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};

/// Default spool size budget (bytes) when `FORM_SPOOL_MAX_BYTES` is unset.
#[cfg(unix)]
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Dead letters get a separate bounded budget so permanent failures cannot
/// bypass the live-queue limit and eventually fill the disk.
const DEFAULT_DEADLETTER_MAX_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_DEADLETTER_MAX_ITEMS: usize = 1_024;
const DEFAULT_DEADLETTER_RETENTION_SECS: u64 = 30 * 24 * 60 * 60;

/// Disambiguates items enqueued within the same nanosecond by one thread.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// One spooled, undelivered upload: the Form route it targets and its body.
///
/// Only the route *path* is stored, not a full URL — replay reconstructs the URL
/// against the current `upload_url`, so the Form address can change between
/// runs without stranding a backlog.
#[derive(Serialize, Deserialize)]
struct SpooledItem {
    path: String,
    body: serde_json::Value,
}

/// Outcome of replaying one spooled item, returned by the drain callback.
pub enum DrainStep {
    /// Form accepted it (202) — remove from the queue.
    Delivered,
    /// Form is unreachable or authentication is blocked — stop draining and
    /// keep the backlog in order for a later network/credential recovery.
    Transient,
    /// Form rejected it for good (for example validation) — move to dead-letter.
    Permanent,
}

/// Durable FIFO spool of undelivered uploads, one file per item.
pub struct Spool {
    dir: PathBuf,
    deadletter_dir: PathBuf,
    lock_path: PathBuf,
    max_bytes: u64,
    deadletter_limits: DeadletterLimits,
}

#[derive(Clone, Copy)]
struct DeadletterLimits {
    max_bytes: u64,
    max_items: usize,
    retention: Duration,
}

impl Default for DeadletterLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_DEADLETTER_MAX_BYTES,
            max_items: DEFAULT_DEADLETTER_MAX_ITEMS,
            retention: Duration::from_secs(DEFAULT_DEADLETTER_RETENTION_SECS),
        }
    }
}

struct DeadletterEntry {
    payload: PathBuf,
    reason: Option<PathBuf>,
    size: u64,
    modified: SystemTime,
}

impl Spool {
    /// Build a spool from the environment, or `None` if spooling is unavailable.
    ///
    /// On Unix, directory resolution is first secure+writable wins:
    /// `FORM_SPOOL_DIR` if set,
    /// then `/var/lib/kcatta/agentd/spool`, then a temp-dir fallback. `None`
    /// means no candidate could be created — the caller then falls back to its
    /// prior drop-after-retries behaviour rather than failing the upload.
    /// The queue byte budget is read from `FORM_SPOOL_MAX_BYTES` (default 64
    /// MiB). Dead letters are independently bounded by
    /// `FORM_SPOOL_DEADLETTER_MAX_BYTES`, `FORM_SPOOL_DEADLETTER_MAX_ITEMS`, and
    /// `FORM_SPOOL_DEADLETTER_RETENTION_SECS`. Non-Unix platforms fail closed
    /// because std does not expose the owner/DACL guarantees this spool needs.
    pub fn from_env() -> Option<Self> {
        #[cfg(not(unix))]
        {
            // Windows service temp paths may be shared (notably LocalSystem),
            // and std cannot prove a protected owner-only DACL or reject every
            // junction/reparse-point ancestor. Fail closed until a dedicated
            // Windows ACL backend exists rather than persisting telemetry in an
            // attacker-readable/injectable directory.
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                eprintln!(
                    "agentd: durable spool is disabled on this platform because private owner/DACL validation is unavailable; using bounded in-memory upload retries only"
                );
            });
            None
        }
        #[cfg(unix)]
        {
            Self::from_env_unix()
        }
    }

    #[cfg(unix)]
    fn from_env_unix() -> Option<Self> {
        let max_bytes = positive_env("FORM_SPOOL_MAX_BYTES")
            .or_else(|| {
                let legacy = positive_env("ANALYZER_SPOOL_MAX_BYTES");
                if legacy.is_some() {
                    warn_deprecated_env_once("ANALYZER_SPOOL_MAX_BYTES", "FORM_SPOOL_MAX_BYTES");
                }
                legacy
            })
            .unwrap_or(DEFAULT_MAX_BYTES);
        let deadletter_limits = DeadletterLimits {
            max_bytes: positive_env("FORM_SPOOL_DEADLETTER_MAX_BYTES")
                .unwrap_or(DEFAULT_DEADLETTER_MAX_BYTES),
            max_items: positive_env("FORM_SPOOL_DEADLETTER_MAX_ITEMS")
                .and_then(|value| usize::try_from(value).ok())
                .unwrap_or(DEFAULT_DEADLETTER_MAX_ITEMS),
            retention: Duration::from_secs(
                positive_env("FORM_SPOOL_DEADLETTER_RETENTION_SECS")
                    .unwrap_or(DEFAULT_DEADLETTER_RETENTION_SECS),
            ),
        };

        let mut candidates: Vec<PathBuf> = Vec::new();
        let form_dir = std::env::var_os("FORM_SPOOL_DIR").filter(|dir| !dir.is_empty());
        if let Some(dir) = form_dir {
            candidates.push(PathBuf::from(dir));
        } else if let Some(dir) =
            std::env::var_os("ANALYZER_SPOOL_DIR").filter(|dir| !dir.is_empty())
        {
            warn_deprecated_env_once("ANALYZER_SPOOL_DIR", "FORM_SPOOL_DIR");
            candidates.push(PathBuf::from(dir));
        }
        candidates.push(PathBuf::from("/var/lib/kcatta/agentd/spool"));
        let temp_root = canonical_temp_dir();
        // Previously released builds used one shared temp name. Inspect it
        // explicitly so a safe owner-matching backlog is not silently stranded
        // when the new per-UID fallback is selected.
        let legacy_temp = temp_root.join("kcatta-agentd-spool");
        if !matches!(
            fs::symlink_metadata(&legacy_temp),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        ) {
            candidates.push(legacy_temp);
        }
        candidates.push(temp_fallback_dir());

        for dir in candidates {
            if let Err(error) = harden_legacy_candidate(&dir) {
                warn_unsafe_candidate_once(&dir, &error);
                continue;
            }
            if let Some(spool) = Self::at_with_limits(&dir, max_bytes, deadletter_limits) {
                return Some(spool);
            }
        }
        None
    }

    /// Construct a spool rooted at `dir` with a `max_bytes` budget, creating the
    /// queue and `deadletter/` directories. Both directories must be owned by
    /// the effective user, must not be symlinks, and must have mode 0700 on
    /// Unix. `None` if they cannot be created or fail validation.
    #[cfg(test)]
    pub fn at(dir: &Path, max_bytes: u64) -> Option<Self> {
        Self::at_with_limits(dir, max_bytes, DeadletterLimits::default())
    }

    #[cfg(any(unix, test))]
    fn at_with_limits(
        dir: &Path,
        max_bytes: u64,
        deadletter_limits: DeadletterLimits,
    ) -> Option<Self> {
        if max_bytes == 0 || deadletter_limits.max_bytes == 0 || deadletter_limits.max_items == 0 {
            return None;
        }
        let deadletter_dir = dir.join("deadletter");
        let lock_path = dir.join(".lock");
        ensure_secure_dir(dir).ok()?;
        ensure_secure_dir(&deadletter_dir).ok()?;
        ensure_private_lock_file(&lock_path).ok()?;
        // `create_dir_all` succeeds for an existing read-only directory. Probe
        // actual create/remove permission so `from_env` can continue to its
        // next candidate (notably the per-user temp fallback) instead of
        // selecting a spool that will reject every enqueue.
        if !probe_writable(dir) || !probe_writable(&deadletter_dir) {
            return None;
        }
        let spool = Self {
            dir: dir.to_path_buf(),
            deadletter_dir,
            lock_path,
            max_bytes,
            deadletter_limits,
        };
        // Enforce age/count/byte limits immediately, not only when the next
        // permanent failure arrives after a long idle period.
        spool
            .with_exclusive_lock(|| {
                cleanup_temporary_files(&spool.dir)?;
                cleanup_temporary_files(&spool.deadletter_dir)?;
                cleanup_orphan_reasons(&spool.deadletter_dir)?;
                spool.enforce_deadletter_limits_unlocked(0, 0)
            })
            .ok()?;
        Some(spool)
    }

    /// Append one undelivered upload, enforcing the byte budget by evicting the
    /// oldest items first. An item larger than the whole budget is dead-lettered
    /// rather than evicting the entire backlog to (fail to) fit it.
    pub fn enqueue(&self, path: &str, body: &serde_json::Value) -> io::Result<()> {
        self.with_exclusive_lock(|| self.enqueue_unlocked(path, body))
    }

    fn enqueue_unlocked(&self, path: &str, body: &serde_json::Value) -> io::Result<()> {
        validate_secure_dir(&self.dir)?;
        validate_secure_dir(&self.deadletter_dir)?;
        let item = SpooledItem {
            path: path.to_string(),
            body: body.clone(),
        };
        let bytes = serde_json::to_vec(&item)?;
        if bytes.len() as u64 > self.max_bytes {
            return self.dead_letter_raw_unlocked(&bytes, "exceeds spool size budget");
        }
        self.evict_until_fits(bytes.len() as u64)?;
        write_atomic(&self.dir.join(self.next_name()), &bytes)?;
        // The cross-process lock makes this a true postcondition rather than a
        // best-effort preflight based on a stale snapshot.
        self.evict_until_fits(0)
    }

    /// Replay queued items oldest-first through `post`.
    ///
    /// Each `Delivered` item is removed; a `Permanent` failure is moved to the
    /// dead-letter dir; the first `Transient` failure stops the drain (that item
    /// and everything after it stay queued, in order, for the next attempt).
    /// Returns the number of items delivered. Errors reading the queue degrade to
    /// "nothing drained" — a spool problem must never break the live upload path.
    pub fn drain<F>(&self, mut post: F) -> usize
    where
        F: FnMut(&str, &serde_json::Value) -> DrainStep,
    {
        let files = match self.queue_files() {
            Ok(files) => files,
            Err(_) => return 0,
        };
        let mut delivered = 0;
        for (path, _size) in files {
            let raw = match read_private_file(&path) {
                Ok(raw) => raw,
                // Vanished (a concurrent drain took it) or transiently unreadable.
                Err(_) => continue,
            };
            let item: SpooledItem = match serde_json::from_slice(&raw) {
                Ok(item) => item,
                Err(_) => {
                    let _ = self.move_to_deadletter(&path, &raw, "unparseable spool item");
                    continue;
                }
            };
            match post(&item.path, &item.body) {
                DrainStep::Delivered => {
                    if remove_if_present(&path).is_ok() {
                        delivered += 1;
                    }
                }
                DrainStep::Permanent => {
                    let _ = self.move_to_deadletter(&path, &raw, "permanent failure on replay");
                }
                // Form still down: stop here so the backlog stays ordered.
                DrainStep::Transient => break,
            }
        }
        delivered
    }

    /// Number of items currently queued (excludes dead-letter). Used for
    /// backlog-depth observability on the live upload path.
    pub fn len(&self) -> usize {
        self.queue_files().map(|f| f.len()).unwrap_or(0)
    }

    /// Whether the queue is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Queue files as `(path, size)`, sorted oldest-first by name. Non-`.json`
    /// entries, in-progress `.tmp` writes, and the `deadletter/` subdir are
    /// excluded.
    fn queue_files(&self) -> io::Result<Vec<(PathBuf, u64)>> {
        validate_secure_dir(&self.dir)?;
        let mut out: Vec<(PathBuf, u64)> = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with(".json") {
                continue;
            }
            let meta = fs::symlink_metadata(entry.path())?;
            validate_private_file_metadata(&meta)?;
            out.push((entry.path(), meta.len()));
        }
        out.sort_by(|a, b| a.0.file_name().cmp(&b.0.file_name()));
        Ok(out)
    }

    /// Evict oldest queued items until `incoming` more bytes fit within budget.
    fn evict_until_fits(&self, incoming: u64) -> io::Result<()> {
        let entries = self.queue_files()?;
        let mut total: u64 = entries.iter().map(|(_, size)| *size).sum();
        let mut evicted_items = 0usize;
        let mut evicted_bytes = 0u64;
        for (path, size) in entries {
            if total.saturating_add(incoming) <= self.max_bytes {
                break;
            }
            remove_if_present(&path)?;
            total = total.saturating_sub(size);
            evicted_items += 1;
            evicted_bytes = evicted_bytes.saturating_add(size);
        }
        if evicted_items > 0 {
            eprintln!(
                "agentd: spool budget evicted {evicted_items} oldest item(s) ({evicted_bytes} bytes)"
            );
        }
        if total.saturating_add(incoming) > self.max_bytes {
            return Err(io::Error::other(
                "spool budget could not free enough space for incoming item",
            ));
        }
        Ok(())
    }

    /// Copy raw bytes into the dead-letter dir (with a `.reason` sidecar) and
    /// remove the source from the queue.
    fn move_to_deadletter(&self, src: &Path, raw: &[u8], reason: &str) -> io::Result<()> {
        self.dead_letter_raw(raw, reason)?;
        remove_if_present(src)
    }

    /// Write raw bytes to the dead-letter dir for operator triage. Dead letters
    /// have independent byte/count/retention limits; when a single entry cannot
    /// fit it is discarded with a warning instead of growing disk use without
    /// bound. The `.reason` sidecar is informational and its failure is ignored.
    fn dead_letter_raw(&self, raw: &[u8], reason: &str) -> io::Result<()> {
        self.with_exclusive_lock(|| self.dead_letter_raw_unlocked(raw, reason))
    }

    fn dead_letter_raw_unlocked(&self, raw: &[u8], reason: &str) -> io::Result<()> {
        validate_secure_dir(&self.deadletter_dir)?;
        let incoming = (raw.len() as u64).saturating_add(reason.len() as u64);
        if !self.enforce_deadletter_limits_unlocked(incoming, 1)? {
            eprintln!(
                "agentd: discarded dead-letter item ({incoming} bytes): dead-letter budget is {} bytes / {} items",
                self.deadletter_limits.max_bytes, self.deadletter_limits.max_items
            );
            return Ok(());
        }

        let name = self.next_name();
        let target = self.deadletter_dir.join(&name);
        write_atomic(&target, raw)?;
        let _ = write_atomic(
            &self.deadletter_dir.join(format!("{name}.reason")),
            reason.as_bytes(),
        );
        // A concurrent writer may have consumed the last available capacity
        // after our preflight. A second oldest-first pass converges back to the
        // configured limits.
        self.enforce_deadletter_limits_unlocked(0, 0)?;
        Ok(())
    }

    /// Purge expired dead letters, then evict oldest entries until `incoming`
    /// bytes/items fit. Returns `false` when the incoming entry can never fit.
    fn enforce_deadletter_limits_unlocked(
        &self,
        incoming_bytes: u64,
        incoming_items: usize,
    ) -> io::Result<bool> {
        validate_secure_dir(&self.deadletter_dir)?;
        if incoming_bytes > self.deadletter_limits.max_bytes
            || incoming_items > self.deadletter_limits.max_items
        {
            return Ok(false);
        }

        let now = SystemTime::now();
        let mut entries = self.deadletter_entries()?;
        let mut evicted_items = 0usize;
        let mut evicted_bytes = 0u64;

        for entry in &entries {
            let expired = now
                .duration_since(entry.modified)
                .map(|age| age >= self.deadletter_limits.retention)
                .unwrap_or(false);
            if expired {
                remove_deadletter_entry(entry)?;
                evicted_items += 1;
                evicted_bytes = evicted_bytes.saturating_add(entry.size);
            }
        }
        if evicted_items > 0 {
            entries = self.deadletter_entries()?;
        }

        let mut total: u64 = entries.iter().map(|entry| entry.size).sum();
        let mut count = entries.len();
        for entry in entries {
            if total.saturating_add(incoming_bytes) <= self.deadletter_limits.max_bytes
                && count.saturating_add(incoming_items) <= self.deadletter_limits.max_items
            {
                break;
            }
            remove_deadletter_entry(&entry)?;
            total = total.saturating_sub(entry.size);
            count = count.saturating_sub(1);
            evicted_items += 1;
            evicted_bytes = evicted_bytes.saturating_add(entry.size);
        }

        if evicted_items > 0 {
            eprintln!(
                "agentd: dead-letter limits evicted {evicted_items} oldest item(s) ({evicted_bytes} bytes)"
            );
        }
        Ok(
            total.saturating_add(incoming_bytes) <= self.deadletter_limits.max_bytes
                && count.saturating_add(incoming_items) <= self.deadletter_limits.max_items,
        )
    }

    /// Dead-letter payloads with their optional reason sidecars, oldest first.
    fn deadletter_entries(&self) -> io::Result<Vec<DeadletterEntry>> {
        validate_secure_dir(&self.deadletter_dir)?;
        let mut payloads = Vec::new();
        for entry in fs::read_dir(&self.deadletter_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with(".json") {
                continue;
            }
            let payload = entry.path();
            let payload_meta = fs::symlink_metadata(&payload)?;
            validate_private_file_metadata(&payload_meta)?;
            let reason = self
                .deadletter_dir
                .join(format!("{}.reason", name.to_string_lossy()));
            let (reason, reason_size, reason_modified) = match fs::symlink_metadata(&reason) {
                Ok(meta) => {
                    validate_private_file_metadata(&meta)?;
                    let modified = meta.modified().unwrap_or(UNIX_EPOCH);
                    (Some(reason), meta.len(), modified)
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => (None, 0, UNIX_EPOCH),
                Err(error) => return Err(error),
            };
            let payload_modified = payload_meta.modified().unwrap_or(UNIX_EPOCH);
            payloads.push(DeadletterEntry {
                payload,
                reason,
                size: payload_meta.len().saturating_add(reason_size),
                modified: payload_modified.max(reason_modified),
            });
        }
        payloads.sort_by(|a, b| a.payload.file_name().cmp(&b.payload.file_name()));
        Ok(payloads)
    }

    /// Serialize budget scans and publications across every agentd process that
    /// shares this spool. The lock itself is a validated private regular file.
    fn with_exclusive_lock<T>(&self, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
        let lock = open_existing_private(&self.lock_path, true)?;
        lock.lock()?;
        let result = operation();
        // File locks are released on close on every supported platform, including
        // unwinding from `operation`; keep HTTP work outside this critical section.
        drop(lock);
        result
    }

    /// A unique, lexically-sortable file name: zero-padded epoch-nanos so a name
    /// sort is a chronological sort, plus pid + sequence to avoid collisions.
    fn next_name(&self) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        format!("{nanos:039}-{:010}-{seq:020}.json", std::process::id())
    }
}

#[cfg(unix)]
fn positive_env(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|&value| value > 0)
}

#[cfg(unix)]
fn warn_deprecated_env_once(legacy: &str, replacement: &str) {
    warn_spool_once(
        format!("deprecated:{legacy}"),
        format!("agentd: {legacy} is deprecated; use {replacement}"),
    );
}

#[cfg(unix)]
fn warn_unsafe_candidate_once(path: &Path, error: &io::Error) {
    warn_spool_once(
        format!("unsafe:{}", path.display()),
        format!(
            "agentd: refusing unsafe legacy spool candidate {}: {error}",
            path.display()
        ),
    );
}

#[cfg(unix)]
fn warn_spool_once(key: String, message: String) {
    use std::collections::HashSet;
    use std::sync::{Mutex, OnceLock};

    static WARNED: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    let warned = WARNED.get_or_init(|| Mutex::new(HashSet::new()));
    let mut guard = warned
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if guard.insert(key) {
        eprintln!("{message}");
    }
}

#[cfg(unix)]
fn temp_fallback_dir() -> PathBuf {
    let temp = canonical_temp_dir();
    let uid = nix::unistd::Uid::effective().as_raw();
    temp.join(format!("kcatta-agentd-spool-{uid}"))
}

#[cfg(unix)]
fn canonical_temp_dir() -> PathBuf {
    let temp = std::env::temp_dir();
    fs::canonicalize(&temp).unwrap_or(temp)
}

/// Create a private directory, or validate an existing one without repairing an
/// unsafe pre-created path. Refusing rather than chmod'ing an existing broad
/// directory prevents an attacker from winning path creation and planting data
/// before agentd starts.
#[cfg(any(unix, test))]
fn ensure_secure_dir(path: &Path) -> io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => return validate_secure_dir(path),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    #[cfg(unix)]
    create_secure_dir_all(path)?;
    #[cfg(not(unix))]
    DirBuilder::new().recursive(true).create(path)?;
    validate_secure_dir(path)
}

/// One-time migration for the previously published 0755/0644 layout. Nothing
/// is changed until the complete tree is proven to be real, owned by the
/// effective UID, nlink=1 for files, and not group/world writable. Unsafe trees
/// are rejected by the caller with a loud warning.
#[cfg(unix)]
fn harden_legacy_candidate(path: &Path) -> io::Result<bool> {
    let root = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let parent = std::path::absolute(path)?
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "legacy spool has no parent"))?
        .to_path_buf();
    validate_trusted_parent_chain(&parent)?;
    validate_legacy_dir_metadata(&root, "legacy spool root")?;

    let deadletter = path.join("deadletter");
    let deadletter_metadata = match fs::symlink_metadata(&deadletter) {
        Ok(metadata) => {
            validate_legacy_dir_metadata(&metadata, "legacy dead-letter directory")?;
            Some(metadata)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => None,
        Err(error) => return Err(error),
    };

    // A fully private current layout may contain a legitimate nlink=2 crash
    // publication; leave it to locked startup cleanup instead of treating it as
    // a legacy tree.
    if root.mode() & 0o7777 == 0o700
        && deadletter_metadata
            .as_ref()
            .is_none_or(|metadata| metadata.mode() & 0o7777 == 0o700)
    {
        return Ok(false);
    }

    let mut files = legacy_files(path, true)?;
    if deadletter_metadata.is_some() {
        files.extend(legacy_files(&deadletter, false)?);
    }
    // Validation above is deliberately a complete first pass: do not partially
    // chmod a tree that later turns out to contain an injected entry.
    for file in &files {
        validate_legacy_file_metadata(&fs::symlink_metadata(file)?)?;
    }

    for file in &files {
        fs::set_permissions(file, fs::Permissions::from_mode(0o600))?;
    }
    if deadletter_metadata.is_some() {
        fs::set_permissions(&deadletter, fs::Permissions::from_mode(0o700))?;
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;

    validate_secure_dir(path)?;
    if deadletter_metadata.is_some() {
        validate_secure_dir(&deadletter)?;
    }
    for file in &files {
        validate_private_file_metadata(&fs::symlink_metadata(file)?)?;
    }
    eprintln!(
        "agentd: securely migrated legacy spool permissions at {} (directories 0700, files 0600)",
        path.display()
    );
    Ok(true)
}

#[cfg(unix)]
fn validate_legacy_dir_metadata(metadata: &Metadata, label: &str) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(permission_error(format!("{label} is not a real directory")));
    }
    let current_uid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != current_uid {
        return Err(permission_error(format!(
            "{label} owner uid {} does not match effective uid {current_uid}",
            metadata.uid()
        )));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(permission_error(format!(
            "{label} is writable by group/world (mode {:04o})",
            metadata.mode() & 0o7777
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_legacy_file_metadata(metadata: &Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(permission_error("legacy spool entry is not a regular file"));
    }
    let current_uid = nix::unistd::Uid::effective().as_raw();
    if metadata.uid() != current_uid || metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
        return Err(permission_error(format!(
            "legacy spool file is unsafe (uid={}, nlink={}, mode={:04o})",
            metadata.uid(),
            metadata.nlink(),
            metadata.mode() & 0o7777
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn legacy_files(dir: &Path, root: bool) -> io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if root && name == "deadletter" {
            continue;
        }
        let known = name == ".lock"
            || name.ends_with(".json")
            || name.ends_with(".json.reason")
            || name.ends_with(".json.tmp")
            || (name.starts_with('.') && name.ends_with(".tmp"));
        if !known {
            return Err(permission_error(format!(
                "legacy spool contains unexpected entry {name:?}"
            )));
        }
        let path = entry.path();
        validate_legacy_file_metadata(&fs::symlink_metadata(&path)?)?;
        files.push(path);
    }
    Ok(files)
}

/// Validate the nearest existing ancestor before making any change, then create
/// each missing Unix path component separately. A hostile process cannot use an
/// intermediate symlink to make a privileged agent chmod/create in another tree.
#[cfg(unix)]
fn create_secure_dir_all(path: &Path) -> io::Result<()> {
    let absolute = std::path::absolute(path)?;
    let mut missing = Vec::new();
    let mut cursor = absolute.as_path();
    loop {
        match fs::symlink_metadata(cursor) {
            Ok(_) => {
                validate_trusted_parent_chain(cursor)?;
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push(cursor.to_path_buf());
                cursor = cursor.parent().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "spool path has no existing root",
                    )
                })?;
            }
            Err(error) => return Err(error),
        }
    }

    for component in missing.into_iter().rev() {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&component) {
            Ok(()) => {
                // `mode` is subject to umask; make the just-created private
                // component exactly 0700 before descending through it.
                fs::set_permissions(&component, fs::Permissions::from_mode(0o700))?;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        validate_secure_dir(&component)?;
    }
    Ok(())
}

fn validate_secure_dir(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(permission_error(format!(
            "spool path is not a real directory: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        validate_unix_owner_mode(&metadata, 0o700, "spool directory")?;
        validate_trusted_ancestors(path)?;
    }
    Ok(())
}

/// Ensure another user cannot swap a validated spool directory by controlling
/// one of its parents. Root/current-user parents must not be group/world
/// writable, except for a sticky shared directory such as `/tmp`.
#[cfg(unix)]
fn validate_trusted_ancestors(path: &Path) -> io::Result<()> {
    let absolute = std::path::absolute(path)?;
    let Some(parent) = absolute.parent() else {
        return Ok(());
    };
    validate_trusted_parent_chain(parent)
}

#[cfg(unix)]
fn validate_trusted_parent_chain(path: &Path) -> io::Result<()> {
    let current_uid = nix::unistd::Uid::effective().as_raw();
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(permission_error(format!(
                "spool ancestor is not a real directory: {}",
                ancestor.display()
            )));
        }
        if metadata.uid() != current_uid && metadata.uid() != 0 {
            return Err(permission_error(format!(
                "spool ancestor {} is owned by untrusted uid {}",
                ancestor.display(),
                metadata.uid()
            )));
        }
        let mode = metadata.mode();
        if mode & 0o022 != 0 && mode & 0o1000 == 0 {
            return Err(permission_error(format!(
                "spool ancestor {} is writable by group/world without the sticky bit",
                ancestor.display()
            )));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn validate_unix_owner_mode(
    metadata: &Metadata,
    expected_mode: u32,
    label: &str,
) -> io::Result<()> {
    let current_uid = nix::unistd::Uid::effective().as_raw();
    validate_unix_owner_mode_for(metadata, current_uid, expected_mode, label)
}

#[cfg(unix)]
fn validate_unix_owner_mode_for(
    metadata: &Metadata,
    expected_uid: u32,
    expected_mode: u32,
    label: &str,
) -> io::Result<()> {
    if metadata.uid() != expected_uid {
        return Err(permission_error(format!(
            "{label} owner uid {} does not match expected uid {expected_uid}",
            metadata.uid()
        )));
    }
    let actual_mode = metadata.mode() & 0o777;
    if actual_mode != expected_mode {
        return Err(permission_error(format!(
            "{label} mode {actual_mode:04o} is not {expected_mode:04o}"
        )));
    }
    Ok(())
}

fn validate_private_file_metadata(metadata: &Metadata) -> io::Result<()> {
    validate_private_file_metadata_allow_links(metadata)?;
    #[cfg(unix)]
    if metadata.nlink() != 1 {
        return Err(permission_error(format!(
            "spool file has unexpected hard-link count {}",
            metadata.nlink()
        )));
    }
    Ok(())
}

/// Validate a private regular file while permitting the temporary `nlink=2`
/// publication state (`tmp` + final name). Only crash-recovery cleanup uses
/// this relaxed form; all readable queue/dead-letter files require one link.
fn validate_private_file_metadata_allow_links(metadata: &Metadata) -> io::Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(permission_error("spool entry is not a regular file"));
    }
    #[cfg(unix)]
    validate_unix_owner_mode(metadata, 0o600, "spool file")?;
    Ok(())
}

fn permission_error(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

#[cfg(any(unix, test))]
fn ensure_private_lock_file(path: &Path) -> io::Result<()> {
    match open_new_private(path) {
        Ok(file) => {
            drop(file);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            drop(open_existing_private(path, true)?);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

#[cfg(any(unix, test))]
fn probe_writable(dir: &Path) -> bool {
    if validate_secure_dir(dir).is_err() {
        return false;
    }
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let probe = dir.join(format!(".write-probe-{}-{seq}", std::process::id()));
    let created = open_new_private(&probe);
    match created {
        Ok(file) => {
            drop(file);
            fs::remove_file(probe).is_ok()
        }
        Err(_) => false,
    }
}

fn open_new_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        options.mode(0o600);
        options.custom_flags(nix::libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let validation = (|| {
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        validate_private_file_metadata(&file.metadata()?)
    })();
    if let Err(error) = validation {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

fn read_private_file(path: &Path) -> io::Result<Vec<u8>> {
    let mut file = open_existing_private(path, false)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn open_existing_private(path: &Path, writable: bool) -> io::Result<File> {
    // Reject the link itself before opening on platforms without O_NOFOLLOW.
    validate_private_file_metadata(&fs::symlink_metadata(path)?)?;
    let mut options = OpenOptions::new();
    options.read(true).write(writable);
    #[cfg(unix)]
    options.custom_flags(nix::libc::O_NOFOLLOW);
    let file = options.open(path)?;
    validate_private_file_metadata(&file.metadata()?)?;
    Ok(file)
}

/// Atomically publish `bytes` at `target`: create a private sibling temp file,
/// then hard-link it into the final name. `hard_link` is an atomic no-clobber
/// publish operation: a pre-created file or symlink makes the write fail instead
/// of being followed or replaced.
fn write_atomic(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "spool target has no parent"))?;
    validate_secure_dir(parent)?;

    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let file_name = target
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "spool target has no name"))?
        .to_string_lossy();
    let tmp = parent.join(format!(".{file_name}.{}-{seq}.tmp", std::process::id()));
    let mut file = open_new_private(&tmp)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    drop(file);
    if let Err(error) = fs::hard_link(&tmp, target) {
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    if let Err(error) = fs::remove_file(&tmp) {
        let _ = fs::remove_file(target);
        let _ = fs::remove_file(&tmp);
        return Err(error);
    }
    let validation =
        fs::symlink_metadata(target).and_then(|metadata| validate_private_file_metadata(&metadata));
    if let Err(error) = validation {
        let _ = fs::remove_file(target);
        return Err(error);
    }
    #[cfg(unix)]
    if let Err(error) = File::open(parent).and_then(|directory| directory.sync_all()) {
        let _ = fs::remove_file(target);
        return Err(error);
    }
    Ok(())
}

fn remove_deadletter_entry(entry: &DeadletterEntry) -> io::Result<()> {
    remove_if_present(&entry.payload)?;
    if let Some(reason) = &entry.reason {
        remove_if_present(reason)?;
    }
    Ok(())
}

/// Remove private unpublished temp files left by a process that died between
/// write/fsync and atomic publication. Call only while holding the spool lock.
#[cfg(any(unix, test))]
fn cleanup_temporary_files(dir: &Path) -> io::Result<()> {
    validate_secure_dir(dir)?;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with('.') || !name.ends_with(".tmp") {
            continue;
        }
        let path = entry.path();
        validate_private_file_metadata_allow_links(&fs::symlink_metadata(&path)?)?;
        let published_target = name
            .strip_prefix('.')
            .and_then(|value| value.strip_suffix(".tmp"))
            .and_then(|value| value.rsplit_once('.').map(|(target, _nonce)| target))
            .filter(|target| !target.is_empty())
            .map(|target| dir.join(target));
        let target_exists = if let Some(target) = published_target.as_ref() {
            match fs::symlink_metadata(target) {
                Ok(metadata) => {
                    // Before unlinking the temp name, a successfully published
                    // target legitimately has nlink=2.
                    validate_private_file_metadata_allow_links(&metadata)?;
                    true
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(error) => return Err(error),
            }
        } else {
            false
        };
        remove_if_present(&path)?;
        if target_exists {
            let target = published_target.as_ref().expect("target checked above");
            // Removing the abandoned tmp link must leave exactly one safe name.
            validate_private_file_metadata(&fs::symlink_metadata(target)?)?;
        }
    }
    Ok(())
}

/// Remove reason sidecars whose payload was already evicted before a crash.
/// Call only while holding the spool lock.
#[cfg(any(unix, test))]
fn cleanup_orphan_reasons(deadletter_dir: &Path) -> io::Result<()> {
    validate_secure_dir(deadletter_dir)?;
    for entry in fs::read_dir(deadletter_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(payload_name) = name.strip_suffix(".reason") else {
            continue;
        };
        if !payload_name.ends_with(".json") {
            continue;
        }
        let reason = entry.path();
        validate_private_file_metadata(&fs::symlink_metadata(&reason)?)?;
        match fs::symlink_metadata(deadletter_dir.join(payload_name)) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                remove_if_present(&reason)?;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Remove a file, treating "already gone" (e.g. a concurrent drain) as success.
fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(unix))]
    #[test]
    fn durable_spool_fails_closed_without_owner_acl_validation() {
        assert!(Spool::from_env().is_none());
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "kcatta-spool-{label}-{}-{nanos}-{seq}",
            std::process::id()
        ))
    }

    fn temp_spool(max_bytes: u64) -> (PathBuf, Spool) {
        let dir = unique_temp_dir("test");
        let spool = Spool::at(&dir, max_bytes).expect("create spool");
        (dir, spool)
    }

    fn cleanup(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    fn deadletter_count(dir: &Path) -> usize {
        fs::read_dir(dir.join("deadletter"))
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| e.file_name().to_string_lossy().ends_with(".json"))
                    .count()
            })
            .unwrap_or(0)
    }

    fn deadletter_total_bytes(spool: &Spool) -> u64 {
        spool
            .deadletter_entries()
            .unwrap()
            .iter()
            .map(|entry| entry.size)
            .sum()
    }

    #[test]
    fn construction_probes_writability_without_leaving_markers() {
        let (dir, _spool) = temp_spool(1024);
        for candidate in [dir.clone(), dir.join("deadletter")] {
            let names: Vec<_> = fs::read_dir(candidate)
                .unwrap()
                .flatten()
                .map(|entry| entry.file_name())
                .collect();
            assert!(names
                .iter()
                .all(|name| !name.to_string_lossy().starts_with(".write-probe-")));
        }
        cleanup(&dir);
    }

    #[test]
    fn construction_cleans_crash_temps_and_orphan_reason_sidecars() {
        let (dir, spool) = temp_spool(1024);
        drop(spool);
        let temp = dir.join(".abandoned.tmp");
        drop(open_new_private(&temp).unwrap());
        let orphan = dir.join("deadletter/orphan.json.reason");
        drop(open_new_private(&orphan).unwrap());

        let _reopened = Spool::at(&dir, 1024).expect("secure crash debris is recoverable");
        assert!(!temp.exists());
        assert!(!orphan.exists());
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn construction_recovers_hardlinked_publish_crash_window() {
        let (dir, spool) = temp_spool(1024);
        drop(spool);
        let target = dir.join("published.json");
        let temp = dir.join(format!(".published.json.{}-999.tmp", std::process::id()));
        let mut file = open_new_private(&temp).unwrap();
        file.write_all(br#"{"path":"/a","body":{"n":1}}"#).unwrap();
        drop(file);
        fs::hard_link(&temp, &target).unwrap();
        assert_eq!(fs::symlink_metadata(&temp).unwrap().nlink(), 2);

        let reopened = Spool::at(&dir, 1024).expect("nlink=2 crash state must recover");
        assert!(!temp.exists());
        assert_eq!(fs::symlink_metadata(&target).unwrap().nlink(), 1);
        assert_eq!(reopened.len(), 1);
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn directories_are_private_and_temp_fallback_is_per_uid() {
        let (dir, _spool) = temp_spool(1024);
        for candidate in [&dir, &dir.join("deadletter")] {
            let metadata = fs::symlink_metadata(candidate).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o700);
            assert_eq!(metadata.uid(), nix::unistd::Uid::effective().as_raw());
        }
        assert_eq!(
            fs::symlink_metadata(dir.join(".lock")).unwrap().mode() & 0o777,
            0o600
        );
        assert!(temp_fallback_dir()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .ends_with(&format!("-{}", nix::unistd::Uid::effective().as_raw())));
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_broad_root_or_deadletter_permissions() {
        let broad_root = unique_temp_dir("broad-root");
        fs::create_dir(&broad_root).unwrap();
        fs::set_permissions(&broad_root, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Spool::at(&broad_root, 1024).is_none());
        cleanup(&broad_root);

        let broad_deadletter = unique_temp_dir("broad-deadletter");
        fs::create_dir(&broad_deadletter).unwrap();
        fs::set_permissions(&broad_deadletter, fs::Permissions::from_mode(0o700)).unwrap();
        fs::create_dir(broad_deadletter.join("deadletter")).unwrap();
        fs::set_permissions(
            broad_deadletter.join("deadletter"),
            fs::Permissions::from_mode(0o770),
        )
        .unwrap();
        assert!(Spool::at(&broad_deadletter, 1024).is_none());
        cleanup(&broad_deadletter);

        let broad_parent = unique_temp_dir("broad-parent");
        fs::create_dir(&broad_parent).unwrap();
        fs::set_permissions(&broad_parent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Spool::at(&broad_parent.join("spool"), 1024).is_none());
        cleanup(&broad_parent);
    }

    #[cfg(unix)]
    #[test]
    fn safely_migrates_owner_matched_legacy_permissions() {
        let dir = unique_temp_dir("legacy-safe");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let deadletter = dir.join("deadletter");
        fs::create_dir(&deadletter).unwrap();
        fs::set_permissions(&deadletter, fs::Permissions::from_mode(0o755)).unwrap();
        let queued = dir.join("legacy.json");
        fs::write(&queued, br#"{"path":"/a","body":{"legacy":true}}"#).unwrap();
        fs::set_permissions(&queued, fs::Permissions::from_mode(0o644)).unwrap();
        let dead = deadletter.join("dead.json");
        let reason = deadletter.join("dead.json.reason");
        fs::write(&dead, b"dead payload").unwrap();
        fs::write(&reason, b"legacy reason").unwrap();
        fs::set_permissions(&dead, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&reason, fs::Permissions::from_mode(0o644)).unwrap();

        assert!(harden_legacy_candidate(&dir).unwrap());
        assert_eq!(fs::symlink_metadata(&dir).unwrap().mode() & 0o7777, 0o700);
        assert_eq!(
            fs::symlink_metadata(&deadletter).unwrap().mode() & 0o7777,
            0o700
        );
        for file in [&queued, &dead, &reason] {
            assert_eq!(fs::symlink_metadata(file).unwrap().mode() & 0o7777, 0o600);
        }
        let spool = Spool::at(&dir, 1 << 20).expect("migrated backlog must reopen");
        assert_eq!(spool.len(), 1);
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_legacy_writable_or_symlink_injected_tree_without_chmod() {
        use std::os::unix::fs::symlink;

        let writable = unique_temp_dir("legacy-writable");
        fs::create_dir(&writable).unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(harden_legacy_candidate(&writable).is_err());
        assert_eq!(
            fs::symlink_metadata(&writable).unwrap().mode() & 0o7777,
            0o770
        );
        cleanup(&writable);

        let injected = unique_temp_dir("legacy-symlink");
        fs::create_dir(&injected).unwrap();
        fs::set_permissions(&injected, fs::Permissions::from_mode(0o755)).unwrap();
        let victim = unique_temp_dir("legacy-victim");
        fs::write(&victim, b"victim").unwrap();
        symlink(&victim, injected.join("injected.json")).unwrap();
        assert!(harden_legacy_candidate(&injected).is_err());
        assert_eq!(
            fs::symlink_metadata(&injected).unwrap().mode() & 0o7777,
            0o755
        );
        cleanup(&injected);
        fs::remove_file(victim).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_root_or_deadletter_directory() {
        use std::os::unix::fs::symlink;

        let real_root = unique_temp_dir("real-root");
        ensure_secure_dir(&real_root).unwrap();
        let linked_root = unique_temp_dir("linked-root");
        symlink(&real_root, &linked_root).unwrap();
        assert!(Spool::at(&linked_root, 1024).is_none());
        fs::remove_file(&linked_root).unwrap();
        cleanup(&real_root);

        let root = unique_temp_dir("linked-deadletter");
        ensure_secure_dir(&root).unwrap();
        let deadletter_target = unique_temp_dir("deadletter-target");
        ensure_secure_dir(&deadletter_target).unwrap();
        symlink(&deadletter_target, root.join("deadletter")).unwrap();
        assert!(Spool::at(&root, 1024).is_none());
        cleanup(&root);
        cleanup(&deadletter_target);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_ancestor_before_creating_any_descendant() {
        use std::os::unix::fs::symlink;

        let base = unique_temp_dir("ancestor-link");
        let target = unique_temp_dir("ancestor-target");
        ensure_secure_dir(&base).unwrap();
        ensure_secure_dir(&target).unwrap();
        symlink(&target, base.join("redirect")).unwrap();

        assert!(ensure_secure_dir(&base.join("redirect/spool")).is_err());
        assert!(!target.join("spool").exists());
        cleanup(&base);
        cleanup(&target);
    }

    #[cfg(unix)]
    #[test]
    fn ownership_validator_rejects_a_different_uid() {
        let (dir, _spool) = temp_spool(1024);
        let metadata = fs::symlink_metadata(&dir).unwrap();
        let actual = metadata.uid();
        let different = if actual == u32::MAX {
            actual - 1
        } else {
            actual + 1
        };
        let error = validate_unix_owner_mode_for(&metadata, different, 0o700, "test dir")
            .expect_err("different owner must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        cleanup(&dir);
    }

    #[test]
    fn enqueue_then_drain_replays_in_fifo_order() {
        let (dir, spool) = temp_spool(1 << 20);
        spool
            .enqueue("/ingest/a", &serde_json::json!({"n": 1}))
            .unwrap();
        spool
            .enqueue("/ingest/b", &serde_json::json!({"n": 2}))
            .unwrap();
        assert_eq!(spool.len(), 2);

        let mut seen = Vec::new();
        let delivered = spool.drain(|route, body| {
            seen.push((route.to_string(), body["n"].as_i64().unwrap()));
            DrainStep::Delivered
        });

        assert_eq!(delivered, 2);
        assert_eq!(
            seen,
            vec![("/ingest/a".to_string(), 1), ("/ingest/b".to_string(), 2)]
        );
        assert!(spool.is_empty());
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn queue_and_deadletter_files_are_mode_0600() {
        let (dir, spool) = temp_spool(1 << 20);
        spool.enqueue("/a", &serde_json::json!({"n": 1})).unwrap();
        for (path, _) in spool.queue_files().unwrap() {
            assert_eq!(fs::symlink_metadata(path).unwrap().mode() & 0o777, 0o600);
        }

        spool.drain(|_, _| DrainStep::Permanent);
        for entry in fs::read_dir(dir.join("deadletter")).unwrap() {
            let metadata = fs::symlink_metadata(entry.unwrap().path()).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
        }
        cleanup(&dir);
    }

    #[test]
    fn atomic_write_refuses_a_precreated_target_without_clobbering_it() {
        let dir = unique_temp_dir("precreated");
        ensure_secure_dir(&dir).unwrap();
        let target = dir.join("item.json");
        let mut existing = open_new_private(&target).unwrap();
        existing.write_all(b"trusted-existing").unwrap();
        drop(existing);

        let error = write_atomic(&target, b"attacker-controlled replacement")
            .expect_err("create-new publish must not replace an existing path");
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(read_private_file(&target).unwrap(), b"trusted-existing");
        cleanup(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_and_queue_reject_symlinks() {
        use std::os::unix::fs::symlink;

        let (dir, spool) = temp_spool(1 << 20);
        let victim = unique_temp_dir("victim");
        let mut victim_file = open_new_private(&victim).unwrap();
        victim_file.write_all(b"do-not-touch").unwrap();
        drop(victim_file);

        let linked_target = dir.join("precreated.json");
        symlink(&victim, &linked_target).unwrap();
        assert!(write_atomic(&linked_target, b"replacement").is_err());
        assert_eq!(read_private_file(&victim).unwrap(), b"do-not-touch");

        let error = spool
            .enqueue("/new", &serde_json::json!({"n": 2}))
            .expect_err("a symlink queue entry must poison the unsafe queue");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        cleanup(&dir);
        fs::remove_file(victim).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn queue_rejects_group_or_world_readable_files() {
        let (dir, spool) = temp_spool(1 << 20);
        let planted = dir.join("planted.json");
        fs::write(&planted, b"{}").unwrap();
        fs::set_permissions(&planted, fs::Permissions::from_mode(0o644)).unwrap();

        let error = spool
            .enqueue("/new", &serde_json::json!({"n": 2}))
            .expect_err("broad queue file permissions must be rejected");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        cleanup(&dir);
    }

    #[test]
    fn drain_stops_on_transient_and_keeps_backlog() {
        let (dir, spool) = temp_spool(1 << 20);
        spool.enqueue("/a", &serde_json::json!({"n": 1})).unwrap();
        spool.enqueue("/b", &serde_json::json!({"n": 2})).unwrap();

        let delivered = spool.drain(|_, _| DrainStep::Transient);

        assert_eq!(delivered, 0);
        assert_eq!(
            spool.len(),
            2,
            "transient failure must not drop the backlog"
        );
        cleanup(&dir);
    }

    #[test]
    fn drain_dead_letters_permanent_failures() {
        let (dir, spool) = temp_spool(1 << 20);
        spool.enqueue("/a", &serde_json::json!({"n": 1})).unwrap();

        let delivered = spool.drain(|_, _| DrainStep::Permanent);

        assert_eq!(delivered, 0);
        assert!(spool.is_empty(), "permanent failure leaves the queue");
        assert_eq!(deadletter_count(&dir), 1, "it lands in dead-letter");
        cleanup(&dir);
    }

    #[test]
    fn deadletter_item_limit_evicts_oldest() {
        let dir = unique_temp_dir("deadletter-count");
        let spool = Spool::at_with_limits(
            &dir,
            1 << 20,
            DeadletterLimits {
                max_bytes: 1 << 20,
                max_items: 2,
                retention: Duration::from_secs(3600),
            },
        )
        .unwrap();

        spool.dead_letter_raw(b"oldest", "reason").unwrap();
        spool.dead_letter_raw(b"middle", "reason").unwrap();
        spool.dead_letter_raw(b"newest", "reason").unwrap();

        let entries = spool.deadletter_entries().unwrap();
        assert_eq!(entries.len(), 2);
        let payloads: Vec<Vec<u8>> = entries
            .iter()
            .map(|entry| read_private_file(&entry.payload).unwrap())
            .collect();
        assert_eq!(payloads, vec![b"middle".to_vec(), b"newest".to_vec()]);
        cleanup(&dir);
    }

    #[test]
    fn deadletter_byte_limit_counts_payloads_and_reasons() {
        let dir = unique_temp_dir("deadletter-bytes");
        let spool = Spool::at_with_limits(
            &dir,
            1 << 20,
            DeadletterLimits {
                max_bytes: 90,
                max_items: 100,
                retention: Duration::from_secs(3600),
            },
        )
        .unwrap();

        for byte in *b"abc" {
            spool.dead_letter_raw(&[byte; 30], "1234567890").unwrap();
        }

        assert!(deadletter_total_bytes(&spool) <= 90);
        assert_eq!(spool.deadletter_entries().unwrap().len(), 2);
        cleanup(&dir);
    }

    #[test]
    fn deadletter_retention_and_oversize_entry_are_bounded() {
        let retained_dir = unique_temp_dir("deadletter-retention");
        let retained = Spool::at_with_limits(
            &retained_dir,
            1 << 20,
            DeadletterLimits {
                max_bytes: 1024,
                max_items: 10,
                retention: Duration::ZERO,
            },
        )
        .unwrap();
        retained.dead_letter_raw(b"expires-now", "reason").unwrap();
        assert_eq!(deadletter_count(&retained_dir), 0);
        cleanup(&retained_dir);

        let oversize_dir = unique_temp_dir("deadletter-oversize");
        let oversize = Spool::at_with_limits(
            &oversize_dir,
            1 << 20,
            DeadletterLimits {
                max_bytes: 8,
                max_items: 10,
                retention: Duration::from_secs(3600),
            },
        )
        .unwrap();
        oversize
            .dead_letter_raw(b"larger-than-eight", "reason")
            .unwrap();
        assert_eq!(deadletter_count(&oversize_dir), 0);
        cleanup(&oversize_dir);
    }

    #[test]
    fn ring_evicts_oldest_when_over_budget() {
        // A budget that holds ~1 padded item, so each enqueue evicts the prior.
        let (dir, spool) = temp_spool(160);
        for seq in 0..4 {
            spool
                .enqueue(
                    "/ingest/asset-report",
                    &serde_json::json!({"seq": seq, "pad": "xxxxxxxxxxxxxxxx"}),
                )
                .unwrap();
        }
        assert!(spool.len() < 4, "expected eviction, got {}", spool.len());
        assert!(!spool.is_empty(), "the newest item must survive");
        cleanup(&dir);
    }

    #[test]
    fn concurrent_enqueues_cannot_exceed_queue_byte_budget() {
        use std::sync::{Arc, Barrier};

        let (dir, spool) = temp_spool(240);
        let spool = Arc::new(spool);
        let barrier = Arc::new(Barrier::new(12));
        let mut threads = Vec::new();
        for sequence in 0..12 {
            let spool = Arc::clone(&spool);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                spool
                    .enqueue(
                        "/ingest/asset-report",
                        &serde_json::json!({"sequence": sequence, "pad": "xxxxxxxxxxxxxxxx"}),
                    )
                    .unwrap();
            }));
        }
        for thread in threads {
            thread.join().unwrap();
        }

        let total: u64 = spool
            .queue_files()
            .unwrap()
            .iter()
            .map(|(_, size)| *size)
            .sum();
        assert!(total <= 240, "queue used {total} bytes beyond its budget");
        cleanup(&dir);
    }

    #[test]
    fn oversize_item_is_dead_lettered_not_queued() {
        let (dir, spool) = temp_spool(50);
        spool
            .enqueue(
                "/ingest/asset-report",
                &serde_json::json!({"big": "yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"}),
            )
            .unwrap();

        assert!(spool.is_empty(), "an oversize item is not queued");
        assert_eq!(deadletter_count(&dir), 1);
        cleanup(&dir);
    }

    #[test]
    fn len_tracks_enqueue_and_drain() {
        let (dir, spool) = temp_spool(1 << 20);
        assert!(spool.is_empty());
        spool.enqueue("/a", &serde_json::json!({"n": 1})).unwrap();
        spool.enqueue("/b", &serde_json::json!({"n": 2})).unwrap();
        assert_eq!(spool.len(), 2, "depth reflects enqueues");

        let delivered = spool.drain(|_, _| DrainStep::Delivered);
        assert_eq!(delivered, 2, "drain returns the delivered count");
        assert!(spool.is_empty(), "drained queue is empty");
        cleanup(&dir);
    }
}
