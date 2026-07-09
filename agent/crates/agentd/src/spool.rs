//! Durable on-disk spool for telemetry that could not be delivered.
//!
//! The collectors are collect-only and `agentd` is the sole uploader, so if
//! analyzer is unreachable the umbrella is the only place that can keep an
//! envelope safe until it recovers. Before this, [`crate::ingest`] dropped a
//! batch once its in-memory retries were exhausted (a ~1.4s window): any host /
//! trace cycle landing during an analyzer restart was lost with no record.
//!
//! This spool closes that gap with a bounded, FIFO, file-per-item queue:
//!   * **durable** — each undelivered upload is written to its own file, so a
//!     crash or shutdown never loses what was already queued;
//!   * **FIFO** — files are named by a zero-padded timestamp so a lexical sort
//!     replays them oldest-first, preserving delivery order on recovery;
//!   * **bounded** — a byte budget caps disk use; the oldest items are evicted
//!     first (a ring), and a single item larger than the whole budget is
//!     dead-lettered rather than evicting everything to make room;
//!   * **self-healing** — items that fail *permanently* on replay (validation /
//!     auth) are moved to a `deadletter/` subdir for operator triage instead of
//!     looping forever.
//!
//! Re-delivery can double-send (a crash between POST and file removal, or two
//! threads draining at once); the analyzer's id-based idempotency guard collapses
//! those duplicates, so the two mechanisms are deliberately complementary.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Default spool size budget (bytes) when `ANALYZER_SPOOL_MAX_BYTES` is unset.
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Disambiguates items enqueued within the same nanosecond by one thread.
static SEQ: AtomicU64 = AtomicU64::new(0);

/// One spooled, undelivered upload: the analyzer route it targets and its body.
///
/// Only the route *path* is stored, not a full URL — replay reconstructs the URL
/// against the current `upload_url`, so the analyzer address can change between
/// runs without stranding a backlog.
#[derive(Serialize, Deserialize)]
struct SpooledItem {
    path: String,
    body: serde_json::Value,
}

/// Outcome of replaying one spooled item, returned by the drain callback.
pub enum DrainStep {
    /// analyzer accepted it (202) — remove from the queue.
    Delivered,
    /// analyzer still unreachable — stop draining and keep the backlog in order.
    Transient,
    /// analyzer rejected it for good (validation / auth) — move to dead-letter.
    Permanent,
}

/// Durable FIFO spool of undelivered uploads, one file per item.
pub struct Spool {
    dir: PathBuf,
    deadletter_dir: PathBuf,
    max_bytes: u64,
}

impl Spool {
    /// Build a spool from the environment, or `None` if spooling is unavailable.
    ///
    /// Directory resolution, first writable wins: `ANALYZER_SPOOL_DIR` if set,
    /// then `/var/lib/kcatta/agentd/spool`, then a temp-dir fallback. `None`
    /// means no candidate could be created — the caller then falls back to its
    /// prior drop-after-retries behaviour rather than failing the upload.
    /// The byte budget is read from `ANALYZER_SPOOL_MAX_BYTES` (default 64 MiB).
    pub fn from_env() -> Option<Self> {
        let max_bytes = std::env::var("ANALYZER_SPOOL_MAX_BYTES")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .filter(|&b| b > 0)
            .unwrap_or(DEFAULT_MAX_BYTES);

        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Some(dir) = std::env::var_os("ANALYZER_SPOOL_DIR") {
            if !dir.is_empty() {
                candidates.push(PathBuf::from(dir));
            }
        }
        candidates.push(PathBuf::from("/var/lib/kcatta/agentd/spool"));
        candidates.push(std::env::temp_dir().join("kcatta-agentd-spool"));

        candidates.iter().find_map(|dir| Self::at(dir, max_bytes))
    }

    /// Construct a spool rooted at `dir` with a `max_bytes` budget, creating the
    /// queue and `deadletter/` directories. `None` if they cannot be created.
    pub fn at(dir: &Path, max_bytes: u64) -> Option<Self> {
        let deadletter_dir = dir.join("deadletter");
        fs::create_dir_all(dir).ok()?;
        fs::create_dir_all(&deadletter_dir).ok()?;
        Some(Self {
            dir: dir.to_path_buf(),
            deadletter_dir,
            max_bytes,
        })
    }

    /// Append one undelivered upload, enforcing the byte budget by evicting the
    /// oldest items first. An item larger than the whole budget is dead-lettered
    /// rather than evicting the entire backlog to (fail to) fit it.
    pub fn enqueue(&self, path: &str, body: &serde_json::Value) -> io::Result<()> {
        let item = SpooledItem {
            path: path.to_string(),
            body: body.clone(),
        };
        let bytes = serde_json::to_vec(&item)?;
        if bytes.len() as u64 > self.max_bytes {
            return self.dead_letter_raw(&bytes, "exceeds spool size budget");
        }
        self.evict_until_fits(bytes.len() as u64)?;
        write_atomic(&self.dir.join(self.next_name()), &bytes)
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
            let raw = match fs::read(&path) {
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
                // analyzer still down: stop here so the backlog stays ordered.
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
            let meta = match entry.metadata() {
                Ok(meta) if meta.is_file() => meta,
                _ => continue,
            };
            out.push((entry.path(), meta.len()));
        }
        out.sort_by(|a, b| a.0.file_name().cmp(&b.0.file_name()));
        Ok(out)
    }

    /// Evict oldest queued items until `incoming` more bytes fit within budget.
    fn evict_until_fits(&self, incoming: u64) -> io::Result<()> {
        let entries = self.queue_files()?;
        let mut total: u64 = entries.iter().map(|(_, size)| *size).sum();
        for (path, size) in entries {
            if total + incoming <= self.max_bytes {
                break;
            }
            if remove_if_present(&path).is_ok() {
                total = total.saturating_sub(size);
            }
        }
        Ok(())
    }

    /// Copy raw bytes into the dead-letter dir (with a `.reason` sidecar) and
    /// remove the source from the queue.
    fn move_to_deadletter(&self, src: &Path, raw: &[u8], reason: &str) -> io::Result<()> {
        self.dead_letter_raw(raw, reason)?;
        remove_if_present(src)
    }

    /// Write raw bytes to the dead-letter dir for operator triage. Best-effort:
    /// the `.reason` sidecar is informational and its failure is ignored.
    fn dead_letter_raw(&self, raw: &[u8], reason: &str) -> io::Result<()> {
        let name = self.next_name();
        let target = self.deadletter_dir.join(&name);
        write_atomic(&target, raw)?;
        let _ = fs::write(
            self.deadletter_dir.join(format!("{name}.reason")),
            reason.as_bytes(),
        );
        Ok(())
    }

    /// A unique, lexically-sortable file name: zero-padded epoch-nanos so a name
    /// sort is a chronological sort, plus pid + sequence to avoid collisions.
    fn next_name(&self) -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        format!("{nanos:039}-{}-{seq}.json", std::process::id())
    }
}

/// Atomically publish `bytes` at `target`: write a sibling `.tmp` then rename, so
/// a reader (drain) never observes a half-written file.
fn write_atomic(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = target.with_extension("json.tmp");
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, target)
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

    fn temp_spool(max_bytes: u64) -> (PathBuf, Spool) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "kcatta-spool-test-{}-{nanos}-{seq}",
            std::process::id()
        ));
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
