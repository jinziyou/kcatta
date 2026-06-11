//! Download remote IOC feeds and write local JSON for [`ThreatFeed`].
//!
//! Sync is deliberately offline from capture/matching: operators refresh
//! feeds on a schedule (cron / systemd timer), and `posture-flow capture`
//! reads the on-disk JSON via `--intel`.

pub mod feodo;

use std::path::Path;

use crate::ThreatFeed;

/// Merge multiple feeds into one, deduplicating on `(type, value)`.
///
/// When the same indicator appears in several feeds, keep the entry with
/// the highest severity; `source` becomes a comma-separated union.
pub fn merge_feeds(feeds: &[ThreatFeed]) -> ThreatFeed {
    use std::collections::HashMap;

    use crate::contract::{IndicatorType, Severity, ThreatMatch};

    let rank = |s: Severity| -> u8 {
        match s {
            Severity::Info => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    };

    let mut merged: HashMap<(IndicatorType, String), ThreatMatch> = HashMap::new();

    for feed in feeds {
        for m in feed.export_matches() {
            let key = (m.indicator_type, m.indicator.clone());
            merged
                .entry(key)
                .and_modify(|existing| {
                    if rank(m.severity) > rank(existing.severity) {
                        existing.severity = m.severity;
                    }
                    if m.description.is_some() && existing.description.is_none() {
                        existing.description.clone_from(&m.description);
                    }
                    // Treat `source` as a comma-separated set: append only if the
                    // new source isn't already a member. (Substring matching here
                    // wrongly dropped "abuse.ch" when "abuse.ch-feodo" was present.)
                    if !existing.source.split(',').any(|s| s == m.source) {
                        existing.source = format!("{},{}", existing.source, m.source);
                    }
                })
                .or_insert(m);
        }
    }

    let mut indicators: Vec<_> = merged.into_values().collect();
    indicators.sort_by(|a, b| a.indicator.cmp(&b.indicator));
    ThreatFeed::from_matches("merged", indicators)
}

/// Write a feed to the standard on-disk JSON format.
pub fn write_feed(path: impl AsRef<Path>, source: &str, feed: &ThreatFeed) -> anyhow::Result<()> {
    feed.write_json_path(path, source)
}
