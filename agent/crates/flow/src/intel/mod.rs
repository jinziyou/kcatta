//! Threat-intelligence IOC matching: collector-side preliminary processing.
//!
//! A [`ThreatFeed`] is a set of indicators (malicious IPs, domains, JA3
//! TLS fingerprints). [`ThreatFeed::enrich`] annotates each captured
//! [`FlowEvent`] with the indicators it hits, so `analyzer` can correlate the
//! observation against known-bad infrastructure without re-doing lookups.
//!
//! v0 matching uses hash indexes keyed by indicator value so lookup stays
//! O(flow fields) rather than O(all indicators). Domain suffix expansion
//! preserves parent-domain matching (`a.b.evil` hits indicator `evil`).

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::contract::{FlowEvent, IndicatorType, Severity, ThreatMatch};

pub mod sync;

/// One indicator of compromise loaded from a feed.
#[derive(Debug, Clone)]
struct Indicator {
    indicator_type: IndicatorType,
    /// Normalized (lower-cased) match value.
    value: String,
    category: String,
    severity: Severity,
    source: String,
    description: Option<String>,
}

/// A loaded threat-intel feed ready to match flows against.
#[derive(Debug, Clone)]
pub struct ThreatFeed {
    indicators: Vec<Indicator>,
    ip_index: HashMap<String, Vec<usize>>,
    ja3_index: HashMap<String, Vec<usize>>,
    domain_index: HashMap<String, Vec<usize>>,
}

/// On-disk feed format (JSON).
///
/// ```json
/// {
///   "source": "abuse.ch-feodo",
///   "indicators": [
///     {"type": "ip", "value": "93.184.216.34", "category": "c2", "severity": "high"},
///     {"type": "domain", "value": "evil.example", "category": "phishing", "severity": "medium"},
///     {"type": "ja3", "value": "e7d705a3...", "category": "malware", "severity": "high"}
///   ]
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FeedIndicator {
    #[serde(rename = "type")]
    indicator_type: IndicatorType,
    value: String,
    category: String,
    severity: Severity,
    #[serde(default)]
    description: Option<String>,
    /// Optional per-indicator source override; defaults to the feed source.
    #[serde(default)]
    source: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FeedFile {
    #[serde(default = "default_source")]
    source: String,
    #[serde(default)]
    indicators: Vec<FeedIndicator>,
}

fn default_source() -> String {
    "unknown".to_string()
}

impl ThreatFeed {
    fn from_indicators(indicators: Vec<Indicator>) -> Self {
        let mut feed = Self {
            indicators,
            ip_index: HashMap::new(),
            ja3_index: HashMap::new(),
            domain_index: HashMap::new(),
        };
        feed.rebuild_indexes();
        feed
    }

    fn rebuild_indexes(&mut self) {
        self.ip_index.clear();
        self.ja3_index.clear();
        self.domain_index.clear();
        for (idx, ind) in self.indicators.iter().enumerate() {
            match ind.indicator_type {
                IndicatorType::Ip => {
                    self.ip_index
                        .entry(canonical_ip_key(&ind.value))
                        .or_default()
                        .push(idx);
                }
                IndicatorType::Ja3 => {
                    self.ja3_index
                        .entry(ind.value.clone())
                        .or_default()
                        .push(idx);
                }
                IndicatorType::Domain => {
                    self.domain_index
                        .entry(ind.value.clone())
                        .or_default()
                        .push(idx);
                }
            }
        }
    }

    fn to_match(&self, idx: usize) -> ThreatMatch {
        let ind = &self.indicators[idx];
        ThreatMatch {
            indicator: ind.value.clone(),
            indicator_type: ind.indicator_type,
            category: ind.category.clone(),
            severity: ind.severity,
            source: ind.source.clone(),
            description: ind.description.clone(),
        }
    }

    /// Built-in demo feed: enough indicators to light up the mock capture
    /// so the end-to-end pipeline (capture -> intel -> upload -> correlate)
    /// demonstrably produces an alert without any external feed.
    pub fn builtin() -> Self {
        Self::from_indicators(vec![
            Indicator {
                indicator_type: IndicatorType::Ip,
                value: "93.184.216.34".to_string(),
                category: "c2".to_string(),
                severity: Severity::High,
                source: "builtin-demo".to_string(),
                description: Some("Demo: hard-coded C2 egress node".to_string()),
            },
            Indicator {
                indicator_type: IndicatorType::Ja3,
                value: "e7d705a3286e19ea42f587b344ee6865".to_string(),
                category: "malware".to_string(),
                severity: Severity::Medium,
                source: "builtin-demo".to_string(),
                description: Some("Demo: known malware TLS fingerprint".to_string()),
            },
        ])
    }

    /// Load a feed from a JSON file on disk.
    pub fn from_json_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read feed {}: {e}", path.display()))?;
        Self::from_json_str(&text)
            .map_err(|e| anyhow::anyhow!("parse feed {}: {e}", path.display()))
    }

    /// Parse a feed from a JSON string.
    pub fn from_json_str(text: &str) -> anyhow::Result<Self> {
        let file: FeedFile = serde_json::from_str(text)?;
        let indicators = file
            .indicators
            .into_iter()
            .map(|i| Indicator {
                indicator_type: i.indicator_type,
                value: i.value.trim().to_ascii_lowercase(),
                category: i.category,
                severity: i.severity,
                source: i.source.unwrap_or_else(|| file.source.clone()),
                description: i.description,
            })
            .collect();
        Ok(Self::from_indicators(indicators))
    }

    /// Build a feed from parsed sync indicators (used by feed adapters).
    pub(crate) fn from_feed_indicators(source: &str, items: Vec<FeedIndicator>) -> Self {
        Self::from_indicators(
            items
                .into_iter()
                .map(|i| Indicator {
                    indicator_type: i.indicator_type,
                    value: i.value.trim().to_ascii_lowercase(),
                    category: i.category,
                    severity: i.severity,
                    source: i.source.unwrap_or_else(|| source.to_string()),
                    description: i.description,
                })
                .collect(),
        )
    }

    /// Build a feed from wire-format matches (used by merge).
    pub(crate) fn from_matches(_source: &str, matches: Vec<ThreatMatch>) -> Self {
        Self::from_indicators(
            matches
                .into_iter()
                .map(|m| Indicator {
                    indicator_type: m.indicator_type,
                    value: m.indicator.trim().to_ascii_lowercase(),
                    category: m.category,
                    severity: m.severity,
                    source: m.source,
                    description: m.description,
                })
                .collect(),
        )
    }

    /// Export every loaded indicator (for merge / diagnostics).
    pub(crate) fn export_matches(&self) -> Vec<ThreatMatch> {
        self.indicators
            .iter()
            .map(|ind| ThreatMatch {
                indicator: ind.value.clone(),
                indicator_type: ind.indicator_type,
                category: ind.category.clone(),
                severity: ind.severity,
                source: ind.source.clone(),
                description: ind.description.clone(),
            })
            .collect()
    }

    /// Write this feed to disk in the standard JSON format.
    pub fn write_json_path(&self, path: impl AsRef<Path>, source: &str) -> anyhow::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let doc = FeedFile {
            source: source.to_string(),
            indicators: self
                .indicators
                .iter()
                .map(|ind| FeedIndicator {
                    indicator_type: ind.indicator_type,
                    value: ind.value.clone(),
                    category: ind.category.clone(),
                    severity: ind.severity,
                    description: ind.description.clone(),
                    source: Some(ind.source.clone()),
                })
                .collect(),
        };
        let text = format!("{}\n", serde_json::to_string_pretty(&doc)?);
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Number of loaded indicators.
    pub fn len(&self) -> usize {
        self.indicators.len()
    }

    /// Whether the feed has no indicators loaded.
    pub fn is_empty(&self) -> bool {
        self.indicators.is_empty()
    }

    /// Return every indicator that matches the given flow.
    pub fn match_flow(&self, flow: &FlowEvent) -> Vec<ThreatMatch> {
        let mut hit: HashSet<usize> = HashSet::new();

        for ip in [flow.src_ip.to_string(), flow.dst_ip.to_string()] {
            // The index is keyed by canonical IpAddr form; flow IPs are already
            // canonical (IpAddr::to_string), so a direct lookup is correct.
            if let Some(idxs) = self.ip_index.get(&ip) {
                hit.extend(idxs);
            }
        }

        if let Some(ja3) = flow.ja3.as_deref() {
            let key = ja3.to_ascii_lowercase();
            if let Some(idxs) = self.ja3_index.get(&key) {
                hit.extend(idxs);
            }
        }

        for host in [flow.dns_query.as_deref(), flow.tls_sni.as_deref()]
            .into_iter()
            .flatten()
        {
            for suffix in domain_suffixes(host) {
                if let Some(idxs) = self.domain_index.get(&suffix) {
                    hit.extend(idxs);
                }
            }
        }

        hit.into_iter().map(|idx| self.to_match(idx)).collect()
    }

    /// Annotate every flow in-place with its IOC matches.
    pub fn enrich(&self, flows: &mut [FlowEvent]) {
        for flow in flows.iter_mut() {
            flow.threat_intel = self.match_flow(flow);
        }
    }
}

/// Canonicalize an IP indicator for indexing. IPv6 has many textual forms for
/// the same address (`2001:0db8:0000:…:0001` vs `2001:db8::1`); parsing to
/// `IpAddr` and re-stringifying yields the same canonical key that flow IPs use
/// (`IpAddr::to_string`), so a non-compressed / leading-zero feed entry still
/// matches. Unparseable values fall back to the raw string (e.g. CIDR or junk).
fn canonical_ip_key(value: &str) -> String {
    match value.parse::<std::net::IpAddr>() {
        Ok(addr) => addr.to_string(),
        Err(_) => value.to_string(),
    }
}

/// Domain suffixes for index lookup (`login.evil.example` -> `login.evil.example`, `evil.example`, `example`).
fn domain_suffixes(host: &str) -> Vec<String> {
    let host = host.trim().to_ascii_lowercase();
    let parts: Vec<&str> = host.split('.').filter(|part| !part.is_empty()).collect();
    (0..parts.len())
        .map(|start| parts[start..].join("."))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use chrono::Utc;

    use super::*;
    use crate::contract::FlowProto;

    fn flow() -> FlowEvent {
        FlowEvent {
            flow_id: "f-1".to_string(),
            host_id: "h-1".to_string(),
            start_ts: Utc::now(),
            end_ts: Utc::now(),
            proto: FlowProto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)),
            src_port: Some(54321),
            dst_ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            dst_port: Some(443),
            bytes_sent: 1,
            bytes_recv: 1,
            packets_sent: 1,
            packets_recv: 1,
            app_proto: Some("TLS".to_string()),
            dns_query: None,
            tls_sni: Some("login.evil.example".to_string()),
            ja3: Some("E7D705A3286E19EA42F587B344EE6865".to_string()),
            threat_intel: Vec::new(),
        }
    }

    #[test]
    fn matches_ip_domain_and_ja3() {
        let feed = ThreatFeed::from_json_str(
            r#"{
                "source": "test-feed",
                "indicators": [
                    {"type": "ip", "value": "93.184.216.34", "category": "c2", "severity": "high"},
                    {"type": "domain", "value": "evil.example", "category": "phishing", "severity": "medium"},
                    {"type": "ja3", "value": "e7d705a3286e19ea42f587b344ee6865", "category": "malware", "severity": "high"}
                ]
            }"#,
        )
        .unwrap();

        let matches = feed.match_flow(&flow());
        assert_eq!(matches.len(), 3, "ip + subdomain + case-insensitive ja3");
        assert!(matches.iter().all(|m| m.source == "test-feed"));
    }

    #[test]
    fn no_match_returns_empty() {
        let feed = ThreatFeed::from_json_str(
            r#"{"indicators": [{"type": "ip", "value": "1.2.3.4", "category": "c2", "severity": "low"}]}"#,
        )
        .unwrap();
        assert!(feed.match_flow(&flow()).is_empty());
    }

    #[test]
    fn ipv6_indicator_matches_regardless_of_textual_form() {
        use std::net::Ipv6Addr;
        // Feed writes the fully-expanded, leading-zero form; the flow carries the
        // canonical compressed form. They must still match (regression: string
        // comparison missed this, only IpAddr comparison catches it).
        let feed = ThreatFeed::from_json_str(
            r#"{
                "source": "test-feed",
                "indicators": [
                    {"type": "ip", "value": "2001:0db8:0000:0000:0000:0000:0000:0001", "category": "c2", "severity": "high"}
                ]
            }"#,
        )
        .unwrap();

        let mut f = flow();
        f.dst_ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)); // 2001:db8::1
        f.tls_sni = None;
        f.ja3 = None;
        let matches = feed.match_flow(&f);
        assert_eq!(
            matches.len(),
            1,
            "expanded-form IPv6 indicator must match compressed flow IP"
        );
    }

    #[test]
    fn per_indicator_source_overrides_feed_source() {
        let feed = ThreatFeed::from_json_str(
            r#"{
                "source": "feed-default",
                "indicators": [
                    {"type": "ip", "value": "93.184.216.34", "category": "c2", "severity": "high", "source": "abuse.ch"}
                ]
            }"#,
        )
        .unwrap();
        assert_eq!(feed.match_flow(&flow())[0].source, "abuse.ch");
    }

    #[test]
    fn enrich_annotates_in_place() {
        let feed = ThreatFeed::builtin();
        let mut flows = vec![flow()];
        feed.enrich(&mut flows);
        // builtin flags the dst IP (c2) and the ja3 (malware).
        assert_eq!(flows[0].threat_intel.len(), 2);
    }

    #[test]
    fn write_json_roundtrip() {
        let feed = ThreatFeed::builtin();
        let dir = std::env::temp_dir().join("collector-feed-test");
        let path = dir.join("feed.json");
        feed.write_json_path(&path, "builtin-demo").unwrap();
        let loaded = ThreatFeed::from_json_path(&path).unwrap();
        assert_eq!(loaded.len(), feed.len());
        let _ = std::fs::remove_dir_all(dir);
    }
}
