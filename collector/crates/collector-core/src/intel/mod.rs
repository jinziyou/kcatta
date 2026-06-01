//! Threat-intelligence IOC matching: collector-side preliminary processing.
//!
//! A [`ThreatFeed`] is a set of indicators (malicious IPs, domains, JA3
//! TLS fingerprints). [`ThreatFeed::enrich`] annotates each captured
//! [`FlowEvent`] with the indicators it hits, so `form` can correlate the
//! observation against known-bad infrastructure without re-doing lookups.
//!
//! v0 matching is a linear scan over indicators -- feeds are small and
//! this keeps the logic obvious. A real deployment with large feeds will
//! swap the inner representation (hash index / bloom prefilter) behind the
//! same [`ThreatFeed::match_flow`] API.

use std::path::Path;

use serde::Deserialize;

use crate::contract::{FlowEvent, IndicatorType, Severity, ThreatMatch};

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
#[derive(Debug, Deserialize)]
struct FeedFile {
    #[serde(default = "default_source")]
    source: String,
    #[serde(default)]
    indicators: Vec<FeedIndicator>,
}

#[derive(Debug, Deserialize)]
struct FeedIndicator {
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

fn default_source() -> String {
    "unknown".to_string()
}

impl ThreatFeed {
    /// Built-in demo feed: enough indicators to light up the mock capture
    /// so the end-to-end pipeline (capture -> intel -> upload -> correlate)
    /// demonstrably produces an alert without any external feed.
    pub fn builtin() -> Self {
        Self {
            indicators: vec![
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
            ],
        }
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
        Ok(Self { indicators })
    }

    /// Number of loaded indicators.
    pub fn len(&self) -> usize {
        self.indicators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.indicators.is_empty()
    }

    /// Return every indicator that matches the given flow.
    pub fn match_flow(&self, flow: &FlowEvent) -> Vec<ThreatMatch> {
        self.indicators
            .iter()
            .filter(|ind| ind.matches(flow))
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

    /// Annotate every flow in-place with its IOC matches.
    pub fn enrich(&self, flows: &mut [FlowEvent]) {
        for flow in flows.iter_mut() {
            flow.threat_intel = self.match_flow(flow);
        }
    }
}

impl Indicator {
    fn matches(&self, flow: &FlowEvent) -> bool {
        match self.indicator_type {
            IndicatorType::Ip => {
                flow.src_ip.to_string() == self.value || flow.dst_ip.to_string() == self.value
            }
            IndicatorType::Domain => {
                domain_hit(flow.dns_query.as_deref(), &self.value)
                    || domain_hit(flow.tls_sni.as_deref(), &self.value)
            }
            IndicatorType::Ja3 => flow
                .ja3
                .as_deref()
                .map(|j| j.eq_ignore_ascii_case(&self.value))
                .unwrap_or(false),
        }
    }
}

/// A domain indicator hits when the observed host equals it (case-insensitive)
/// or is a subdomain of it (`a.b.evil` matches indicator `evil`).
fn domain_hit(observed: Option<&str>, indicator: &str) -> bool {
    let Some(host) = observed else { return false };
    let host = host.trim().to_ascii_lowercase();
    host == indicator || host.ends_with(&format!(".{indicator}"))
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
}
