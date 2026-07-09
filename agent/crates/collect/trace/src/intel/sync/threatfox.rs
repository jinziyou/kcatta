//! abuse.ch ThreatFox IOC adapter.
//!
//! Source: https://threatfox.abuse.ch/
//! Default export: https://threatfox.abuse.ch/export/json/recent/
//!
//! ThreatFox carries many indicator types; we import the two that fit our match
//! indices — `domain` (lights up the otherwise-empty domain index) and `ip:port`
//! (complements the feodo IP feed). `url` and `*_hash` types are skipped: they do
//! not map to the IP / domain / JA3 flow fields the matcher keys on.
//!
//! The export is a JSON object keyed by ThreatFox id, each value an array with a
//! single entry object.

use crate::contract::{IndicatorType, Severity};
use crate::ThreatFeed;
use agent_detect::ioc::FeedIndicator;

/// Default ThreatFox recent-IOC export URL.
pub const DEFAULT_URL: &str = "https://threatfox.abuse.ch/export/json/recent/";
/// Source label applied to indicators imported from this feed.
pub const SOURCE: &str = "abuse.ch-threatfox";

#[derive(Debug, serde::Deserialize)]
struct ThreatFoxEntry {
    ioc_value: String,
    ioc_type: String,
    #[serde(default)]
    threat_type: Option<String>,
    #[serde(default)]
    malware_printable: Option<String>,
    #[serde(default)]
    confidence_level: Option<u8>,
    #[serde(default)]
    tags: Option<String>,
}

/// Resolve severity. Severity is IMPACT (per the contract), so it is driven by
/// `threat_type` — C2 = High, mirroring the feodo adapter so the same indicator
/// class rates consistently across feeds. abuse.ch `confidence_level` is the
/// orthogonal CERTAINTY axis and is intentionally NOT a 1:1 severity input: a
/// genuinely low-certainty row (<50) is demoted one band, but confidence never
/// inflates impact.
fn severity_for(threat_type: Option<&str>, confidence: Option<u8>) -> Severity {
    let base = match threat_type {
        // Active command-and-control / malware delivery: high impact.
        Some("botnet_cc") | Some("payload_delivery") | Some("payload") => Severity::High,
        _ => Severity::Medium,
    };
    match confidence {
        Some(c) if c < 50 => demote(base),
        _ => base,
    }
}

/// One severity band lower (used to demote a low-certainty ThreatFox row).
fn demote(s: Severity) -> Severity {
    match s {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low | Severity::Info => Severity::Info,
    }
}

/// Map a ThreatFox `threat_type` to our coarse category, drawn from a CLOSED set
/// so an attacker-influenced feed cannot inject arbitrary text into the alert key
/// the category feeds. `botnet_cc -> c2` keeps the label aligned with the feodo
/// adapter so the same C2 seen across feeds folds together.
fn category_for(threat_type: Option<&str>) -> &'static str {
    match threat_type {
        Some("botnet_cc") => "c2",
        Some("payload_delivery") => "payload_delivery",
        Some("payload") => "payload",
        _ => "malware",
    }
}

/// A ThreatFox `domain` IOC we are willing to index. Requires at least two
/// non-empty dot-separated labels and only hostname-legal characters, so a
/// poisoned feed cannot push a bare TLD (`com`) or junk and have domain-suffix
/// expansion match benign infrastructure on every flow.
fn is_plausible_domain(d: &str) -> bool {
    let labels: Vec<&str> = d.split('.').filter(|l| !l.is_empty()).collect();
    labels.len() >= 2
        && d.len() <= 253
        && d.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Extract the host from a ThreatFox `ip:port` value. Handles bracketed IPv6
/// (`[2001:db8::1]:443`), a bare IPv6 literal (no port), and `ipv4:port`.
fn host_from_ip_port(value: &str) -> &str {
    let value = value.trim();
    if let Some(rest) = value.strip_prefix('[') {
        // [ipv6]:port — take what's inside the brackets.
        if let Some(end) = rest.find(']') {
            return &rest[..end];
        }
    }
    // A bare value that already parses as an IP (e.g. a port-less IPv6) is kept
    // whole, so a trailing-`:` split can't mangle it.
    if value.parse::<std::net::IpAddr>().is_ok() {
        return value;
    }
    // Otherwise strip the trailing `:port` (ipv4:port or host:port).
    match value.rsplit_once(':') {
        Some((host, _port)) => host,
        None => value,
    }
}

/// Parse the ThreatFox recent-IOC JSON export into a [`ThreatFeed`].
///
/// Resilient to an untrusted feed: a non-array value or a single malformed entry
/// is skipped rather than discarding the whole batch.
pub fn parse_json(text: &str) -> anyhow::Result<ThreatFeed> {
    let root: serde_json::Value = serde_json::from_str(text)?;
    let obj = root.as_object().ok_or_else(|| {
        anyhow::anyhow!("threatfox export: expected a JSON object of id -> [entry]")
    })?;

    let mut indicators = Vec::new();
    for entries in obj.values() {
        let Some(arr) = entries.as_array() else {
            continue;
        };
        for value in arr {
            let entry: ThreatFoxEntry = match serde_json::from_value(value.clone()) {
                Ok(e) => e,
                Err(_) => continue, // missing ioc_value/ioc_type or wrong shape
            };

            let (indicator_type, ioc_value) = match entry.ioc_type.as_str() {
                "domain" => {
                    let d = entry.ioc_value.trim().to_ascii_lowercase();
                    if !is_plausible_domain(&d) {
                        continue; // bare TLD / junk: would over-match via suffix expansion
                    }
                    (IndicatorType::Domain, d)
                }
                "ip:port" => (
                    IndicatorType::Ip,
                    host_from_ip_port(&entry.ioc_value).to_string(),
                ),
                _ => continue, // url / md5_hash / sha1_hash / sha256_hash: no flow field
            };
            if ioc_value.is_empty() {
                continue;
            }

            let mut description = Vec::new();
            if let Some(m) = entry.malware_printable.as_deref().filter(|s| !s.is_empty()) {
                description.push(m.to_string());
            }
            if let Some(t) = entry.tags.as_deref().filter(|s| !s.is_empty()) {
                description.push(format!("tags: {t}"));
            }

            indicators.push(FeedIndicator {
                indicator_type,
                value: ioc_value,
                category: category_for(entry.threat_type.as_deref()).to_string(),
                severity: severity_for(entry.threat_type.as_deref(), entry.confidence_level),
                description: if description.is_empty() {
                    None
                } else {
                    Some(description.join("; "))
                },
                source: Some(SOURCE.to_string()),
            });
        }
    }

    Ok(ThreatFeed::from_feed_indicators(SOURCE, indicators))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"{
        "1836308": [
            {
                "ioc_value": "az6trzrx.one1xbet.vip",
                "ioc_type": "domain",
                "threat_type": "payload_delivery",
                "malware_printable": "ClearFake",
                "confidence_level": 100,
                "tags": "clearfake"
            }
        ],
        "1836307": [
            {
                "ioc_value": "188.40.60.27:7802",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware_printable": "Remus",
                "confidence_level": 75,
                "tags": null
            }
        ],
        "1836306": [
            {
                "ioc_value": "40ad28b87b5ed395fe8ff303555cc28974682ed6cc5a71ede76c4b17648cb8ed",
                "ioc_type": "sha256_hash",
                "threat_type": "payload",
                "malware_printable": "KV",
                "confidence_level": 100
            }
        ],
        "1836305": [
            {
                "ioc_value": "http://62.60.226.159/debug.php",
                "ioc_type": "url",
                "threat_type": "botnet_cc",
                "confidence_level": 100
            }
        ]
    }"#;

    #[test]
    fn imports_domain_and_ip_skips_url_and_hash() {
        let feed = parse_json(FIXTURE).unwrap();
        assert_eq!(
            feed.len(),
            2,
            "only domain + ip:port import; url & hash skipped"
        );

        let m = feed.export_matches();
        let domain = m
            .iter()
            .find(|x| x.indicator_type == IndicatorType::Domain)
            .unwrap();
        assert_eq!(domain.indicator, "az6trzrx.one1xbet.vip");
        assert_eq!(domain.category, "payload_delivery");
        assert_eq!(domain.severity, Severity::High); // payload_delivery = high impact
        assert!(domain.description.as_ref().unwrap().contains("ClearFake"));

        let ip = m
            .iter()
            .find(|x| x.indicator_type == IndicatorType::Ip)
            .unwrap();
        assert_eq!(ip.indicator, "188.40.60.27", "port stripped");
        assert_eq!(ip.category, "c2", "botnet_cc -> c2 (folds with feodo)");
        // botnet_cc = High impact; confidence 75 (>=50) does not demote — a
        // confirmed C2 must not be under-stated to Medium just because certainty<100.
        assert_eq!(ip.severity, Severity::High);
        assert_eq!(ip.source, SOURCE);
    }

    #[test]
    fn severity_tracks_impact_not_confidence() {
        // High-impact class stays High across confidence; only <50 certainty demotes.
        assert_eq!(severity_for(Some("botnet_cc"), Some(100)), Severity::High);
        assert_eq!(severity_for(Some("botnet_cc"), Some(50)), Severity::High);
        assert_eq!(severity_for(Some("botnet_cc"), Some(20)), Severity::Medium); // demoted
                                                                                 // Unknown class is Medium baseline; low certainty demotes to Low.
        assert_eq!(severity_for(Some("other"), Some(90)), Severity::Medium);
        assert_eq!(severity_for(None, None), Severity::Medium);
        assert_eq!(severity_for(Some("payload"), Some(10)), Severity::Medium);
    }

    #[test]
    fn rejects_bare_tld_and_junk_domains() {
        // A poisoned feed pushing a bare TLD / single label would, via suffix
        // expansion, match benign infrastructure on every flow — must be dropped.
        let text = r#"{
            "1": [{"ioc_value": "com", "ioc_type": "domain", "confidence_level": 100}],
            "2": [{"ioc_value": "evil.example", "ioc_type": "domain", "confidence_level": 100}],
            "3": [{"ioc_value": "ev!l.example/path", "ioc_type": "domain", "confidence_level": 100}]
        }"#;
        let feed = parse_json(text).unwrap();
        assert_eq!(feed.len(), 1, "only the well-formed domain survives");
        assert_eq!(feed.export_matches()[0].indicator, "evil.example");
    }

    #[test]
    fn ipv6_ip_port_forms_strip_port_correctly() {
        assert_eq!(host_from_ip_port("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(host_from_ip_port("2001:db8::1"), "2001:db8::1"); // bare, no port
        assert_eq!(host_from_ip_port("188.40.60.27:7802"), "188.40.60.27");
        assert_eq!(host_from_ip_port("evil.example:8080"), "evil.example");
    }

    #[test]
    fn skips_malformed_entries() {
        let text = r#"{
            "1": [{"ioc_type": "domain"}],
            "2": "not-an-array",
            "3": [{"ioc_value": "bad.example", "ioc_type": "domain", "confidence_level": 50}]
        }"#;
        let feed = parse_json(text).unwrap();
        assert_eq!(feed.len(), 1);
        let only = &feed.export_matches()[0];
        assert_eq!(only.indicator, "bad.example");
        assert_eq!(only.severity, Severity::Medium); // unknown threat_type baseline
    }

    #[test]
    fn missing_confidence_is_medium() {
        let text = r#"{"1": [{"ioc_value": "x.example", "ioc_type": "domain"}]}"#;
        let feed = parse_json(text).unwrap();
        assert_eq!(feed.export_matches()[0].severity, Severity::Medium);
    }

    #[test]
    fn empty_host_after_strip_is_dropped() {
        // ":443" -> host "" -> dropped; whitespace-only domain -> "" -> dropped;
        // a bare IPv4:port host is kept.
        let text = r#"{
            "1": [{"ioc_value": ":443", "ioc_type": "ip:port", "confidence_level": 80}],
            "2": [{"ioc_value": "   ", "ioc_type": "domain", "confidence_level": 80}],
            "3": [{"ioc_value": "8.8.8.8:53", "ioc_type": "ip:port", "confidence_level": 80}]
        }"#;
        let feed = parse_json(text).unwrap();
        assert_eq!(feed.len(), 1);
        assert_eq!(feed.export_matches()[0].indicator, "8.8.8.8");
    }

    #[test]
    fn parsed_indicators_match_a_flow_end_to_end() {
        use std::net::{IpAddr, Ipv4Addr};

        use chrono::Utc;

        use crate::contract::{TraceEvent, TraceProto};

        let feed = parse_json(FIXTURE).unwrap();
        let now = Utc::now();
        let flow = TraceEvent {
            trace_id: "t".into(),
            host_id: "h".into(),
            start_ts: now,
            end_ts: now,
            proto: TraceProto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            src_port: Some(40000),
            dst_ip: IpAddr::V4(Ipv4Addr::new(188, 40, 60, 27)), // == the ip:port indicator host
            dst_port: Some(443),
            bytes_sent: 1,
            bytes_recv: 1,
            packets_sent: 1,
            packets_recv: 1,
            app_proto: Some("TLS".into()),
            dns_query: None,
            tls_sni: Some("cdn.az6trzrx.one1xbet.vip".into()), // subdomain of the domain indicator
            ja3: None,
            threat_intel: Vec::new(),
        };
        let types: std::collections::HashSet<_> = feed
            .match_flow(&flow)
            .iter()
            .map(|m| m.indicator_type)
            .collect();
        assert!(
            types.contains(&IndicatorType::Ip),
            "ip:port indicator must match dst_ip"
        );
        assert!(
            types.contains(&IndicatorType::Domain),
            "domain indicator must match the SNI parent domain"
        );
    }
}
