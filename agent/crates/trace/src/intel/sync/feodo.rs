//! abuse.ch Feodo Tracker IP blocklist adapter.
//!
//! Source: https://feodotracker.abuse.ch/
//! Default export: https://feodotracker.abuse.ch/downloads/ipblocklist.json

use crate::intel::FeedIndicator;
use crate::ThreatFeed;

/// Default Feodo Tracker IP blocklist export URL.
pub const DEFAULT_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
/// Source label applied to indicators imported from this feed.
pub const SOURCE: &str = "abuse.ch-feodo";

#[derive(Debug, serde::Deserialize)]
struct FeodoEntry {
    ip_address: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    malware: Option<String>,
    #[serde(default)]
    last_online: Option<String>,
}

/// Locate the array of rows in a Feodo export. The canonical export is a bare
/// JSON array, but abuse.ch has historically wrapped rows in an object
/// (`{"data": [...]}`); accept both so an upstream format tweak doesn't break sync.
fn extract_entries_array(root: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    if let Some(arr) = root.as_array() {
        return Some(arr);
    }
    if let Some(obj) = root.as_object() {
        for key in ["data", "ipblocklist", "results", "entries"] {
            if let Some(arr) = obj.get(key).and_then(|v| v.as_array()) {
                return Some(arr);
            }
        }
    }
    None
}

/// Parse the Feodo Tracker JSON export into a [`ThreatFeed`].
///
/// Resilient to an untrusted feed: a single malformed/foreign row is skipped
/// rather than discarding the whole batch of otherwise-valid IOCs.
pub fn parse_json(text: &str) -> anyhow::Result<ThreatFeed> {
    let root: serde_json::Value = serde_json::from_str(text)?;
    let entries = extract_entries_array(&root)
        .ok_or_else(|| anyhow::anyhow!("feodo export: expected a JSON array of entries"))?;
    let mut indicators = Vec::with_capacity(entries.len());

    for value in entries {
        let entry: FeodoEntry = match serde_json::from_value(value.clone()) {
            Ok(e) => e,
            Err(_) => continue, // skip a row missing ip_address / wrong shape
        };
        let ip = entry.ip_address.trim();
        if ip.is_empty() {
            continue;
        }

        let mut description = Vec::new();
        if let Some(malware) = &entry.malware {
            description.push(format!("malware: {malware}"));
        }
        if let Some(status) = &entry.status {
            description.push(format!("status: {status}"));
        }
        if let Some(last) = &entry.last_online {
            description.push(format!("last_online: {last}"));
        }

        indicators.push(FeedIndicator {
            indicator_type: crate::contract::IndicatorType::Ip,
            value: ip.to_string(),
            category: "c2".to_string(),
            severity: crate::contract::Severity::High,
            description: if description.is_empty() {
                None
            } else {
                Some(description.join("; "))
            },
            source: Some(SOURCE.to_string()),
        });
    }

    Ok(ThreatFeed::from_feed_indicators(SOURCE, indicators))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = r#"[
        {
            "ip_address": "109.234.34.83",
            "port": 447,
            "status": "online",
            "malware": "Emotet",
            "last_online": "2026-01-01 12:00:00 UTC"
        },
        {
            "ip_address": "203.0.113.50",
            "status": "offline",
            "malware": "QakBot"
        }
    ]"#;

    #[test]
    fn skips_malformed_rows_keeps_valid_ones() {
        // One good row, one missing ip_address, one wrong type: only the good one survives.
        let text = r#"[
            {"ip_address": "198.51.100.7", "malware": "Dridex"},
            {"port": 443, "status": "online"},
            "not-an-object"
        ]"#;
        let feed = parse_json(text).unwrap();
        assert_eq!(feed.len(), 1);
    }

    #[test]
    fn accepts_object_wrapped_export() {
        let text = r#"{"data": [{"ip_address": "198.51.100.9", "malware": "Emotet"}]}"#;
        let feed = parse_json(text).unwrap();
        assert_eq!(feed.len(), 1);
    }

    #[test]
    fn parses_feodo_export() {
        let feed = parse_json(FIXTURE).unwrap();
        assert_eq!(feed.len(), 2);
        let matches = feed.export_matches();
        assert_eq!(matches[0].indicator, "109.234.34.83");
        assert_eq!(matches[0].category, "c2");
        assert_eq!(matches[0].severity, crate::contract::Severity::High);
        assert_eq!(matches[0].source, SOURCE);
        assert!(matches[0].description.as_ref().unwrap().contains("Emotet"));
    }
}
