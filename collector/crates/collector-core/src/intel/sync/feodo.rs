//! abuse.ch Feodo Tracker IP blocklist adapter.
//!
//! Source: https://feodotracker.abuse.ch/
//! Default export: https://feodotracker.abuse.ch/downloads/ipblocklist.json

use crate::intel::FeedIndicator;
use crate::ThreatFeed;

pub const DEFAULT_URL: &str = "https://feodotracker.abuse.ch/downloads/ipblocklist.json";
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

/// Parse the Feodo Tracker JSON export into a [`ThreatFeed`].
pub fn parse_json(text: &str) -> anyhow::Result<ThreatFeed> {
    let entries: Vec<FeodoEntry> = serde_json::from_str(text)?;
    let mut indicators = Vec::with_capacity(entries.len());

    for entry in entries {
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
