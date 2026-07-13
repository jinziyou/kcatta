//! abuse.ch SSLBL JA3 Fingerprint Blacklist adapter.
//!
//! Source: https://sslbl.abuse.ch/
//! Default export: https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv
//!
//! This is the one abuse.ch feed that carries JA3 TLS fingerprints, so it is
//! what lights up the (otherwise unpopulated) JA3 index. The export is a CSV
//! with a `#`-commented header followed by rows:
//! `ja3_md5,Firstseen,Lastseen,Listingreason`.

use crate::contract::{IndicatorType, Severity};
use agent_detect::ioc::{FeedIndicator, ThreatFeed};

/// Default SSLBL JA3 fingerprint blocklist export URL.
pub const DEFAULT_URL: &str = "https://sslbl.abuse.ch/blacklist/ja3_fingerprints.csv";
/// Source label applied to indicators imported from this feed.
pub const SOURCE: &str = "abuse.ch-sslbl-ja3";

/// A JA3 fingerprint is an MD5 hash: exactly 32 hex characters.
fn is_ja3_md5(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Parse the SSLBL JA3 fingerprint CSV export into a [`ThreatFeed`].
///
/// Resilient to an untrusted feed: `#`-comment and blank lines are skipped, and
/// a row whose first field is not a valid JA3 MD5 is dropped rather than
/// poisoning the batch of otherwise-valid fingerprints.
pub fn parse_csv(text: &str) -> anyhow::Result<ThreatFeed> {
    let mut indicators = Vec::new();

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // ja3_md5, Firstseen, Lastseen, Listingreason. `splitn(4, ..)` so a reason
        // that itself contains a comma is preserved whole (last field = remainder).
        let mut cols = line.splitn(4, ',');
        let ja3 = cols.next().unwrap_or("").trim().to_ascii_lowercase();
        if !is_ja3_md5(&ja3) {
            continue; // header drift / malformed / foreign row
        }
        let _firstseen = cols.next();
        let lastseen = cols.next().map(str::trim).filter(|s| !s.is_empty());
        let reason = cols.next().map(str::trim).filter(|s| !s.is_empty());

        // Surface the last-seen date so an operator sees this feed's age at match
        // time — SSLBL's JA3 list has not been updated since 2021, and a hit on a
        // years-old fingerprint should be read in that light.
        let description = match (reason, lastseen) {
            (Some(r), Some(ls)) => Some(format!("SSLBL JA3 (last seen {ls}): {r}")),
            (Some(r), None) => Some(format!("SSLBL listing reason: {r}")),
            (None, Some(ls)) => Some(format!("SSLBL JA3 (last seen {ls})")),
            (None, None) => None,
        };

        indicators.push(FeedIndicator {
            indicator_type: IndicatorType::Ja3,
            value: ja3,
            category: "malware".to_string(),
            // SSLBL lists fingerprints tied to confirmed malware families — treat
            // a hit as high-signal (the staleness caveat rides in the description).
            severity: Severity::High,
            description,
            source: Some(SOURCE.to_string()),
        });
    }

    Ok(ThreatFeed::from_feed_indicators(SOURCE, indicators))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = "\
################################################################
# abuse.ch Suricata JA3 Fingerprint Blacklist (CSV)            #
# ja3_md5,Firstseen,Lastseen,Listingreason
#
b386946a5a44d1ddcc843bc75336dfce,2017-07-14 18:08:15,2019-07-27 20:42:54,Dridex
1aa7bf8b97e540ca5edd75f7b8384bfa,2017-07-14 20:23:38,2019-07-28 01:38:22,TrickBot
";

    #[test]
    fn parses_ja3_rows_skipping_comments() {
        let feed = parse_csv(FIXTURE).unwrap();
        assert_eq!(feed.len(), 2);
        let m = feed.export_matches();
        assert_eq!(m[0].indicator, "b386946a5a44d1ddcc843bc75336dfce");
        assert_eq!(m[0].indicator_type, IndicatorType::Ja3);
        assert_eq!(m[0].category, "malware");
        assert_eq!(m[0].severity, Severity::High);
        assert_eq!(m[0].source, SOURCE);
        let desc = m[0].description.as_ref().unwrap();
        assert!(desc.contains("Dridex"));
        assert!(
            desc.contains("2019-07-27"),
            "last-seen date surfaces feed age"
        );
    }

    #[test]
    fn parsed_ja3_matches_a_flow_end_to_end() {
        use std::net::{IpAddr, Ipv4Addr};

        use chrono::Utc;

        use crate::contract::{TraceEvent, TraceProto};

        let feed = parse_csv(FIXTURE).unwrap();
        let now = Utc::now();
        let flow = TraceEvent {
            trace_id: "t".into(),
            host_id: "h".into(),
            start_ts: now,
            end_ts: now,
            proto: TraceProto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            src_port: Some(40000),
            dst_ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
            dst_port: Some(443),
            bytes_sent: 1,
            bytes_recv: 1,
            packets_sent: 1,
            packets_recv: 1,
            app_proto: Some("TLS".into()),
            dns_query: None,
            tls_sni: None,
            // Uppercase on the wire — must still hit the lower-cased index.
            ja3: Some("B386946A5A44D1DDCC843BC75336DFCE".into()),
            threat_intel: Vec::new(),
        };
        let matches = feed.match_flow(&flow);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].indicator_type, IndicatorType::Ja3);
    }

    #[test]
    fn drops_rows_that_are_not_a_valid_ja3() {
        // A wrong-length hash, a non-hex value, and a short line all dropped.
        let text = "\
not_a_hash,2020,2020,Junk
zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz,2020,2020,Junk
b386946a5a44d1ddcc843bc75336dfce,2017-07-14,2019-07-27,Dridex
";
        let feed = parse_csv(text).unwrap();
        assert_eq!(feed.len(), 1);
    }

    #[test]
    fn uppercase_ja3_is_normalized_to_lowercase() {
        let text = "B386946A5A44D1DDCC843BC75336DFCE,2017,2019,Dridex\n";
        let feed = parse_csv(text).unwrap();
        assert_eq!(
            feed.export_matches()[0].indicator,
            "b386946a5a44d1ddcc843bc75336dfce"
        );
    }

    #[test]
    fn row_without_reason_still_imports() {
        let text = "b386946a5a44d1ddcc843bc75336dfce\n";
        let feed = parse_csv(text).unwrap();
        assert_eq!(feed.len(), 1);
        assert!(feed.export_matches()[0].description.is_none());
    }
}
