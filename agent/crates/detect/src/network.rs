//! Network IOC and lightweight IDS detection.
//!
//! This module owns the transition from collected [`TraceEvent`] values to
//! normalized [`Detection`] facts. It enriches the wire events in place so IOC
//! matches remain available to downstream consumers, then emits detections in
//! event order. For each event, IOC detections precede its optional IDS hit.

use agent_contract::{IndicatorType, Severity, ThreatMatch, TraceEvent};

use crate::ioc::ThreatFeed;
use crate::Detection;

/// Well-known backdoor/C2 destination ports flagged by the built-in IDS rule.
const BACKDOOR_PORTS: &[u16] = &[4444, 31337, 6667, 1337];

/// Enrich captured events with IOC matches and convert all enabled hits into
/// normalized detections.
///
/// Events and their `threat_intel` fields retain wire compatibility. Returned
/// detections follow event order; within one event, all IOC detections are
/// emitted before the optional IDS detection.
pub fn detect(feed: &ThreatFeed, events: &mut [TraceEvent], include_ids: bool) -> Vec<Detection> {
    feed.enrich(events);

    let mut detections = Vec::new();
    for flow in events {
        detections.extend(flow.threat_intel.iter().map(|hit| Detection::Network {
            severity: hit.severity,
            proto: flow.proto,
            src_ip: flow.src_ip.to_string(),
            src_port: flow.src_port,
            dst_ip: flow.dst_ip.to_string(),
            dst_port: flow.dst_port,
            response_ip: response_ip_for_hit(flow, hit),
            indicator: hit.indicator.clone(),
            indicator_type: hit.indicator_type,
            category: hit.category.clone(),
            source: hit.source.clone(),
        }));

        if include_ids {
            if let Some(detection) = ids_detection(flow) {
                detections.push(detection);
            }
        }
    }

    detections
}

/// Authorize an egress block only when an IP IOC matched the observed
/// destination. The current nft/eBPF responders block future egress by
/// destination; a source-IP hit may describe inbound traffic and therefore
/// remains report-only instead of claiming an ineffective response. Non-IP
/// indicators likewise do not authorize an endpoint action.
fn response_ip_for_hit(flow: &TraceEvent, hit: &ThreatMatch) -> Option<String> {
    if hit.indicator_type != IndicatorType::Ip {
        return None;
    }

    let indicator = hit.indicator.parse::<std::net::IpAddr>().ok()?;
    if indicator == flow.dst_ip {
        Some(flow.dst_ip.to_string())
    } else {
        // Source matches and any future matcher invariant drift fail closed on
        // the response side while retaining the detection/report.
        None
    }
}

fn backdoor_port_signature(dst_port: u16) -> Option<(String, String)> {
    BACKDOOR_PORTS.contains(&dst_port).then(|| {
        (
            format!("GUARD-PORT-{dst_port}"),
            format!("connection to suspicious port {dst_port}"),
        )
    })
}

fn ids_detection(flow: &TraceEvent) -> Option<Detection> {
    let dst_port = flow.dst_port?;
    let (signature_id, signature_name) = backdoor_port_signature(dst_port)?;
    Some(Detection::Ids {
        severity: Severity::High,
        signature_id,
        signature_name,
        proto: flow.proto,
        src_ip: flow.src_ip.to_string(),
        src_port: flow.src_port,
        dst_ip: flow.dst_ip.to_string(),
        dst_port: flow.dst_port,
        // This port-only rule cannot tell whether the observed first-packet
        // direction represents an outbound connection or an inbound connection
        // to a local service. It reports the raw endpoints but does not authorize
        // either one for automatic blocking.
        response_ip: None,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use agent_contract::{IndicatorType, TraceProto};
    use chrono::Utc;

    use super::*;

    fn flow(trace_id: &str, dst_ip: [u8; 4], dst_port: u16) -> TraceEvent {
        TraceEvent {
            trace_id: trace_id.to_string(),
            host_id: "host-1".to_string(),
            start_ts: Utc::now(),
            end_ts: Utc::now(),
            proto: TraceProto::Tcp,
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            src_port: Some(54321),
            dst_ip: IpAddr::V4(Ipv4Addr::from(dst_ip)),
            dst_port: Some(dst_port),
            bytes_sent: 1,
            bytes_recv: 2,
            packets_sent: 1,
            packets_recv: 1,
            app_proto: None,
            dns_query: None,
            tls_sni: None,
            ja3: None,
            threat_intel: Vec::new(),
        }
    }

    #[test]
    fn flags_known_backdoor_ports() {
        for port in [4444u16, 31337, 6667, 1337] {
            let signature = backdoor_port_signature(port);
            assert!(signature.is_some(), "port {port} should be flagged");
            assert_eq!(signature.unwrap().0, format!("GUARD-PORT-{port}"));
        }
    }

    #[test]
    fn ignores_ordinary_ports() {
        assert!(backdoor_port_signature(443).is_none());
        assert!(backdoor_port_signature(80).is_none());
        assert!(backdoor_port_signature(22).is_none());
    }

    #[test]
    fn enriches_wire_events_and_preserves_detection_order() {
        let feed = ThreatFeed::from_json_str(
            r#"{
                "source": "network-test",
                "indicators": [
                    {"type": "ip", "value": "93.184.216.34", "category": "c2", "severity": "high"}
                ]
            }"#,
        )
        .unwrap();
        let mut events = vec![
            flow("flow-1", [93, 184, 216, 34], 4444),
            flow("flow-2", [192, 0, 2, 1], 31337),
        ];

        let detections = detect(&feed, &mut events, true);

        assert_eq!(events[0].threat_intel.len(), 1);
        assert!(events[1].threat_intel.is_empty());
        assert_eq!(detections.len(), 3);
        assert!(matches!(
            &detections[0],
            Detection::Network {
                indicator_type: IndicatorType::Ip,
                indicator,
                response_ip: Some(response_ip),
                source,
                ..
            } if indicator == "93.184.216.34"
                && response_ip == "93.184.216.34"
                && source == "network-test"
        ));
        assert!(matches!(
            &detections[1],
            Detection::Ids { signature_id, .. } if signature_id == "GUARD-PORT-4444"
        ));
        assert!(matches!(
            &detections[2],
            Detection::Ids { signature_id, .. } if signature_id == "GUARD-PORT-31337"
        ));
    }

    #[test]
    fn ids_can_be_disabled_without_disabling_ioc_detection() {
        let feed = ThreatFeed::builtin();
        let mut events = vec![flow("flow-1", [93, 184, 216, 34], 4444)];

        let detections = detect(&feed, &mut events, false);

        assert_eq!(detections.len(), 1);
        assert!(matches!(detections[0], Detection::Network { .. }));
        assert!(events[0].threat_intel.len() == 1);
    }

    #[test]
    fn direction_ambiguous_ids_hit_never_authorizes_endpoint_blocking() {
        let feed = ThreatFeed::from_feed_indicators("ids-only", Vec::new());
        // Model an inbound connection from a public peer to a local service on
        // a suspicious port. Treating `dst_ip` as the block target would block
        // this host's own address.
        let mut inbound = flow("inbound", [10, 0, 0, 1], 4444);
        inbound.src_ip = "198.51.100.23".parse().unwrap();
        let mut events = vec![inbound];

        let detections = detect(&feed, &mut events, true);

        assert_eq!(detections.len(), 1);
        assert!(matches!(
            &detections[0],
            Detection::Ids {
                src_ip,
                dst_ip,
                response_ip: None,
                ..
            } if src_ip == "198.51.100.23" && dst_ip == "10.0.0.1"
        ));
        assert_eq!(detections[0].response_ip(), None);
    }

    #[test]
    fn source_ip_ioc_is_report_only_for_egress_block_backends() {
        let feed = ThreatFeed::from_json_str(
            r#"{
                "source": "source-ip-test",
                "indicators": [
                    {"type": "ip", "value": "10.0.0.1", "category": "scanner", "severity": "high"}
                ]
            }"#,
        )
        .unwrap();
        let mut events = vec![flow("source-ip", [192, 0, 2, 10], 443)];

        let detections = detect(&feed, &mut events, false);

        assert_eq!(detections.len(), 1);
        assert!(matches!(
            &detections[0],
            Detection::Network {
                src_ip,
                dst_ip,
                response_ip: None,
                ..
            } if src_ip == "10.0.0.1"
                && dst_ip == "192.0.2.10"
        ));
        assert_eq!(detections[0].response_ip(), None);
    }

    #[test]
    fn domain_and_ja3_iocs_never_authorize_an_ip_block() {
        let feed = ThreatFeed::from_json_str(
            r#"{
                "source": "non-ip-test",
                "indicators": [
                    {"type": "domain", "value": "evil.example", "category": "c2", "severity": "high"},
                    {"type": "ja3", "value": "bad-fingerprint", "category": "malware", "severity": "high"}
                ]
            }"#,
        )
        .unwrap();
        let mut event = flow("non-ip", [203, 0, 113, 20], 443);
        event.tls_sni = Some("api.evil.example".to_string());
        event.ja3 = Some("bad-fingerprint".to_string());
        let mut events = vec![event];

        let detections = detect(&feed, &mut events, false);

        assert_eq!(detections.len(), 2);
        assert!(detections.iter().all(|detection| matches!(
            detection,
            Detection::Network {
                response_ip: None,
                ..
            }
        )));
        assert!(detections
            .iter()
            .all(|detection| detection.response_ip().is_none()));
        assert!(events[0].threat_intel.iter().any(|hit| {
            hit.indicator_type == IndicatorType::Domain && hit.indicator == "evil.example"
        }));
        assert!(events[0].threat_intel.iter().any(|hit| {
            hit.indicator_type == IndicatorType::Ja3 && hit.indicator == "bad-fingerprint"
        }));
    }
}
