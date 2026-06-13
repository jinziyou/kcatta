//! Network linkage + IDS sensor.
//!
//! Reuses `agent-flow`'s capture + `ThreatFeed` IOC matcher: each iteration
//! captures a short window, enriches flows against the shared IOC feed, and
//! emits a [`Detection::Network`] per IOC hit. With the `ids` feature a minimal
//! built-in signature set also emits [`Detection::Ids`].
//!
//! Near-real-time by nature (the windowed capture means a block lands on the
//! NEXT connection, not the triggering packet) — documented as a v1 limitation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

use agent_flow::{run_capture_with_config, CaptureConfig, ThreatFeed};

use crate::config::NetworkConfig;
use crate::event::Detection;
use crate::sensors::Sensor;

/// Network / IDS sensor driving `agent-flow` capture in a loop.
pub struct NetworkSensor {
    config: NetworkConfig,
}

impl NetworkSensor {
    /// Build the sensor from network config.
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }

    fn run_inner(&self, tx: &Sender<Detection>, shutdown: &Arc<AtomicBool>) {
        let feed = match &self.config.intel {
            Some(path) => ThreatFeed::from_json_path(path).unwrap_or_else(|e| {
                eprintln!("guard: network intel load failed ({e}); using built-in feed");
                ThreatFeed::builtin()
            }),
            None => ThreatFeed::builtin(),
        };

        while !shutdown.load(Ordering::Relaxed) {
            let capture_config = self.capture_config();
            match run_capture_with_config(&feed, &capture_config) {
                Ok(batch) => {
                    for flow in &batch.flows {
                        for hit in &flow.threat_intel {
                            let detection = Detection::Network {
                                severity: hit.severity,
                                proto: flow.proto,
                                src_ip: flow.src_ip.to_string(),
                                src_port: flow.src_port,
                                dst_ip: flow.dst_ip.to_string(),
                                dst_port: flow.dst_port,
                                indicator: hit.indicator.clone(),
                                indicator_type: hit.indicator_type,
                                category: hit.category.clone(),
                                source: hit.source.clone(),
                            };
                            if tx.send(detection).is_err() {
                                return;
                            }
                        }
                        #[cfg(feature = "ids")]
                        if let Some(detection) = ids_check(flow) {
                            if tx.send(detection).is_err() {
                                return;
                            }
                        }
                    }
                }
                Err(e) => eprintln!("guard: network capture failed: {e}"),
            }

            // Sleep one window in small slices so shutdown is observed promptly.
            let window = Duration::from_secs(self.config.window_secs.max(1));
            let mut slept = Duration::ZERO;
            while slept < window && !shutdown.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                slept += Duration::from_millis(200);
            }
        }
    }

    fn capture_config(&self) -> CaptureConfig {
        #[cfg(feature = "pcap")]
        {
            CaptureConfig::pcap(
                self.config.iface.clone(),
                self.config.window_secs.max(1),
                "tcp or udp or icmp".to_string(),
            )
        }
        #[cfg(not(feature = "pcap"))]
        {
            CaptureConfig::mock()
        }
    }
}

impl Sensor for NetworkSensor {
    fn name(&self) -> &'static str {
        "network"
    }

    fn run(self: Box<Self>, tx: Sender<Detection>, shutdown: Arc<AtomicBool>) {
        self.run_inner(&tx, &shutdown);
    }
}

/// Minimal built-in IDS: flag flows to well-known backdoor/C2 ports.
#[cfg(feature = "ids")]
fn ids_check(flow: &agent_flow::FlowEvent) -> Option<Detection> {
    use agent_contract::Severity;
    const BACKDOOR_PORTS: &[u16] = &[4444, 31337, 6667, 1337];
    let dst_port = flow.dst_port?;
    if !BACKDOOR_PORTS.contains(&dst_port) {
        return None;
    }
    Some(Detection::Ids {
        severity: Severity::High,
        signature_id: format!("GUARD-PORT-{dst_port}"),
        signature_name: format!("connection to suspicious port {dst_port}"),
        proto: flow.proto,
        src_ip: flow.src_ip.to_string(),
        src_port: flow.src_port,
        dst_ip: flow.dst_ip.to_string(),
        dst_port: flow.dst_port,
    })
}
