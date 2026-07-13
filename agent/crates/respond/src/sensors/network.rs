//! Network linkage + IDS sensor.
//!
//! Composes `agent-collect-trace` collection
//! ([`agent_collect_trace::capture_batch`]) with
//! [`agent_detect::network::detect`]: each iteration captures a short window,
//! runs IOC and optional IDS detection, and sends the normalized results to the
//! response pipeline.
//!
//! Near-real-time by nature (the windowed capture means a block lands on the
//! NEXT connection, not the triggering packet) — documented as a v1 limitation.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;

use agent_collect_trace::{capture_batch, CaptureConfig};
use agent_detect::ioc::ThreatFeed;
use agent_detect::network::detect as detect_network;
use anyhow::{bail, Context as _};

use crate::config::NetworkConfig;
use crate::sensors::{Sensor, SensorEvent};

/// Bound one blocking live-capture call so shared shutdown remains responsive.
const MAX_CAPTURE_SLICE_SECS: u64 = 5;

/// Network / IDS sensor driving `agent-collect-trace` capture in a loop.
pub struct NetworkSensor {
    config: NetworkConfig,
}

impl NetworkSensor {
    /// Build the sensor from network config.
    pub fn new(config: NetworkConfig) -> Self {
        Self { config }
    }

    fn load_feed(&self) -> anyhow::Result<ThreatFeed> {
        match &self.config.intel {
            Some(path) => ThreatFeed::from_json_path(path)
                .with_context(|| format!("load configured network IOC feed {}", path.display())),
            None if cfg!(feature = "ids") => Ok(ThreatFeed::from_feed_indicators(
                "ids-only-empty-feed",
                Vec::new(),
            )),
            None => bail!(
                "network sensor requires `network.intel`; alternatively build with the `ids` \
                 feature to run IDS-only with no IOC feed"
            ),
        }
    }

    fn run_inner(
        &self,
        tx: &Sender<SensorEvent>,
        shutdown: &Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        let feed = self.load_feed()?;

        while !shutdown.load(Ordering::Relaxed) {
            let capture_config = self.capture_config();
            let mut batch = capture_batch(&capture_config)
                .context("capture live network telemetry for response")?;
            if shutdown.load(Ordering::SeqCst) {
                break;
            }
            for detection in detect_network(&feed, &mut batch.events, cfg!(feature = "ids")) {
                if tx.send(detection.into()).is_err() {
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    fn capture_config(&self) -> CaptureConfig {
        let window_secs = self.config.window_secs.clamp(1, MAX_CAPTURE_SLICE_SECS);
        #[cfg(feature = "pcap")]
        {
            CaptureConfig::pcap(
                self.config.iface.clone(),
                window_secs,
                "tcp or udp or icmp".to_string(),
            )
        }
        #[cfg(not(feature = "pcap"))]
        {
            CaptureConfig::win_net(window_secs)
        }
    }
}

impl Sensor for NetworkSensor {
    fn name(&self) -> &'static str {
        "network"
    }

    fn run(
        self: Box<Self>,
        tx: Sender<SensorEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        let result = self.run_inner(&tx, &shutdown);
        if result.is_err() {
            // A dead protection source is fatal. Wake the supervisor and peer
            // sensors immediately; joining this thread preserves the concrete
            // error for the final non-zero result.
            shutdown.store(true, Ordering::SeqCst);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_response_never_selects_mock_capture() {
        let sensor = NetworkSensor::new(NetworkConfig::default());
        let config = sensor.capture_config();

        #[cfg(feature = "pcap")]
        assert!(matches!(
            config.backend,
            agent_collect_trace::CaptureBackend::Pcap(_)
        ));
        #[cfg(not(feature = "pcap"))]
        assert!(matches!(
            config.backend,
            agent_collect_trace::CaptureBackend::WinNet(_)
        ));
    }

    #[test]
    fn capture_slice_is_bounded_for_shutdown_responsiveness() {
        let sensor = NetworkSensor::new(NetworkConfig {
            window_secs: u64::MAX,
            ..NetworkConfig::default()
        });
        let config = sensor.capture_config();

        #[cfg(feature = "pcap")]
        match config.backend {
            agent_collect_trace::CaptureBackend::Pcap(config) => {
                assert_eq!(config.duration.as_secs(), MAX_CAPTURE_SLICE_SECS);
            }
            _ => panic!("response network must select pcap"),
        }
        #[cfg(not(feature = "pcap"))]
        match config.backend {
            agent_collect_trace::CaptureBackend::WinNet(config) => {
                assert_eq!(config.duration.as_secs(), MAX_CAPTURE_SLICE_SECS);
            }
            _ => panic!("response network must select winnet"),
        }
    }

    #[test]
    fn configured_feed_failure_is_fatal_without_demo_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broken-feed.json");
        std::fs::write(&path, "not valid JSON").unwrap();
        let config = NetworkConfig {
            intel: Some(path),
            ..NetworkConfig::default()
        };
        let sensor = NetworkSensor::new(config);

        let error = sensor
            .load_feed()
            .expect_err("invalid configured feed must fail");

        assert!(error
            .to_string()
            .contains("load configured network IOC feed"));
    }

    #[cfg(not(feature = "ids"))]
    #[test]
    fn missing_feed_is_fatal_for_ioc_only_sensor() {
        let sensor = NetworkSensor::new(NetworkConfig::default());
        let error = sensor.load_feed().expect_err("missing feed must fail");
        assert!(error.to_string().contains("network.intel"));
    }

    #[cfg(feature = "ids")]
    #[test]
    fn ids_only_sensor_uses_an_empty_ioc_feed() {
        let sensor = NetworkSensor::new(NetworkConfig::default());
        let feed = sensor.load_feed().expect("IDS-only feed");
        assert!(feed.is_empty());
    }
}
