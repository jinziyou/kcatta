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
use sha2::{Digest, Sha256};

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
            Some(path) => {
                let bytes = std::fs::read(path).with_context(|| {
                    format!("read configured network IOC feed {}", path.display())
                })?;
                if let Some(expected) = self.config.intel_sha256.as_deref() {
                    validate_sha256(expected)?;
                    let actual = sha256_hex(&bytes);
                    anyhow::ensure!(
                        actual == expected,
                        "network IOC feed SHA-256 mismatch for {}: expected {}, got {}",
                        path.display(),
                        expected,
                        actual
                    );
                }
                let text = std::str::from_utf8(&bytes).with_context(|| {
                    format!(
                        "decode configured network IOC feed {} as UTF-8",
                        path.display()
                    )
                })?;
                ThreatFeed::from_json_str(text)
                    .with_context(|| format!("load configured network IOC feed {}", path.display()))
            }
            None if self.config.intel_sha256.is_some() => {
                bail!("network.intel_sha256 requires network.intel")
            }
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
        self.capture_config_for(self.config.window_secs)
    }

    fn capture_config_for(&self, window_secs: u64) -> CaptureConfig {
        let window_secs = window_secs.clamp(1, MAX_CAPTURE_SLICE_SECS);
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

fn validate_sha256(value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() == 64
            && value
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)),
        "network.intel_sha256 must be exactly 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

impl Sensor for NetworkSensor {
    fn name(&self) -> &'static str {
        "network"
    }

    fn preflight(&self) -> anyhow::Result<()> {
        // Loading verifies the configured feed, optional digest, and parser.
        self.load_feed()?;
        // Exercise the real capture backend for the shortest supported window;
        // constructing CaptureConfig alone would not detect missing privileges,
        // an invalid interface, or an unavailable OS capture source.
        capture_batch(&self.capture_config_for(1))
            .context("preflight live network telemetry capture")?;
        Ok(())
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

    #[test]
    fn configured_feed_sha256_is_verified_before_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.json");
        let bytes = br#"{"source":"test","indicators":[]}"#;
        std::fs::write(&path, bytes).unwrap();
        let sensor = NetworkSensor::new(NetworkConfig {
            intel: Some(path),
            intel_sha256: Some(sha256_hex(bytes)),
            ..NetworkConfig::default()
        });

        assert!(sensor.load_feed().is_ok());
    }

    #[test]
    fn configured_feed_sha256_mismatch_is_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.json");
        std::fs::write(&path, r#"{"source":"test","indicators":[]}"#).unwrap();
        let sensor = NetworkSensor::new(NetworkConfig {
            intel: Some(path),
            intel_sha256: Some("0".repeat(64)),
            ..NetworkConfig::default()
        });

        let error = sensor.load_feed().expect_err("digest mismatch must fail");
        assert!(error.to_string().contains("SHA-256 mismatch"));
    }

    #[test]
    fn configured_feed_sha256_format_must_be_lowercase_hex() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("feed.json");
        std::fs::write(&path, r#"{"source":"test","indicators":[]}"#).unwrap();
        for invalid in ["abc".to_string(), "A".repeat(64), "z".repeat(64)] {
            let sensor = NetworkSensor::new(NetworkConfig {
                intel: Some(path.clone()),
                intel_sha256: Some(invalid),
                ..NetworkConfig::default()
            });
            let error = sensor.load_feed().expect_err("invalid digest must fail");
            assert!(error.to_string().contains("64 lowercase hexadecimal"));
        }
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
