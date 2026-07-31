//! Periodic non-secret health heartbeat for server-side gap detection.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agent_contract::{CollectorHealthStatus, Detection, Severity};

use super::{Sensor, SensorEvent};
use crate::config::HealthConfig;

pub(crate) struct HealthSensor {
    config: HealthConfig,
}

impl HealthSensor {
    pub(crate) fn new(config: HealthConfig) -> Self {
        Self { config }
    }

    fn event(&self, status: CollectorHealthStatus, gap: Option<u64>) -> Detection {
        let (severity, message) = match status {
            CollectorHealthStatus::Started => {
                (Severity::Info, Some("guard supervisor started".to_string()))
            }
            CollectorHealthStatus::Healthy => {
                (Severity::Info, Some("guard sensors reporting".to_string()))
            }
            CollectorHealthStatus::Gap => (
                Severity::High,
                Some("guard heartbeat scheduling gap observed".to_string()),
            ),
            CollectorHealthStatus::Degraded => {
                (Severity::High, Some("guard coverage degraded".to_string()))
            }
            CollectorHealthStatus::Stopped => {
                (Severity::High, Some("guard supervisor stopped".to_string()))
            }
        };
        Detection::CollectorHealth {
            severity,
            component: "agent-respond".to_string(),
            status,
            message,
            observed_gap_seconds: gap,
        }
    }
}

impl Sensor for HealthSensor {
    fn name(&self) -> &'static str {
        "health"
    }

    fn preflight(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.config.interval_secs > 0,
            "health.interval_secs must be greater than zero"
        );
        anyhow::ensure!(
            self.config.gap_threshold_secs >= self.config.interval_secs,
            "health.gap_threshold_secs must be at least health.interval_secs"
        );
        Ok(())
    }

    fn run(
        self: Box<Self>,
        tx: Sender<SensorEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> anyhow::Result<()> {
        if tx
            .send(self.event(CollectorHealthStatus::Started, None).into())
            .is_err()
        {
            return Ok(());
        }
        let interval = Duration::from_secs(self.config.interval_secs);
        let gap_threshold = Duration::from_secs(self.config.gap_threshold_secs);
        let mut last = Instant::now();
        while !shutdown.load(Ordering::Acquire) {
            sleep_interruptible(interval, &shutdown);
            if shutdown.load(Ordering::Acquire) {
                break;
            }
            let now = Instant::now();
            let elapsed = now.saturating_duration_since(last);
            let (status, gap) = if elapsed > gap_threshold {
                (CollectorHealthStatus::Gap, Some(elapsed.as_secs()))
            } else {
                (CollectorHealthStatus::Healthy, None)
            };
            if tx.send(self.event(status, gap).into()).is_err() {
                return Ok(());
            }
            last = now;
        }
        Ok(())
    }
}

fn sleep_interruptible(duration: Duration, shutdown: &AtomicBool) {
    let mut remaining = duration;
    while !remaining.is_zero() && !shutdown.load(Ordering::Acquire) {
        let slice = remaining.min(Duration::from_millis(100));
        std::thread::sleep(slice);
        remaining = remaining.saturating_sub(slice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn emits_started_and_periodic_healthy_events() {
        let sensor = HealthSensor::new(HealthConfig {
            enabled: true,
            interval_secs: 1,
            gap_threshold_secs: 2,
        });
        sensor.preflight().unwrap();
        let (tx, rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = Arc::clone(&shutdown);
        let handle = std::thread::spawn(move || Box::new(sensor).run(tx, worker_shutdown).unwrap());
        let first = rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let second = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        shutdown.store(true, Ordering::Release);
        handle.join().unwrap();
        assert!(matches!(
            first.detection,
            Detection::CollectorHealth {
                status: CollectorHealthStatus::Started,
                ..
            }
        ));
        assert!(matches!(
            second.detection,
            Detection::CollectorHealth {
                status: CollectorHealthStatus::Healthy,
                ..
            }
        ));
    }
}
