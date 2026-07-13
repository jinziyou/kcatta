//! Sensors: long-running detection sources, one per OS thread.
//!
//! Each sensor pushes [`Detection`]s into the pipeline channel until the shared
//! `shutdown` flag flips. Sensor backends are Linux-only (nix syscalls) and
//! feature-gated; on other platforms (or with features off) [`build_sensors`]
//! simply returns an empty set and the supervisor refuses to run.

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use agent_contract::{ActionTaken, Outcome};

use crate::config::GuardConfig;
use crate::Detection;

#[cfg(all(target_os = "linux", feature = "behavior"))]
mod behavior;
// FIM runs on Linux (inotify) and Windows (ReadDirectoryChangesW); the per-OS
// backend lives inside `fim.rs`, cfg-split. Other sensors remain Linux-only.
#[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "fim"))]
mod fim;
#[cfg(all(target_os = "linux", feature = "network"))]
mod network;
#[cfg(all(target_os = "linux", feature = "onaccess"))]
mod onaccess;

/// One sensor emission. Most sensors only carry a detection; a sensor that had
/// to execute a response synchronously (fanotify permission events) can attach
/// the exact result so the pipeline reports it without applying another action.
#[derive(Debug)]
pub(crate) struct SensorEvent {
    pub(crate) detection: Detection,
    pub(crate) pre_applied: Option<(ActionTaken, Outcome)>,
}

impl SensorEvent {
    #[cfg(any(
        feature = "onaccess",
        all(test, unix, not(any(target_os = "redox", target_os = "solaris")))
    ))]
    pub(crate) fn pre_applied(
        detection: Detection,
        action_taken: ActionTaken,
        outcome: Outcome,
    ) -> Self {
        Self {
            detection,
            pre_applied: Some((action_taken, outcome)),
        }
    }
}

impl From<Detection> for SensorEvent {
    fn from(detection: Detection) -> Self {
        Self {
            detection,
            pre_applied: None,
        }
    }
}

/// A long-running detection source.
pub trait Sensor: Send {
    /// Stable sensor name (for logs).
    fn name(&self) -> &'static str;
    /// Run until `shutdown` is observed `true`, pushing detections to `tx`.
    ///
    /// Returns `Err` if the sensor stops because of a failure (e.g. an inotify
    /// read error) rather than a clean shutdown. The supervisor watches for a
    /// sensor returning before `shutdown` is set and treats it as a fatal
    /// degradation (the protection that sensor provided is now off) — exiting
    /// non-zero so a service manager can restart, instead of silently running on
    /// with a dead sensor.
    fn run(
        self: Box<Self>,
        tx: Sender<SensorEvent>,
        shutdown: Arc<AtomicBool>,
    ) -> anyhow::Result<()>;
}

/// Assemble the enabled-and-compiled sensors for `config`.
///
/// An explicitly enabled sensor that is unavailable in this build/platform is
/// a configuration error; silently omitting it would advertise protection the
/// process is not providing.
#[allow(unused_mut)]
pub fn build_sensors(config: &GuardConfig) -> anyhow::Result<Vec<Box<dyn Sensor>>> {
    ensure_available(
        config.fim.enabled,
        cfg!(feature = "fim") && cfg!(any(target_os = "linux", target_os = "windows")),
        "fim",
    )?;
    ensure_available(
        config.behavior.enabled,
        cfg!(feature = "behavior") && cfg!(target_os = "linux"),
        "behavior",
    )?;
    ensure_available(
        config.onaccess.enabled,
        cfg!(feature = "onaccess") && cfg!(target_os = "linux"),
        "onaccess",
    )?;
    ensure_available(
        config.network.enabled,
        cfg!(feature = "network") && cfg!(target_os = "linux"),
        "network",
    )?;

    let mut sensors: Vec<Box<dyn Sensor>> = Vec::new();

    #[cfg(all(any(target_os = "linux", target_os = "windows"), feature = "fim"))]
    if config.fim.enabled {
        sensors.push(Box::new(fim::FimSensor::new(config.fim.paths.clone())));
    }
    #[cfg(all(target_os = "linux", feature = "behavior"))]
    if config.behavior.enabled {
        sensors.push(Box::new(behavior::BehaviorSensor::new(
            config.behavior.poll_interval_ms,
        )));
    }
    #[cfg(all(target_os = "linux", feature = "onaccess"))]
    if config.onaccess.enabled {
        sensors.push(Box::new(onaccess::OnAccessSensor::new(config.clone())));
    }
    #[cfg(all(target_os = "linux", feature = "network"))]
    if config.network.enabled {
        sensors.push(Box::new(network::NetworkSensor::new(
            config.network.clone(),
        )));
    }

    Ok(sensors)
}

fn ensure_available(enabled: bool, available: bool, name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !enabled || available,
        "sensor '{name}' is enabled in config but unavailable in this build/platform"
    );
    Ok(())
}
