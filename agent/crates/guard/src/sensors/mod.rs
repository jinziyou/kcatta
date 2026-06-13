//! Sensors: long-running detection sources, one per OS thread.
//!
//! Each sensor pushes [`Detection`]s into the pipeline channel until the shared
//! `shutdown` flag flips. Sensor backends are Linux-only (nix syscalls) and
//! feature-gated; on other platforms (or with features off) [`build_sensors`]
//! simply returns an empty set and the supervisor refuses to run.

use std::sync::atomic::AtomicBool;
use std::sync::mpsc::Sender;
use std::sync::Arc;

use crate::config::GuardConfig;
use crate::event::Detection;

#[cfg(all(target_os = "linux", feature = "behavior"))]
mod behavior;
#[cfg(all(target_os = "linux", feature = "fim"))]
mod fim;
#[cfg(all(target_os = "linux", feature = "network"))]
mod network;
#[cfg(all(target_os = "linux", feature = "onaccess"))]
mod onaccess;

/// A long-running detection source.
pub trait Sensor: Send {
    /// Stable sensor name (for logs).
    fn name(&self) -> &'static str;
    /// Run until `shutdown` is observed `true`, pushing detections to `tx`.
    fn run(self: Box<Self>, tx: Sender<Detection>, shutdown: Arc<AtomicBool>);
}

/// Assemble the enabled-and-compiled sensors for `config`.
#[allow(unused_mut, unused_variables)]
pub fn build_sensors(config: &GuardConfig) -> Vec<Box<dyn Sensor>> {
    let mut sensors: Vec<Box<dyn Sensor>> = Vec::new();

    #[cfg(all(target_os = "linux", feature = "fim"))]
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
        sensors.push(Box::new(onaccess::OnAccessSensor::new(
            config.onaccess.clone(),
            config.mode,
        )));
    }
    #[cfg(all(target_os = "linux", feature = "network"))]
    if config.network.enabled {
        sensors.push(Box::new(network::NetworkSensor::new(
            config.network.clone(),
        )));
    }

    sensors
}
