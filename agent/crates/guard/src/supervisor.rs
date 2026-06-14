//! Supervisor: spawn sensors, drain the pipeline, shut down gracefully.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

use crate::config::GuardConfig;
use crate::context::GuardContext;
use crate::pipeline::Pipeline;

/// Owns the daemon lifecycle: build sensors, run the detect→respond→report loop,
/// and flush + drain on shutdown.
pub struct Supervisor {
    config: GuardConfig,
    ctx: GuardContext,
    extra_sinks: Vec<Box<dyn crate::ReportSink>>,
}

impl Supervisor {
    /// Build a supervisor, resolving the run context (host id, agent version).
    ///
    /// `extra_sinks` are caller-injected report destinations (the standalone
    /// daemon passes none; `agentd guard --upload` injects a analyzer sink).
    pub fn new(config: GuardConfig, extra_sinks: Vec<Box<dyn crate::ReportSink>>) -> Self {
        let ctx = GuardContext::new(config.host_id.clone(), env!("CARGO_PKG_VERSION"));
        Self {
            config,
            ctx,
            extra_sinks,
        }
    }

    /// Run until SIGINT/SIGTERM (Linux). Blocks the calling thread.
    pub fn run(self) -> anyhow::Result<()> {
        run_impl(self.config, self.ctx, self.extra_sinks)
    }
}

#[cfg(target_os = "linux")]
fn run_impl(
    config: GuardConfig,
    ctx: GuardContext,
    extra_sinks: Vec<Box<dyn crate::ReportSink>>,
) -> anyhow::Result<()> {
    use crate::sensors::build_sensors;
    use nix::sys::signal::{SigSet, Signal};
    use nix::sys::signalfd::SignalFd;

    let sensors = build_sensors(&config);
    if sensors.is_empty() {
        anyhow::bail!("no sensors enabled — check config toggles and build features");
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel();

    // Block SIGINT/SIGTERM here so signalfd is the sole consumer; threads spawned
    // afterwards inherit the blocked mask.
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGINT);
    mask.add(Signal::SIGTERM);
    mask.thread_block()?;
    let sfd = SignalFd::new(&mask)?;

    let mut handles = Vec::new();
    for sensor in sensors {
        let tx = tx.clone();
        let shutdown = Arc::clone(&shutdown);
        let name = sensor.name();
        handles.push(
            std::thread::Builder::new()
                .name(format!("guard-{name}"))
                .spawn(move || sensor.run(tx, shutdown))?,
        );
        eprintln!("guard: started sensor {name}");
    }
    drop(tx); // only the sensor threads hold senders now

    // Signal thread flips the shutdown flag on the first SIGINT/SIGTERM.
    {
        let shutdown = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("guard-signal".into())
            .spawn(move || {
                if let Ok(Some(_)) = sfd.read_signal() {
                    eprintln!("guard: shutdown signal received");
                }
                shutdown.store(true, Ordering::SeqCst);
            })?;
    }

    eprintln!("guard: running in {:?} mode", config.mode);
    let flush_interval = Duration::from_secs(config.report.flush_secs.max(1));
    let mut pipeline = Pipeline::new(config, ctx, extra_sinks);

    loop {
        match rx.recv_timeout(flush_interval) {
            Ok(detection) => pipeline.handle(detection),
            Err(mpsc::RecvTimeoutError::Timeout) => pipeline.flush(),
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if shutdown.load(Ordering::SeqCst) {
            while let Ok(detection) = rx.try_recv() {
                pipeline.handle(detection);
            }
            break;
        }
    }

    pipeline.flush();
    eprintln!("guard: draining sensors...");
    for handle in handles {
        let _ = handle.join();
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_impl(
    _config: GuardConfig,
    _ctx: GuardContext,
    _extra_sinks: Vec<Box<dyn crate::ReportSink>>,
) -> anyhow::Result<()> {
    anyhow::bail!("agent-guard real-time protection is only supported on Linux")
}
