//! Supervisor: spawn sensors, drain the pipeline, shut down gracefully.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
    /// daemon passes none; `agentd respond --upload` injects a Form sink).
    pub fn new(config: GuardConfig, extra_sinks: Vec<Box<dyn crate::ReportSink>>) -> Self {
        let ctx = GuardContext::new(config.host_id.clone(), env!("CARGO_PKG_VERSION"));
        Self {
            config,
            ctx,
            extra_sinks,
        }
    }

    /// Run until a shutdown signal (SIGINT/SIGTERM on Linux, Ctrl-C / console
    /// close on Windows). Blocks the calling thread.
    pub fn run(self) -> anyhow::Result<()> {
        let shutdown = Arc::new(AtomicBool::new(false));
        // Wire the OS shutdown trigger BEFORE spawning sensors (Linux blocks the
        // signal mask on this thread so the sensor threads inherit it).
        install_shutdown(&shutdown)?;
        run_loop(self.config, self.ctx, self.extra_sinks, shutdown)
    }

    /// Run under a caller-owned shutdown token.
    ///
    /// Composition runtimes such as `agentd` use this entry point so Collect,
    /// Detect, and Respond share one lifecycle and drain together. The caller is
    /// responsible for flipping `shutdown`; no second signal handler is
    /// installed here.
    pub fn run_with_shutdown(self, shutdown: Arc<AtomicBool>) -> anyhow::Result<()> {
        run_loop(self.config, self.ctx, self.extra_sinks, shutdown)
    }
}

/// Flip `shutdown` when the OS asks the process to stop. Must run before the
/// sensor threads spawn. Platform-specific; the loop below is platform-neutral.
#[cfg(target_os = "linux")]
fn install_shutdown(shutdown: &Arc<AtomicBool>) -> anyhow::Result<()> {
    use nix::sys::signal::{SigSet, Signal};
    use nix::sys::signalfd::SignalFd;

    // Block SIGINT/SIGTERM here so signalfd is the sole consumer; threads spawned
    // afterwards inherit the blocked mask.
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGINT);
    mask.add(Signal::SIGTERM);
    mask.thread_block()?;
    let sfd = SignalFd::new(&mask)?;

    let shutdown = Arc::clone(shutdown);
    std::thread::Builder::new()
        .name("guard-signal".into())
        .spawn(move || {
            if let Ok(Some(_)) = sfd.read_signal() {
                eprintln!("guard: shutdown signal received");
            }
            shutdown.store(true, Ordering::SeqCst);
        })?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_shutdown(shutdown: &Arc<AtomicBool>) -> anyhow::Result<()> {
    // Ctrl-C / console-close → flip the same shutdown flag (SetConsoleCtrlHandler
    // under the hood). `ctrlc` is a safe wrapper, so no raw FFI callback is needed
    // and agent-respond stays `unsafe_code = "deny"`-clean.
    let shutdown = Arc::clone(shutdown);
    ctrlc::set_handler(move || {
        eprintln!("guard: shutdown signal received");
        shutdown.store(true, Ordering::SeqCst);
    })?;
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn install_shutdown(_shutdown: &Arc<AtomicBool>) -> anyhow::Result<()> {
    anyhow::bail!("agent-respond real-time protection is only supported on Linux and Windows")
}

/// The platform-neutral detect → respond → report loop: spawn sensors, drain the
/// pipeline until shutdown (or a sensor dies), then flush + join.
fn run_loop(
    config: GuardConfig,
    ctx: GuardContext,
    extra_sinks: Vec<Box<dyn crate::ReportSink>>,
    shutdown: Arc<AtomicBool>,
) -> anyhow::Result<()> {
    use crate::sensors::build_sensors;

    let sensors = build_sensors(&config)?;
    if sensors.is_empty() {
        anyhow::bail!("no sensors enabled — check config toggles and build features");
    }

    let (tx, rx) = mpsc::channel();

    let mut handles: Vec<(&'static str, std::thread::JoinHandle<anyhow::Result<()>>)> = Vec::new();
    for sensor in sensors {
        let tx = tx.clone();
        let shutdown = Arc::clone(&shutdown);
        let name = sensor.name();
        let handle = std::thread::Builder::new()
            .name(format!("guard-{name}"))
            .spawn(move || sensor.run(tx, shutdown))?;
        handles.push((name, handle));
        eprintln!("guard: started sensor {name}");
    }
    drop(tx); // only the sensor threads hold senders now

    eprintln!("guard: running in {:?} mode", config.mode);
    let flush_interval = Duration::from_secs(config.report.flush_secs.max(1));
    let receive_poll = flush_interval.min(Duration::from_millis(500));
    let mut next_flush = Instant::now() + flush_interval;
    // Active-response state is never touched in monitor/detect-only mode.
    #[cfg(target_os = "linux")]
    let manage_netblock = config.mode == crate::Mode::Enforce && config.response.allow_netblock;
    // Clear stale state before a new enforce lifecycle begins.
    #[cfg(target_os = "linux")]
    if manage_netblock {
        crate::respond::netblock_reset();
    }
    let mut pipeline = Pipeline::new(config, ctx, extra_sinks);

    let mut sensor_failure = false;
    loop {
        match rx.recv_timeout(receive_poll) {
            Ok(event) => pipeline.handle_sensor_event(event),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !shutdown.load(Ordering::SeqCst) {
                    eprintln!(
                        "guard: all sensor channels disconnected before shutdown; stopping for restart"
                    );
                    sensor_failure = true;
                    shutdown.store(true, Ordering::SeqCst);
                }
                break;
            }
        }
        if Instant::now() >= next_flush {
            pipeline.flush();
            next_flush = Instant::now() + flush_interval;
        }
        if shutdown.load(Ordering::SeqCst) {
            while let Ok(event) = rx.try_recv() {
                pipeline.handle_sensor_event(event);
            }
            break;
        }
        // Watchdog: a sensor thread returning before shutdown means it stopped
        // detecting (e.g. an inotify error). Do not silently run on with a dead
        // sensor — shut down and exit non-zero so a service manager (systemd
        // Restart=on-failure / Windows SCM) restarts the daemon instead of leaving
        // the host believing a protection is active when it is not.
        if let Some((name, _)) = handles.iter().find(|(_, h)| h.is_finished()) {
            eprintln!("guard: sensor {name} exited unexpectedly; stopping for restart");
            sensor_failure = true;
            shutdown.store(true, Ordering::SeqCst);
            while let Ok(event) = rx.try_recv() {
                pipeline.handle_sensor_event(event);
            }
            break;
        }
    }

    // Join producers before the final drain. A sensor can enqueue one last
    // event after the loop's earlier `try_recv` but before it observes the
    // shutdown flag; draining only before join would silently lose that event.
    eprintln!("guard: stopping sensors...");
    for (name, handle) in handles {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                eprintln!("guard: sensor {name} error: {e}");
                sensor_failure = true;
            }
            Err(_) => {
                eprintln!("guard: sensor {name} panicked");
                sensor_failure = true;
            }
        }
    }
    while let Ok(event) = rx.try_recv() {
        pipeline.handle_sensor_event(event);
    }
    let report_result = pipeline.finish();
    #[cfg(target_os = "linux")]
    if manage_netblock {
        crate::respond::netblock_cleanup();
    }
    if sensor_failure {
        if let Err(error) = report_result {
            eprintln!("guard: final report flush also failed: {error}");
        }
        anyhow::bail!(
            "guard: a sensor failed; exiting non-zero so the service manager can restart"
        );
    }
    report_result
}
