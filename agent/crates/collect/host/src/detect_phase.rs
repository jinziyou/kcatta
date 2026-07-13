//! Backward-compatible host-detection facade.
//!
//! Detection orchestration is owned by [`agent_detect::host`]. These aliases
//! preserve the original `agent_collect_host` API while new composition code
//! should call the detect crate directly.

pub use agent_detect::host::{
    detect as run_detect_at, DetectOptions as DetectOpts, MalwareDetectOptions as MalwareDetectOpts,
};
