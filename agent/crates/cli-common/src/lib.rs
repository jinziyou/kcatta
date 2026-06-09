//! agent-cli-common: shared CLI plumbing for the posture agent binaries.
//!
//! Pure, domain-free utilities hoisted out of the per-subcommand handlers the
//! old single `agent` binary duplicated. Depends on nothing internal, so it can
//! never participate in a dependency cycle.
//!
//! - [`output`] — write a serializable value as JSON to a file or stdout,
//!   honoring a `--pretty` flag (used by every binary's output path).
//! - [`http`] (feature `http`) — a blocking reqwest client builder + `get_text`
//!   helper for `posture-flow intel-sync` feed downloads. fusion *uploads* live
//!   in `agent-ingest`, not here.

pub mod output;

#[cfg(feature = "http")]
pub mod http;
