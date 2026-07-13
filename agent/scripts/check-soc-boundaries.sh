#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"

# These paths are the reusable Collect core. CLI/composition facades may call
# Detect for backward compatibility, but a Source/backend must only produce raw
# facts. Keeping the allow-list explicit makes a new source opt into this guard.
collect_core=(
  crates/collect/host/src/collector.rs
  crates/collect/host/src/collectors
  crates/collect/host/src/platform
  crates/collect/host/src/sources
  crates/collect/host/src/walk
  crates/collect/trace/src/capture
  crates/collect/trace/src/source.rs
  crates/collect/trace/src/sources
  crates/collect/trace/src/ebpf.rs
)

if rg -n 'agent_detect|agent_detect_malware|ThreatFeed|enrich_batch|run_detect' "${collect_core[@]}"; then
  echo "SOC boundary violation: reusable Collect code must not invoke Detect" >&2
  exit 1
fi

# Detection is an internal stage contract owned once by agent-contract. Detect
# and Respond may re-export it, but no crate may grow another definition that
# can drift.
detection_defs="$(rg -l 'pub enum Detection' crates --glob '*.rs' || true)"
if [[ "$detection_defs" != "crates/contract/src/detection.rs" ]]; then
  echo "SOC boundary violation: expected exactly one Detection definition in agent-contract" >&2
  if [[ -n "$detection_defs" ]]; then
    echo "$detection_defs" >&2
  fi
  exit 1
fi

rg -q 'pub use detection::Detection' crates/contract/src/lib.rs
rg -q 'pub use agent_contract::Detection' crates/detect/src/lib.rs
rg -q 'pub use agent_contract::Detection' crates/respond/src/lib.rs

# The long-running composition path must keep the Collect -> Detect hand-off
# visible instead of calling a collect-owned convenience wrapper.
rg -q 'agent_detect::host::detect' crates/agentd/src/run.rs
rg -q 'agent_detect::ioc::ThreatFeed' crates/agentd/src/run.rs
if rg -n 'agent_collect_(host::run_scan_with_detect|trace::enrich_batch)' crates/agentd/src; then
  echo "SOC boundary violation: agentd must orchestrate Collect and Detect explicitly" >&2
  exit 1
fi

echo "SOC stage boundaries OK"
