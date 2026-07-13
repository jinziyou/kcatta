#!/usr/bin/env bash
# Start analyzer-api for Playwright E2E (invoked by playwright.config.ts webServer).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA_DIR="${E2E_ANALYZER_DATA_DIR:-/tmp/kcatta-e2e-analyzer}"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

export ANALYZER_DATA_DIR="$DATA_DIR"
export ANALYZER_STORAGE="${ANALYZER_STORAGE:-jsonl}"
export ANALYZER_INTERNAL_TOKEN="${ANALYZER_INTERNAL_TOKEN:-${E2E_ANALYZER_TOKEN:-e2e-analyzer-token}}"

cd "$ROOT/analyzer"
if [ ! -x .venv/bin/analyzer-api ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -e .
fi

exec .venv/bin/analyzer-api --host 127.0.0.1 --port 10068
