#!/usr/bin/env bash
# Start fusion-api for Playwright E2E (invoked by playwright.config.ts webServer).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA_DIR="${E2E_FUSION_DATA_DIR:-/tmp/kcatta-e2e-fusion}"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

export FUSION_DATA_DIR="$DATA_DIR"
export FUSION_STORAGE="${FUSION_STORAGE:-jsonl}"
export FUSION_API_TOKEN="${E2E_API_TOKEN:-e2e-test-token}"

cd "$ROOT/fusion"
if [ ! -x .venv/bin/fusion-api ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -e .
fi

exec .venv/bin/fusion-api --host 127.0.0.1 --port 8000
