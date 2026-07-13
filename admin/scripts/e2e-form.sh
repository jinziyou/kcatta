#!/usr/bin/env bash
# Start Form for Playwright E2E (invoked by playwright.config.ts webServer).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DATA_DIR="${E2E_FORM_DATA_DIR:-/tmp/kcatta-e2e-form}"
rm -rf "$DATA_DIR"
mkdir -p "$DATA_DIR"

export FORM_DATA_DIR="$DATA_DIR"
export FORM_ANALYZER_BASE_URL="${FORM_ANALYZER_BASE_URL:-http://127.0.0.1:10068}"
export FORM_API_TOKEN="${FORM_API_TOKEN:-${E2E_API_TOKEN:-e2e-control-token}}"
export FORM_INGEST_TOKEN="${FORM_INGEST_TOKEN:-${E2E_INGEST_TOKEN:-e2e-ingest-token}}"
export ANALYZER_INTERNAL_TOKEN="${ANALYZER_INTERNAL_TOKEN:-${E2E_ANALYZER_TOKEN:-e2e-analyzer-token}}"

cd "$ROOT/form"
if [ ! -x .venv/bin/form-api ]; then
  python3 -m venv .venv
  # Form owns orchestration but reuses analyzer's internal schema/storage
  # package. Install both into Form's isolated E2E environment.
  .venv/bin/pip install -q -e "$ROOT/analyzer" -e .
fi

exec .venv/bin/form-api --host 127.0.0.1 --port 10067
