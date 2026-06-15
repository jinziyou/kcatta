#!/usr/bin/env bash
# Start production admin for Playwright E2E (after `pnpm build`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PORT="${PORT:-10063}"
export HOSTNAME="${HOSTNAME:-127.0.0.1}"
export NEXT_PUBLIC_ANALYZER_BASE_URL="${NEXT_PUBLIC_ANALYZER_BASE_URL:-http://127.0.0.1:10068}"
export ANALYZER_API_TOKEN="${E2E_API_TOKEN:-e2e-test-token}"

exec pnpm start --port "$PORT"
