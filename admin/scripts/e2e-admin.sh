#!/usr/bin/env bash
# Start production admin for Playwright E2E (after `pnpm build`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PORT="${PORT:-10063}"
export HOSTNAME="${HOSTNAME:-127.0.0.1}"
export FORM_BASE_URL="${FORM_BASE_URL:-http://127.0.0.1:10067}"
export FORM_API_TOKEN="${FORM_API_TOKEN:-${E2E_API_TOKEN:-e2e-control-token}}"

exec pnpm start --port "$PORT"
