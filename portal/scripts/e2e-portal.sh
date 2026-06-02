#!/usr/bin/env bash
# Start production portal for Playwright E2E (after `pnpm build`).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

export PORT="${PORT:-3000}"
export HOSTNAME="${HOSTNAME:-127.0.0.1}"
export NEXT_PUBLIC_FORM_BASE_URL="${NEXT_PUBLIC_FORM_BASE_URL:-http://127.0.0.1:8000}"

if [ -f .next/standalone/server.js ]; then
  exec node .next/standalone/server.js
fi

exec pnpm start --port "$PORT"
