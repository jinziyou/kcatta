#!/usr/bin/env bash
# Enforce the runtime integration boundary:
#
#   admin -> Form -> analyzer
#             |  \
#             |   -> agent (SSH/WinRM/local)
#             <- agent (dedicated HTTPS/mTLS ingest listener)
#
# No other component may establish a direct runtime integration.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

fail() {
  echo "component boundary violation: $*" >&2
  exit 1
}

for required in \
  form/src/kcatta_form/api/app.py \
  form/src/kcatta_form/api/scans.py \
  form/src/kcatta_form/api/credentials.py \
  form/src/kcatta_form/deploy/agent.py; do
  [[ -f "$required" ]] || fail "missing Form-owned file $required"
done

# Admin is a Form client. In particular, a legacy public analyzer URL must not
# silently bypass Form after an upgrade.
if rg -n 'NEXT_PUBLIC_ANALYZER_BASE_URL|ANALYZER_API_TOKEN|ANALYZER_API_TIMEOUT_MS|http://analyzer' \
  admin/src admin/Dockerfile admin/.env.example admin/scripts admin/playwright.config.ts; then
  fail "admin still contains a direct analyzer integration"
fi
rg -q 'FORM_BASE_URL' admin/src/lib/api.ts || fail "admin API client does not target Form"

# Analyzer is analysis-only. Transport, fleet state, and admin-facing control
# APIs belong to Form.
if find analyzer/src/analyzer/deploy -type f -name '*.py' -print -quit 2>/dev/null | rg -q .; then
  fail "analyzer still owns deploy adapters"
fi
[[ ! -e analyzer/src/analyzer/api/scans.py ]] || fail "analyzer still owns scan orchestration"
[[ ! -e analyzer/src/analyzer/api/credentials.py ]] || fail "analyzer still owns credentials API"
[[ ! -e analyzer/src/analyzer/schemas/scan.py ]] || fail "analyzer still owns control models"
if rg -n 'analyzer\.deploy|from \.deploy|from \.\.deploy|include_router\((scans|credentials)\.router|scan_(target|job)_store' \
  analyzer/src analyzer/tests; then
  fail "analyzer still imports or exposes Form responsibilities"
fi
if rg -n '(^|["[:space:]])(paramiko|pywinrm)([<=>~!"[:space:]]|$)|analyzer-scan' analyzer/pyproject.toml; then
  fail "analyzer still packages remote orchestration dependencies or CLI"
fi

# Agent uploads only to Form. The URL remains a runtime argument, but the
# authentication/retry/spool namespace must make the boundary unambiguous.
if rg -n 'ANALYZER_(API_TOKEN|INGEST_TOKEN|UPLOAD_[A-Z_]+|BASE_URL)' \
  agent/crates/agentd agent/examples; then
  fail "agentd still uses analyzer transport configuration"
fi
# The only permitted old Analyzer-namespaced setting is a read-only upgrade
# bridge for already-durable spool data. It must stay isolated to the spool
# implementation and its deprecation documentation, never become a transport.
if rg -n 'ANALYZER_SPOOL_[A-Z_]+' agent \
  --glob '!agent/crates/agentd/src/spool.rs' \
  --glob '!agent/crates/agentd/README.md'; then
  fail "legacy analyzer spool compatibility escaped its migration boundary"
fi
rg -q 'FORM_INGEST_TOKEN' agent/crates/agentd/src/ingest.rs \
  || fail "agentd does not use Form ingest authentication"
for setting in FORM_AGENT_CERT FORM_AGENT_KEY FORM_AGENT_CA; do
  rg -q "$setting" agent/crates/agentd/src/ingest.rs \
    || fail "agentd is missing mTLS setting $setting"
done

# The three credentials must not share a volume: otherwise compromising Admin
# would reveal the Agent ingest and Analyzer internal credentials despite the
# logical token scopes.
for volume in form-admin-secret form-ingest-secret analyzer-internal-secret; do
  rg -q "$volume" docker-compose.yml || fail "compose is missing isolated volume $volume"
done
if rg -q 'kcatta-secrets' docker-compose.yml; then
  fail "compose still shares all trust-domain tokens in one volume"
fi

# Validate the rendered topology as well as raw YAML names. This catches an
# accidental extra network, published Analyzer port, or secret mount that a
# simple text grep cannot distinguish.
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  docker compose config --format json | python3 scripts/check-compose-boundaries.py
fi

# Form owns all three trust domains; never forward the caller's credential to
# Analyzer.
for token in FORM_API_TOKEN FORM_INGEST_TOKEN ANALYZER_INTERNAL_TOKEN; do
  rg -q "$token" form/src form/README.md \
    || fail "Form contract is missing $token"
done

echo "component boundaries OK"
