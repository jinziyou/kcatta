#!/usr/bin/env bash
# Apply GitHub branch protection rules for kcatta `main`.
#
# Prerequisites:
#   - gh CLI authenticated with admin on the repo
#   - Repository public OR GitHub Pro (private repos on Free cannot use branch protection)
#
# Usage:
#   ./scripts/setup-branch-protection.sh              # apply
#   ./scripts/setup-branch-protection.sh --dry-run    # print JSON only
#   REPO=owner/name BRANCH=main ./scripts/setup-branch-protection.sh
#
# See .github/BRANCH_PROTECTION.md for manual UI steps and verification.

set -euo pipefail

REPO="${REPO:-jinziyou/kcatta}"
BRANCH="${BRANCH:-main}"
DRY_RUN=0

if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI not found. Install: https://cli.github.com/" >&2
  exit 1
fi

if ! gh auth status >/dev/null 2>&1; then
  echo "error: gh not authenticated. Run: gh auth login" >&2
  exit 1
fi

VISIBILITY="$(gh api "repos/${REPO}" --jq '.visibility')"
PRIVATE="$(gh api "repos/${REPO}" --jq '.private')"
if [[ "${PRIVATE}" == "true" && "${VISIBILITY}" == "private" ]]; then
  echo "note: ${REPO} is private. Branch protection on private repos requires GitHub Pro"
  echo "      OR make the repository public before applying rules."
  echo "      See .github/BRANCH_PROTECTION.md"
fi

# Required job names (must match workflow job `name:` fields exactly).
# Excludes `dependency audit` — CI marks it continue-on-error (non-blocking).
read -r -d '' PAYLOAD <<'EOF' || true
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "agent (Rust)" },
      { "context": "agent (musl deploy build)" },
      { "context": "agent (musl deploy build, arm64)" },
      { "context": "analyzer (Python)" },
      { "context": "admin (Next.js)" },
      { "context": "e2e (admin + analyzer)" },
      { "context": "Signed-off-by" }
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true,
    "dismiss_stale_reviews": true,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_linear_history": false,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "block_creations": false,
  "required_conversation_resolution": true
}
EOF

echo "Repository : ${REPO}"
echo "Branch     : ${BRANCH}"
echo "Payload    :"
echo "${PAYLOAD}" | python3 -m json.tool

if [[ "${DRY_RUN}" -eq 1 ]]; then
  echo "dry-run: not calling GitHub API"
  exit 0
fi

echo "Applying branch protection..."
if gh api \
  --method PUT \
  "repos/${REPO}/branches/${BRANCH}/protection" \
  --input - <<<"${PAYLOAD}"; then
  echo "ok: branch protection applied to ${REPO}@${BRANCH}"
  echo "Verify: ./scripts/verify-branch-protection.sh"
else
  echo "error: failed to apply branch protection (see message above)." >&2
  echo "If the repo is private on GitHub Free, make it public or upgrade to Pro," >&2
  echo "or configure manually via Settings → Branches (see .github/BRANCH_PROTECTION.md)." >&2
  exit 1
fi
