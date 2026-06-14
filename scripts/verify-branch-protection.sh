#!/usr/bin/env bash
# Print current branch protection status for kcatta `main`.

set -euo pipefail

REPO="${REPO:-jinziyou/kcatta}"
BRANCH="${BRANCH:-main}"

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI not found" >&2
  exit 1
fi

echo "=== ${REPO} @ ${BRANCH} ==="
gh api "repos/${REPO}" --jq '"visibility=\(.visibility) private=\(.private) default_branch=\(.default_branch)"'

echo
echo "--- branch protection ---"
if ! gh api "repos/${REPO}/branches/${BRANCH}/protection" 2>/dev/null | python3 -m json.tool; then
  echo "(not configured or not available — private repos on Free need Pro or public visibility)"
  exit 1
fi
