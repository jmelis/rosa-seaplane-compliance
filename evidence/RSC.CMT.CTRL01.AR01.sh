#!/usr/bin/env bash
set -euo pipefail

# Requires: gh (authenticated via GITHUB_TOKEN env var), jq, python3 (PyYAML).
# One evidence file per repository in config/scope.yaml, plus a manifest; see
# evidence/lib/collect.sh.

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
source "$(cd "$(dirname "$0")" && pwd)/lib/collect.sh"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set (gh CLI reads it for API auth)." >&2
  exit 1
fi

collect_repo() {
  local repo="$1" out="$2" branch raw protected=true errf
  branch="$(rsc_default_branch "${repo}")" || return 1
  errf="$(mktemp)"
  if ! raw="$(gh api "repos/${repo}/branches/${branch}/protection" 2>"${errf}")"; then
    if grep -q "Branch not protected" "${errf}"; then
      # An unprotected default branch is a finding, not a collection error.
      raw='{}'
      protected=false
    else
      cat "${errf}" >&2
      rm -f "${errf}"
      return 1
    fi
  fi
  rm -f "${errf}"
  jq --arg ar "${AR_ID}" --arg repo "${repo}" --arg branch "${branch}" --argjson protected "${protected}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '{assessment_requirement: $ar, generated_at: $generated_at, repository: $repo, branch: $branch, protected: $protected, protection: .}' \
    <<<"${raw}" >"${out}" || return 1
}

rsc_collect_all
