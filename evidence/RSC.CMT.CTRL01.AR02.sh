#!/usr/bin/env bash
set -euo pipefail

# Requires: gh (authenticated via GITHUB_TOKEN env var; gh reads it
# automatically, no `gh auth login` needed), jq, python3 (PyYAML).
# One evidence file per repository in config/scope.yaml, plus a manifest; see
# evidence/lib/collect.sh.
#
# Orders by UPDATED_AT (GitHub has no MERGED_AT sort) and filters by
# mergedAt within the first 100 results. Add pagination if merge volume ever
# exceeds that per window.

AR_ID="$(basename "$0" .sh)"
WINDOW_DAYS="${RSC_WINDOW_DAYS:-30}"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
source "$(cd "$(dirname "$0")" && pwd)/lib/collect.sh"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set (gh CLI reads it for GraphQL auth)." >&2
  exit 1
fi

collect_repo() {
  local repo="$1" out="$2" owner="${1%%/*}" name="${1##*/}" base_ref raw
  base_ref="$(rsc_default_branch "${repo}")" || return 1
  raw="$(gh api graphql -f query='
    query($owner: String!, $name: String!, $baseRefName: String!) {
      repository(owner: $owner, name: $name) {
        pullRequests(states: MERGED, baseRefName: $baseRefName, first: 100,
                      orderBy: {field: UPDATED_AT, direction: DESC}) {
          nodes {
            number
            mergedAt
            author { login }
            reviewDecision
            mergedBy { login }
            commits(last: 1) {
              nodes { commit { statusCheckRollup { state } } }
            }
          }
        }
      }
    }' -f owner="${owner}" -f name="${name}" -f baseRefName="${base_ref}")" || return 1

  jq --arg ar "${AR_ID}" --arg repo "${repo}" \
    --arg base_ref "${base_ref}" \
    --argjson window_days "${WINDOW_DAYS}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    '
    # A GraphQL error (e.g. no access) still exits 0 from gh; treat it as failure.
    if .data.repository == null then error("no repository data returned") else . end
    | ($window_days * 86400) as $window_seconds
    | (now - $window_seconds | gmtime | strftime("%Y-%m-%dT%H:%M:%SZ")) as $cutoff
    | {
        assessment_requirement: $ar,
        generated_at: $generated_at,
        repository: $repo,
        base_ref: $base_ref,
        window_days: $window_days,
        pull_requests: [
          .data.repository.pullRequests.nodes[]
          | select(.mergedAt >= $cutoff)
          | {
              number: .number,
              merged_at: .mergedAt,
              author: .author.login,
              merged_by: .mergedBy.login,
              review_decision: (.reviewDecision // "NONE"),
              status_check_state: (.commits.nodes[0].commit.statusCheckRollup.state // "NONE")
            }
        ]
      }
    ' <<<"${raw}" >"${out}" || return 1
}

rsc_collect_all
