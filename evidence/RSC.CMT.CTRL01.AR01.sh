#!/usr/bin/env bash
set -euo pipefail

# Requires: gh (authenticated via GITHUB_TOKEN env var), jq, python3 (PyYAML).
# One evidence file per repository in config/scope.yaml, plus a manifest; see
# evidence/lib/collect.sh.
#
# Evidence per repository:
#   protection     GitHub branch protection, as returned by the API
#   approval_gate  the repository's approval requirement, normalized so the Rego
#                  needs no GitHub or Prow knowledge:
#                    mechanism         github-required-reviews | prow-tide | none
#                    requires_approval merges need an approval
#                    enforced_on_github GitHub itself stops a merge that skips
#                                      the gate (otherwise it can be bypassed)
#
# The team approves through Prow, not GitHub required reviews. Prow's merge bot
# (Tide) merges a PR only when it carries the `lgtm` and `approved` labels; that
# policy lives in openshift/release. GitHub does not know about it, so the gate
# is enforced on GitHub only if branch protection restricts who may merge or
# requires Tide's own `tide` status. Without either, anyone with write access
# can merge once CI is green, labels or not.

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
LIB_DIR="$(cd "$(dirname "$0")" && pwd)/lib"
source "${LIB_DIR}/collect.sh"

PROW_CONFIG_REPO="${RSC_PROW_CONFIG_REPO:-openshift/release}"
PROW_CONFIG_DIR="${RSC_PROW_CONFIG_DIR:-core-services/prow/02_config}"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set (gh CLI reads it for API auth)." >&2
  exit 1
fi

# Print a Prow config file from the config repo, or nothing if it does not
# exist. Any other failure (auth, rate limit, 5xx) is an error, never "no gate".
prow_config_file() {
  local path="$1" errf out
  errf="$(mktemp)"
  if out="$(rsc_retry gh api "repos/${PROW_CONFIG_REPO}/contents/${path}" -H 'Accept: application/vnd.github.raw' 2>"${errf}")"; then
    printf '%s' "${out}"
  elif grep -q "HTTP 404" "${errf}"; then
    :
  else
    cat "${errf}" >&2; rm -f "${errf}"; return 1
  fi
  rm -f "${errf}"
}

collect_repo() {
  local repo="$1" out="$2" owner="${1%%/*}" name="${1##*/}" branch raw protected=true errf
  local tmp files=() cfg gate
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

  # Tide's requirements: repo-level and org-level _prowconfig.yaml.
  tmp="$(mktemp -d)"
  for path in "${PROW_CONFIG_DIR}/${owner}/${name}/_prowconfig.yaml" "${PROW_CONFIG_DIR}/${owner}/_prowconfig.yaml"; do
    cfg="$(prow_config_file "${path}")" || { rm -rf "${tmp}"; return 1; }
    if [[ -n "${cfg}" ]]; then
      printf '%s\n' "${cfg}" >"${tmp}/${#files[@]}.yaml"
      files+=("${tmp}/${#files[@]}.yaml")
    fi
  done
  gate="$(python3 "${LIB_DIR}/prow_tide_gate.py" "${repo}" "${branch}" "${files[@]}")" || { rm -rf "${tmp}"; return 1; }
  rm -rf "${tmp}"

  jq --arg ar "${AR_ID}" --arg repo "${repo}" --arg branch "${branch}" --argjson protected "${protected}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson tide "${gate}" '
    . as $p
    | ($p.required_pull_request_reviews.required_approving_review_count // 0) as $reviews
    | (($p.required_status_checks.contexts // []) | index("tide") != null) as $tide_required
    | (($p.restrictions // null) != null) as $restricted
    | (if $reviews >= 1 then
         {mechanism: "github-required-reviews", requires_approval: true, enforced_on_github: true}
       elif $tide.queries > 0 then
         {mechanism: "prow-tide", requires_approval: $tide.requires_approval,
          enforced_on_github: ($restricted or $tide_required),
          queries_without_approval: $tide.queries_without_approval}
       else
         {mechanism: "none", requires_approval: false, enforced_on_github: false}
       end) as $gate
    | {assessment_requirement: $ar, generated_at: $generated_at, repository: $repo,
       branch: $branch, protected: $protected, protection: $p, approval_gate: $gate}
  ' <<<"${raw}" >"${out}" || return 1
}

rsc_collect_all
