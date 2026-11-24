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
AUTOMATION_CONFIG="${RSC_AUTOMATION_CONFIG:-${RSC_ROOT}/config/automation.yaml}"

if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "ERROR: GITHUB_TOKEN must be set (gh CLI reads it for GraphQL auth)." >&2
  exit 1
fi

# Prow (OpenShift CI) approves through `/lgtm` (a reviewer) and `/approve` (an
# OWNERS approver) commands that set the `lgtm` and `approved` labels, so
# GitHub's reviewDecision is mostly empty. Prow also reads commands in review
# bodies, and (review_acts_as_lgtm) treats an approving review as /lgtm. What
# the team's merge gate (Tide) requires is both labels, so a Prow approval
# counts here only when:
#   - both the `lgtm` and `approved` labels are present, AND
#   - a non-author, non-bot account has an unretracted `/lgtm` or `/approve`
#     in a comment or review body made BEFORE the merge (a command on a closed
#     PR does nothing), so the label is attributable to a person.
# A bot that applies the labels to its own PR leaves no such command and so has
# no approver; author_is_bot says so. Automation identities (config/automation.yaml)
# are never counted as approvers of other people's PRs.
#
# automated_change records the facts the policy needs to decide whether a PR may
# count as approved by automation (see config/automation.yaml): the author is
# allowlisted, the repo's Tide config has a dedicated query for that author, the
# approval labels are present, the merge bot merged it, and every commit is
# authored by that identity with a valid signature. The collector only reports the
# facts; the Rego decides. `summary` counts how many PRs satisfy all five, so
# reports can say how many merges relied on the exemption.
# GitHub approving reviews by non-authors count directly.
#
# Normalized per PR: approved_by (non-author, non-bot accounts), approval_sources
# and author_is_bot, so the Rego never needs to know about GitHub or Prow.

collect_repo() {
  local repo="$1" out="$2" owner="${1%%/*}" name="${1##*/}" base_ref cutoff after="" page raw="[]" pages=0 tide automation
  base_ref="$(rsc_default_branch "${repo}")" || return 1
  tide="$(rsc_tide_gate "${repo}" "${base_ref}")" || return 1
  automation="$(python3 "${RSC_LIB_DIR}/automation_config.py" "${AUTOMATION_CONFIG}")" || return 1
  cutoff="$(jq -nr --argjson d "${WINDOW_DAYS}" 'now - ($d * 86400) | gmtime | strftime("%Y-%m-%dT%H:%M:%SZ")')"

  # Pages are ordered by UPDATED_AT (GitHub has no MERGED_AT sort). Keep going
  # until a page reaches PRs last updated before the window, so a busy repo is
  # not silently truncated. A PR merged inside the window was updated inside it.
  while :; do
    local args=(-f owner="${owner}" -f name="${name}" -f baseRefName="${base_ref}")
    [[ -n "${after}" ]] && args+=(-f after="${after}")
    page="$(rsc_retry gh api graphql -f query='
      query($owner: String!, $name: String!, $baseRefName: String!, $after: String) {
        repository(owner: $owner, name: $name) {
          pullRequests(states: MERGED, baseRefName: $baseRefName, first: 50, after: $after,
                        orderBy: {field: UPDATED_AT, direction: DESC}) {
            pageInfo { hasNextPage endCursor }
            nodes {
              number
              mergedAt
              updatedAt
              author { login __typename }
              mergedBy { login }
              labels(first: 50) { nodes { name } }
              latestOpinionatedReviews(first: 50) { nodes { state author { login __typename } } }
              comments(first: 100) { pageInfo { hasNextPage } nodes { author { login __typename } body createdAt } }
              reviews(first: 50) { pageInfo { hasNextPage } nodes { author { login __typename } body submittedAt } }
              commits(last: 1) { nodes { commit { statusCheckRollup { state } } } }
              allCommits: commits(first: 100) { totalCount nodes { commit { author { user { login } } signature { isValid } } } }
            }
          }
        }
      }' "${args[@]}")" || return 1
    # A GraphQL error (e.g. no access) can still exit 0 from gh; treat it as failure.
    jq -e '.data.repository != null and (.errors | not)' <<<"${page}" >/dev/null || return 1
    raw="$(jq -s '.[0] + .[1].data.repository.pullRequests.nodes' <(echo "${raw}") <(echo "${page}"))" || return 1
    pages=$((pages + 1))
    jq -e '.data.repository.pullRequests.pageInfo.hasNextPage' <<<"${page}" >/dev/null || break
    jq -e --arg c "${cutoff}" '[.data.repository.pullRequests.nodes[].updatedAt] | (length > 0 and min >= $c)' <<<"${page}" >/dev/null || break
    [[ "${pages}" -lt 20 ]] || { echo "more than 20 pages of merged PRs" >&2; return 1; }
    after="$(jq -r '.data.repository.pullRequests.pageInfo.endCursor' <<<"${page}")"
  done

  jq --arg ar "${AR_ID}" --arg repo "${repo}" --arg base_ref "${base_ref}" \
    --argjson window_days "${WINDOW_DAYS}" --arg cutoff "${cutoff}" \
    --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --argjson tide "${tide}" --argjson automation "${automation}" '
    def base: sub("\\[bot\\]$"; "");
    # A person: not a GitHub Bot and not one of our allowlisted automation identities.
    def human($a): $a != null and $a.login != null and ($a.__typename != "Bot")
      and (($automation.change_authors | index($a.login | base)) == null);
    # Final state per commenter and command: the last of /x or /x cancel wins.
    def commanders($author; $merged_at):
      [ ((.comments.nodes | map({author, body, at: .createdAt}))
         + (.reviews.nodes | map({author, body, at: .submittedAt})))
        | sort_by(.at)[] | select(human(.author) and .at <= $merged_at)
        | .author.login as $login
        | .body | split("\n")[] | gsub("\r"; "")
        | capture("^/(?<cmd>lgtm|approve)(?<cancel> cancel)?[ \t]*$") | {login: $login, cmd, cancel: (.cancel != null and .cancel != "")} ]
      | group_by([.login, .cmd]) | map(last | select(.cancel | not) | .login)
      | unique | map(select(. != $author));
    {
      assessment_requirement: $ar,
      generated_at: $generated_at,
      repository: $repo,
      base_ref: $base_ref,
      window_days: $window_days,
      summary: null,
      pull_requests: [
        .[]
        | select(.mergedAt >= $cutoff)
        | (.author.login) as $author
        | ([.labels.nodes[].name]) as $labels
        | ([.latestOpinionatedReviews.nodes[]
            | select(.state == "APPROVED" and human(.author) and .author.login != $author)
            | .author.login]) as $reviewers
        | (($labels | index("lgtm")) != null and ($labels | index("approved")) != null) as $labelled
        | (.allCommits.nodes) as $commits
        | {
            author_allowlisted: (($automation.change_authors | index($author | base)) != null),
            gate_defined: (($tide.author_queries | index($author | base)) != null),
            gate_labels_present: $labelled,
            merged_by_merge_automation: ((.mergedBy.login // "" | base) as $m | ($automation.merge_automation | index($m)) != null),
            all_commits_by_author: (($commits | length) > 0 and .allCommits.totalCount == ($commits | length)
              and all($commits[]; (.commit.author.user.login // "" | base) == ($author | base) and .commit.signature.isValid == true))
          } as $auto
        | (if ($labels | index("lgtm")) != null and ($labels | index("approved")) != null
           then commanders($author; .mergedAt) else [] end) as $prow
        | {
            number: .number,
            merged_at: .mergedAt,
            author: $author,
            author_is_bot: (.author.__typename == "Bot"),
            automated_change: $auto,
            merged_by: .mergedBy.login,
            approved_by: ($reviewers + $prow | unique),
            approval_sources: ([(if ($reviewers | length) > 0 then "github-review" else empty end),
                                (if ($prow | length) > 0 then "prow" else empty end)]),
            history_truncated: (.comments.pageInfo.hasNextPage or .reviews.pageInfo.hasNextPage),
            status_check_state: (.commits.nodes[0].commit.statusCheckRollup.state // "NONE")
          }
      ]
    }
    | .summary = {merged: (.pull_requests | length),
                  automation_exempt: ([.pull_requests[] | select(.automated_change | all(.[]; . == true))] | length),
                  exemption_approved: $automation.exemption_approved}
  ' <<<"${raw}" >"${out}" || return 1
}

rsc_collect_all
