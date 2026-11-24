# Shared by the evidence collectors; sourced, not executed (so the entrypoint,
# which runs every executable file directly under evidence/, skips it).
#
# A collector defines `collect_repo <owner/name> <out-file>` (write one JSON
# evidence document, exit non-zero on failure). It runs where `set -e` is
# ignored, so guard every command with `|| return 1` and then calls
# `rsc_collect_all`. That runs it for every repository in config/scope.yaml,
# writing:
#   $EVIDENCE_DIR/<AR>/<repo-name>.json  one evidence file per repository
#   $EVIDENCE_DIR/<AR>/manifest.json     per-target status for coverage
#
# One repository failing never stops the others: it is recorded in the
# manifest as `error` so that missing scope is visible and is never confused
# with a failing check. Needs AR_ID, EVIDENCE_DIR, jq and python3 (PyYAML).

RSC_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RSC_ROOT="$(cd "${RSC_LIB_DIR}/../.." && pwd)"

# Repositories to collect from: RSC_REPOS (space separated) overrides
# config/scope.yaml, for one-off runs and tests.
rsc_repos() {
  if [[ -n "${RSC_REPOS:-}" ]]; then
    tr ' ' '\n' <<<"${RSC_REPOS}"
  else
    python3 -c '
import sys, yaml
print("\n".join(yaml.safe_load(open(sys.argv[1]))["github-repositories"]))
' "${RSC_SCOPE_FILE:-${RSC_ROOT}/config/scope.yaml}"
  fi
}

# The repository's default branch, unless RSC_BASE_REF pins one.
rsc_default_branch() {
  if [[ -n "${RSC_BASE_REF:-}" ]]; then echo "${RSC_BASE_REF}"; else gh api "repos/$1" --jq .default_branch; fi
}

# Run a command, retrying a few times: GitHub's API returns transient 5xx
# (e.g. HTTP 502/504) on heavy GraphQL queries.
rsc_retry() {
  local attempt out rc errf
  errf="$(mktemp)"
  for attempt in 1 2 3; do
    if out="$("$@" 2>"${errf}")"; then rm -f "${errf}"; printf '%s' "${out}"; return 0; fi
    rc=$?
    grep -q -E 'HTTP 5[0-9][0-9]' "${errf}" || break
    sleep $((attempt * 2))
  done
  cat "${errf}" >&2
  rm -f "${errf}"
  return "${rc}"
}

rsc_collect_all() {
  local out_dir="${EVIDENCE_DIR}/${AR_ID}" repo name err targets="[]" ok=0 failed=0
  mkdir -p "${out_dir}"
  # Evidence from a previous run must not survive into this one.
  find "${out_dir}" -maxdepth 1 -name '*.json' -delete

  while IFS= read -r repo; do
    [[ -n "${repo}" ]] || continue
    name="${repo##*/}"
    if err="$(collect_repo "${repo}" "${out_dir}/${name}.json" 2>&1 >/dev/null)"; then
      targets="$(jq --arg n "${repo}" '. + [{name: $n, status: "collected"}]' <<<"${targets}")"
      ok=$((ok + 1))
    else
      rm -f "${out_dir}/${name}.json"
      # First line only: enough to tell auth from not-found, short enough to be safe.
      targets="$(jq --arg n "${repo}" --arg e "$(head -n 1 <<<"${err}" | cut -c1-200)" \
        '. + [{name: $n, status: "error", error: $e}]' <<<"${targets}")"
      failed=$((failed + 1))
      echo "WARN: ${AR_ID}: could not collect ${repo}: $(head -n 1 <<<"${err}")" >&2
    fi
  done < <(rsc_repos)

  # No assessment_requirement key: the Rego packages judge every JSON file under
  # input_path, and the manifest is not evidence about any repository.
  jq -n --arg ar "${AR_ID}" --arg env "${RSC_ENV:-integration}" \
    --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --argjson targets "${targets}" \
    '{ar: $ar, environment: $env, generated_at: $at, targets: $targets}' >"${out_dir}/manifest.json"

  echo "${AR_ID}: collected ${ok} repo(s), ${failed} error(s); manifest at ${out_dir}/manifest.json" >&2
  [[ "${ok}" -gt 0 ]] || { echo "ERROR: ${AR_ID}: no repository could be collected." >&2; return 1; }
}
