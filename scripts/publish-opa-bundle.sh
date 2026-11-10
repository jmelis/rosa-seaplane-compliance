#!/usr/bin/env bash
set -euo pipefail

# Assembles every domain's Rego (opa/*/policy/*.rego) plus a single merged
# complytime-mapping.json into one project-wide conftest OCI bundle and pushes
# it. One bundle per target is what complyctl's opa provider expects
# (opa_bundle_ref is a per-target variable).
#
# Staged flat (no "policy/" subdirectory): conftest's OCI bundle format
# preserves whatever directory structure sits under --policy, so pushing a
# "policy/" subfolder makes `conftest pull --policy <dir>` land content at
# <dir>/policy/... instead of <dir>/... directly — breaking opa-provider's
# expectation that complytime-mapping.json sits directly in the pulled
# directory (cmd/opa-provider/generate/mapping.go's LoadMapping).
#
# Requires: conftest, jq. Log in first if the target registry needs auth.
#
# An "http://" prefix on the ref opts into plain-HTTP (for a local/insecure
# registry — see docs/credentials.md), mirroring the same convention
# complyctl itself uses for policies[].url.
# Usage: ./scripts/publish-opa-bundle.sh <oci-ref>

INPUT_REF="${1:?usage: $0 <oci-ref>}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REF="${INPUT_REF}"
CONFTEST_FLAGS=()
if [[ "${REF}" == http://* ]]; then
  REF="${REF#http://}"
  CONFTEST_FLAGS+=(--tls=false)
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "${STAGE}"' EXIT

shopt -s nullglob

# Collect every domain's Rego (excluding unit tests), failing loudly on a
# filename collision.
for rego in "${REPO_ROOT}"/opa/*/policy/*.rego; do
  base="$(basename "${rego}")"
  case "${base}" in *_test.rego) continue ;; esac
  dest="${STAGE}/${base}"
  if [[ -e "${dest}" ]]; then
    echo "ERROR: duplicate Rego filename ${base} across domains; rename one." >&2
    exit 1
  fi
  cp "${rego}" "${dest}"
done

# Merge every domain's complytime-mapping.json into one (concatenate entries).
mappings=( "${REPO_ROOT}"/opa/*/policy/complytime-mapping.json )
if (( ${#mappings[@]} == 0 )); then
  echo "ERROR: no opa/*/policy/complytime-mapping.json found." >&2
  exit 1
fi
jq -s '{version: "1", mappings: (map(.mappings) | add)}' \
  "${mappings[@]}" >"${STAGE}/complytime-mapping.json"

cd "${STAGE}"
conftest push "${CONFTEST_FLAGS[@]}" --policy . "${REF}"

echo "Published ${INPUT_REF}"
echo "Update .complytime/complytime.yaml's opa_bundle_ref target variable to match if this differs from what's there."
