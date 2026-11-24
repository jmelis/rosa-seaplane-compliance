#!/usr/bin/env bash
set -euo pipefail

# Policy test suite, run through a pinned conftest container so the repo needs
# no local conftest install. Requires podman or docker.
#   - Rego unit tests (conftest verify) for every assessment requirement.
#   - Pass/fail fixtures run through the real policy (conftest test), with
#     every package evaluating every fixture as the opa provider does.
#
# Overrides: CONFTEST_IMAGE pins the image; CONFTEST_BIN=conftest uses a local
# binary instead of the container.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

OPA_POLICY="opa/change-management/policy"
# Match the conftest version baked into containers/complyctl/Containerfile.
CONFTEST_IMAGE="${CONFTEST_IMAGE:-docker.io/openpolicyagent/conftest:v0.68.2}"

if [[ -n "${CONFTEST_BIN:-}" ]]; then
  conftest() { "${CONFTEST_BIN}" "$@"; }
else
  runtime=""
  for r in podman docker; do
    if command -v "${r}" >/dev/null 2>&1; then runtime="${r}"; break; fi
  done
  if [[ -z "${runtime}" ]]; then
    echo "ERROR: need podman or docker (or set CONFTEST_BIN to a local conftest)." >&2
    exit 1
  fi
  conftest() { "${runtime}" run --rm -v "${ROOT}:/project:ro" -w /project "${CONFTEST_IMAGE}" "$@"; }
fi

echo "== Rego unit tests =="
conftest verify -p "${OPA_POLICY}"

echo
for AR in RSC.CMT.CTRL01.AR01 RSC.CMT.CTRL01.AR02; do
  echo "== ${AR} fixture (compliant) must pass =="
  conftest test "tests/fixtures/${AR}/pass.json" -p "${OPA_POLICY}" --all-namespaces

  echo
  echo "== ${AR} fixture (violations) must fail =="
  if conftest test "tests/fixtures/${AR}/fail.json" -p "${OPA_POLICY}" --all-namespaces >/dev/null 2>&1; then
    echo "FAIL: ${AR} violations fixture was not denied" >&2
    exit 1
  fi
  echo "OK: violations correctly denied"
  echo
done

echo
echo "== complypack: contract validation and fixture schema checks =="
if ! command -v complypack >/dev/null 2>&1; then
  echo "SKIP: complypack not installed (go install github.com/complytime/complypack/cmd/complypack@latest)."
else
  # "<rego package file> <platform schema> <AR>"
  while read -r REGO PLATFORM AR; do
    SCHEMA="${PLATFORM}=file://${ROOT}/schemas/${PLATFORM}.cue"
    complypack validate-policy "${OPA_POLICY}/${REGO}.rego" --platform "${PLATFORM}" \
      --schema "${SCHEMA}" --format text
    for f in pass fail; do
      complypack test-policy "${OPA_POLICY}/${REGO}.rego" --platform "${PLATFORM}" \
        --schema "${SCHEMA}" --test-data "tests/fixtures/${AR}/${f}.json" --format text
    done
  done <<'LIST'
github_default_branch_protection github-branch-protection RSC.CMT.CTRL01.AR01
github_default_branch_merge_review github-pr-merge-review RSC.CMT.CTRL01.AR02
LIST
fi

echo
echo "== Python unit tests =="
"${PYTHON:-python3}" -I -m unittest discover -s tests/python -p 'test_*.py'

echo
echo "All implemented tests passed."
