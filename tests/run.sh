#!/usr/bin/env bash
set -euo pipefail

# Policy test suite, run through a pinned conftest container so the repo needs
# no local conftest install. Requires podman or docker.
#   - Rego unit tests (conftest verify) for RSC.CMT.CTRL01.AR02.
#   - Pass/fail fixtures run through the real policy (conftest test).
#   - AR01 (ampel) fixtures run through ampel/policies/RSC.CMT.CTRL01.AR01.json,
#     if `ampel` is installed locally (no official container image, so this
#     part is skipped rather than required).
#
# Overrides: CONFTEST_IMAGE pins the image; CONFTEST_BIN=conftest uses a local
# binary instead of the container.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "${ROOT}"

OPA_POLICY="opa/change-management/policy"
AR02_FIX="tests/fixtures/RSC.CMT.CTRL01.AR02"
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
echo "== AR02 fixture (compliant) must pass =="
conftest test "${AR02_FIX}/pass.json" -p "${OPA_POLICY}" --all-namespaces

echo
echo "== AR02 fixture (violations) must fail =="
if conftest test "${AR02_FIX}/fail.json" -p "${OPA_POLICY}" --all-namespaces >/dev/null 2>&1; then
  echo "FAIL: violations fixture was not denied" >&2
  exit 1
fi
echo "OK: violations correctly denied"

echo
echo "== AR01 (ampel) =="
AR01_FIX="tests/fixtures/RSC.CMT.CTRL01.AR01"
AR01_POLICY="ampel/policies/RSC.CMT.CTRL01.AR01.json"
AR01_TYPE="http://github.com/openshift-online/rosa-seaplane-compliance/ampel/specs/github-branch-protection.yaml"
DUMMY_HASH="0000000000000000000000000000000000000000000000000000000000000000000000000000"
DUMMY_HASH="${DUMMY_HASH:0:64}"

if ! command -v ampel >/dev/null 2>&1; then
  echo "SKIP: ampel not installed locally (no official container image; install from"
  echo "      github.com/policylabs/ampel to run this part)."
else
  # Wraps a fixture's .protection object as the in-toto attestation
  # ampel/specs/github-branch-protection.yaml's snappy spec would produce,
  # so the real policy can be exercised without a live GitHub API call.
  wrap_fixture() {
    jq --arg type "${AR01_TYPE}" --arg hash "${DUMMY_HASH}" '{
      "_type": "https://in-toto.io/Statement/v1",
      "subject": [{"name": "test-subject", "digest": {"sha256": $hash}}],
      "predicateType": $type,
      "predicate": {"type": $type, "values": .protection}
    }' "$1"
  }

  run_ar01_fixture() {
    local att results
    att="$(mktemp)"
    results="$(mktemp)"
    wrap_fixture "$1" >"${att}"
    ampel verify --subject-hash "sha256:${DUMMY_HASH}" \
      -p "${AR01_POLICY}" -a "${att}" --allow-skip --attest-results \
      --results-path "${results}" >/dev/null 2>&1
    local rc=$?
    rm -f "${att}" "${results}"
    return $rc
  }

  echo "-- AR01 fixture (compliant) must pass --"
  if ! run_ar01_fixture "${AR01_FIX}/pass.json"; then
    echo "FAIL: compliant fixture did not pass" >&2
    exit 1
  fi
  echo "OK"

  echo "-- AR01 fixture (violations) must fail --"
  if run_ar01_fixture "${AR01_FIX}/fail.json"; then
    echo "FAIL: violations fixture was not denied" >&2
    exit 1
  fi
  echo "OK: violations correctly denied"
fi

echo
echo "All implemented tests passed."
