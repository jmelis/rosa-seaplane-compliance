#!/usr/bin/env bash
set -euo pipefail

# Requires: aws CLI, uv, python3 (PyYAML), and the sibling checkouts rosa-seaplane
# and rosa-seaplane-internal (see docs/credentials.md).
# One evidence file per AWS account of the environment (RSC_ENV, default
# integration), plus a manifest; see evidence/lib/collect.sh and aws.sh.
#
# Evidence per account: whether any long-term access key authenticated in the
# window (RSC_WINDOW_DAYS, default 30, at most 90), found by asking CloudTrail for the
# events of each existing key and cross-checking IAM's last-used record. See
# lib/iam_key_usage.py for the method and its limits, and schemas/principal-key-usage.cue.
# Read-only: list, get and lookup calls through the read-only profile only.

AR_ID="$(basename "$0" .sh)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-$(cd "$(dirname "$0")" && pwd)/output}"
LIB_DIR="$(cd "$(dirname "$0")" && pwd)/lib"
source "${LIB_DIR}/collect.sh"
source "${LIB_DIR}/aws.sh"

rsc_aws_reexec "$0"

rsc_list_targets() { rsc_aws_accounts; }

collect_target() {
  local account="$1" out="$2" profile
  profile="$(rsc_aws_ro_profile "${account}")"
  python3 "${LIB_DIR}/iam_key_usage.py" --ar "${AR_ID}" --target "${account}" --profile "${profile}" \
    --window-days "${RSC_WINDOW_DAYS:-30}" --regions "$(rsc_aws_regions)" >"${out}" || return 1
}

rsc_collect_all
