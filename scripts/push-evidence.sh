#!/usr/bin/env bash
set -euo pipefail

# Pushes one run's evidence (evidence/output/) and L5 EvaluationLog
# (.complytime/scan/) to the shared evidence locker (an S3 bucket), under a
# timestamped, append-only prefix. Requires: aws CLI, credentials for the
# target bucket (real AWS creds, or AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
# for a local S3-compatible endpoint).
#
# Env:
#   RSC_S3_BUCKET        required. Destination bucket name.
#   RSC_S3_PREFIX         optional. Key prefix under the bucket (default: rosa-seaplane-compliance).
#   RSC_S3_ENDPOINT_URL   optional. Set for a local/non-AWS S3-compatible endpoint (e.g. s3mock, MinIO);
#                         leave unset against real AWS.
#   RSC_EVIDENCE_DIR      optional. Default: evidence/output (relative to repo root).
#   RSC_SCAN_DIR          optional. Default: .complytime/scan (relative to repo root).
#
# Usage: ./scripts/push-evidence.sh

: "${RSC_S3_BUCKET:?set RSC_S3_BUCKET to the evidence-locker bucket name}"
PREFIX="${RSC_S3_PREFIX:-rosa-seaplane-compliance}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
EVIDENCE_DIR="${RSC_EVIDENCE_DIR:-${REPO_ROOT}/evidence/output}"
SCAN_DIR="${RSC_SCAN_DIR:-${REPO_ROOT}/.complytime/scan}"

AWS=(aws)
if [[ -n "${RSC_S3_ENDPOINT_URL:-}" ]]; then
  AWS+=(--endpoint-url "${RSC_S3_ENDPOINT_URL}")
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
DEST="s3://${RSC_S3_BUCKET}/${PREFIX}/${RUN_ID}"

pushed=0
if [[ -d "${EVIDENCE_DIR}" ]]; then
  echo "==> Pushing ${EVIDENCE_DIR} to ${DEST}/evidence/" >&2
  "${AWS[@]}" s3 cp --recursive "${EVIDENCE_DIR}" "${DEST}/evidence/"
  pushed=1
else
  echo "WARN: ${EVIDENCE_DIR} not found; nothing to push for raw evidence." >&2
fi

if [[ -d "${SCAN_DIR}" ]]; then
  echo "==> Pushing ${SCAN_DIR} to ${DEST}/scan/" >&2
  "${AWS[@]}" s3 cp --recursive "${SCAN_DIR}" "${DEST}/scan/"
  pushed=1
else
  echo "WARN: ${SCAN_DIR} not found; nothing to push for the EvaluationLog." >&2
fi

if [[ "${pushed}" -eq 0 ]]; then
  echo "ERROR: nothing found to push (checked ${EVIDENCE_DIR} and ${SCAN_DIR})." >&2
  exit 1
fi

echo "Pushed run ${RUN_ID} to ${DEST}"
