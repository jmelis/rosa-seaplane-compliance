#!/usr/bin/env python3
"""Container entrypoint: collect evidence, then run complyctl scan.

Runs every executable file in evidence/ (any language), each named by the AR
FQDN it serves; the AR's text is looked up in gemara/*/controls.yaml for the log
line. Assumes CWD is the repo root (true in the container at WORKDIR /workspace
and locally via `make run-local`).
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

EVIDENCE_DIR = Path("evidence")
CATALOG_GLOB = "gemara/*/controls.yaml"
POLICY_GLOB = "gemara/*/policy.yaml"


def require_env(name: str, why: str) -> None:
    if not os.environ.get(name):
        sys.exit(f"ERROR: {name} must be set; {why}")


def ar_texts() -> dict:
    """AR id -> its assessment-requirement text, across every control catalog."""
    texts = {}
    for catalog in Path().glob(CATALOG_GLOB):
        doc = yaml.safe_load(catalog.read_text()) or {}
        for control in doc.get("controls", []):
            for ar in control.get("assessment-requirements", []):
                texts[ar["id"]] = " ".join((ar.get("text") or "").split())
    return texts


def policy_ars() -> list:
    """Every AR the policies assess, across all domains."""
    ars = []
    for policy in sorted(Path().glob(POLICY_GLOB)):
        doc = yaml.safe_load(policy.read_text()) or {}
        for plan in doc.get("adherence", {}).get("assessment-plans", []):
            ars.append(plan["requirement-id"])
    return ars


def missing_evidence(ars: list, evidence_dir: Path) -> list:
    """ARs with no evidence file that declares itself evidence for that AR.

    The Rego packages only judge evidence carrying their own
    assessment_requirement, so an AR with no evidence yields no denials and
    would look like a pass. It must fail the run instead.
    """
    missing = []
    for ar in ars:
        found = False
        for f in sorted((evidence_dir / ar).glob("*.json")):
            try:
                found = json.loads(f.read_text()).get("assessment_requirement") == ar
            except (ValueError, AttributeError):
                found = False
            if found:
                break
        if not found:
            missing.append(ar)
    return missing


def run(cmd: list, check: bool = True) -> None:
    print(f"==> {' '.join(cmd)}", flush=True)
    subprocess.run(cmd, check=check)


def main() -> None:
    require_env("GITHUB_TOKEN", "required by the evidence collectors (gh api).")
    require_env("RSC_EVIDENCE_DIR", "the opa evaluator's input_path in .complytime/complytime.yaml references it directly.")

    texts = ar_texts()
    collectors = sorted(
        p for p in EVIDENCE_DIR.iterdir() if p.is_file() and os.access(p, os.X_OK)
    )
    for collector in collectors:
        fqdn = collector.stem
        text = texts.get(fqdn)
        label = f"{fqdn} ({text})" if text else fqdn
        print(f"==> Collecting evidence for {label}", flush=True)
        subprocess.run([str(collector.resolve())], check=True)

    missing = missing_evidence(policy_ars(), Path(os.environ["RSC_EVIDENCE_DIR"]))
    if missing:
        sys.exit(
            "ERROR: no evidence collected for " + ", ".join(missing)
            + "; refusing to scan, since missing evidence would look like a pass."
        )

    run(["complyctl", "get"])
    run(["complyctl", "doctor", "--format", "text"], check=False)
    # No target name: scans every target configured for this policy.
    # check=False: complyctl exits non-zero when any AR fails, which is a
    # finding to report, not a pipeline error.
    run(
        ["complyctl", "scan", "--policy-id", "change-management", "--format", "oscal,sarif,pretty"],
        check=False,
    )


if __name__ == "__main__":
    main()
