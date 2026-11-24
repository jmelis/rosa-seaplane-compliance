import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import coverage  # noqa: E402
import fedramp_data  # noqa: E402

DATA = Path(__file__).resolve().parent / "data"
AR1, AR2 = "RSC.CMT.CTRL01.AR01", "RSC.CMT.CTRL01.AR02"
REPOS = ["org/a", "org/b"]


def manifest(**status):
    return {"targets": [{"name": n, "status": s} for n, s in status.items()]}


def base_data():
    cov = json.loads((DATA / "complypack-coverage.json").read_text())
    tri = json.loads((DATA / "complypack-triage.json").read_text())
    ksis = fedramp_data.load_ksis()
    return {
        "ksis": {k: ksis[k] for k in ("KSI-CMT-VTD", "KSI-CMT-LMC", "KSI-CMT-RMV")},
        "scope": {"automatable": ["KSI-CMT-VTD", "KSI-CMT-LMC", "KSI-CMT-RMV"], "hybrid": [], "process": []},
        "records": {},
        "repos": REPOS,
        "coverage": {r["requirement_id"]: r for r in cov["requirements"]},
        "triage": {r["requirement_id"]: r for r in tri["automated"]},
        "kinds": {AR1: "Intent", AR2: "Behavioral"},
        "ksi_maps": {"KSI-CMT-VTD": {AR1: "r1", AR2: "r2"}, "KSI-CMT-LMC": {AR2: "r2"}},
        "control_maps": {AR1: {"cm-3", "cm-3.2", "cm-5"}, AR2: {"au-2", "cm-3.1"}},
        "manifests": {},
        "fixtures": {AR1, AR2},
    }


def roll_ksi(data, ksi, bucket="automatable"):
    return coverage.rollup_ksi(ksi, bucket, data)


FULL_RECORD = {
    "ksi": "KSI-CMT-VTD", "target-types": ["github-repository"],
    "measures": "m", "automation-verification": "a", "validation": "v",
}


def decide_all_open(ksis):
    return {c: {"decision": "not-applicable", "rationale": "r"}
            for c in ksis["KSI-CMT-VTD"]["controls"] if c not in ("cm-3", "cm-3.2")}


class States(unittest.TestCase):
    def test_not_started(self):
        r = roll_ksi(base_data(), "KSI-CMT-RMV")
        self.assertEqual(r["state"], coverage.NOT_STARTED)
        self.assertEqual(r["methods_implemented"], 0)

    def test_one_method_is_in_progress(self):
        r = roll_ksi(base_data(), "KSI-CMT-LMC")
        self.assertEqual(r["state"], coverage.IN_PROGRESS)
        self.assertEqual(r["methods_implemented"], 1)

    def test_two_methods_but_not_run_is_in_progress(self):
        r = roll_ksi(base_data(), "KSI-CMT-VTD")
        self.assertEqual(r["methods_implemented"], 2)
        self.assertEqual(r["state"], coverage.IN_PROGRESS)
        self.assertFalse(r["scope_run"])

    def test_partial_scope_is_in_progress(self):
        d = base_data()
        d["records"]["KSI-CMT-VTD"] = FULL_RECORD
        d["manifests"] = {AR1: manifest(**{"org/a": "collected", "org/b": "collected"}),
                          AR2: manifest(**{"org/a": "collected", "org/b": "error"})}
        r = roll_ksi(d, "KSI-CMT-VTD")
        self.assertEqual(r["state"], coverage.IN_PROGRESS)
        ar2 = next(m for m in r["methods"] if m["ar"] == AR2)
        self.assertEqual(ar2["scope"]["missing"], ["org/b"])

    def test_repo_absent_from_manifest_is_missing(self):
        d = base_data()
        d["records"]["KSI-CMT-VTD"] = FULL_RECORD
        d["manifests"] = {AR1: manifest(**{"org/a": "collected"}), AR2: manifest(**{"org/a": "collected"})}
        r = roll_ksi(d, "KSI-CMT-VTD")
        self.assertEqual(r["state"], coverage.IN_PROGRESS)
        self.assertEqual(r["methods"][0]["scope"]["missing"], ["org/b"])

    def full_scope(self, d):
        ok = manifest(**{"org/a": "collected", "org/b": "collected"})
        d["manifests"] = {AR1: ok, AR2: ok}

    def test_covered_with_open_controls(self):
        d = base_data()
        d["records"]["KSI-CMT-VTD"] = FULL_RECORD
        self.full_scope(d)
        self.assertEqual(roll_ksi(d, "KSI-CMT-VTD")["state"], coverage.COVERED)

    def test_covered_when_narrative_missing(self):
        d = base_data()
        d["records"]["KSI-CMT-VTD"] = dict(FULL_RECORD, measures="",
                                           **{"control-decisions": decide_all_open(d["ksis"])})
        self.full_scope(d)
        self.assertEqual(roll_ksi(d, "KSI-CMT-VTD")["state"], coverage.COVERED)

    def test_sdr_ready(self):
        d = base_data()
        d["records"]["KSI-CMT-VTD"] = dict(FULL_RECORD, **{"control-decisions": decide_all_open(d["ksis"])})
        self.full_scope(d)
        r = roll_ksi(d, "KSI-CMT-VTD")
        self.assertEqual(r["state"], coverage.SDR_READY)
        self.assertEqual(r["controls"]["open"], [])

    def test_missing_fixtures_means_not_implemented(self):
        d = base_data()
        d["fixtures"] = {AR2}
        r = roll_ksi(d, "KSI-CMT-VTD")
        self.assertEqual(r["methods_implemented"], 1)

    def test_gap_in_complypack_means_not_implemented(self):
        d = base_data()
        d["coverage"][AR1] = dict(d["coverage"][AR1], status="gap")
        self.assertEqual(roll_ksi(d, "KSI-CMT-VTD")["methods_implemented"], 1)

    def test_manual_plan_means_not_implemented(self):
        d = base_data()
        del d["triage"][AR1]
        self.assertEqual(roll_ksi(d, "KSI-CMT-VTD")["methods_implemented"], 1)


class Controls(unittest.TestCase):
    def test_addressed_only_counts_related_controls(self):
        c = roll_ksi(base_data(), "KSI-CMT-VTD")["controls"]
        self.assertEqual(c["addressed"], ["cm-3", "cm-3.2"])  # cm-5 and au-2 are not VTD's
        self.assertEqual(c["open"], ["cm-4.2", "cm-6.2", "ir-9.4", "si-2"])

    def test_recorded_decision_closes_control(self):
        d = base_data()
        d["records"]["KSI-CMT-VTD"] = dict(FULL_RECORD, **{"control-decisions": {
            "si-2": {"decision": "inherited", "rationale": "r"}}})
        r = roll_ksi(d, "KSI-CMT-VTD")
        self.assertEqual(r["controls"]["inherited"], ["si-2"])
        self.assertEqual(r["controls_decided"], 3)


class Rollup(unittest.TestCase):
    def test_summary_numbers(self):
        d = base_data()
        roll = coverage.rollup(d, "integration")
        s = roll["summary"]
        self.assertEqual((s["ksis"], s["covered"], s["sdr_ready"]), (3, 0, 0))
        self.assertEqual((s["methods_implemented"], s["methods_required"]), (3, 6))

    def test_real_scope_numbers(self):
        d = base_data()
        import ksi_data
        d["ksis"] = fedramp_data.load_ksis()
        d["scope"] = ksi_data.load_scope()
        s = coverage.rollup(d, "integration")["summary"]
        self.assertEqual((s["ksis"], s["automatable"], s["hybrid"], s["deferred_process"]), (35, 26, 9, 11))
        self.assertEqual((s["methods_implemented"], s["methods_required"]), (3, 70))

    def test_never_asks_complypack_for_pass_fail(self):
        self.assertNotIn("--run-tests", (ROOT / "scripts/coverage.py").read_text().split("def run_complypack")[1])

    def test_no_record_cannot_be_covered(self):
        d = base_data()
        ok = manifest(**{"org/a": "collected", "org/b": "collected"})
        d["manifests"] = {AR1: ok, AR2: ok}
        self.assertEqual(roll_ksi(d, "KSI-CMT-VTD")["state"], coverage.IN_PROGRESS)

    def test_rendering(self):
        roll = coverage.rollup(base_data(), "integration")
        text = coverage.render_summary(roll)
        self.assertIn("KSI-CMT-VTD", text)
        self.assertIn("2/2 int+beh", text)
        detail = coverage.render_detail(next(r for r in roll["ksis"] if r["id"] == "KSI-CMT-VTD"))
        self.assertIn("addressed       cm-3, cm-3.2", detail)
        self.assertIn("Next:", detail)


if __name__ == "__main__":
    unittest.main()


class NextSteps(unittest.TestCase):
    def test_rows_carry_next_steps(self):
        row = roll_ksi(base_data(), "KSI-CMT-LMC")
        self.assertEqual(row["next"], coverage.next_steps(row))
        self.assertIn("implement 1 more automated method", row["next"])
        self.assertIn("add the KSI record", row["next"])

    def test_nothing_left(self):
        d = base_data()
        d["records"]["KSI-CMT-VTD"] = dict(FULL_RECORD, **{"control-decisions": decide_all_open(d["ksis"])})
        ok = manifest(**{"org/a": "collected", "org/b": "collected"})
        d["manifests"] = {AR1: ok, AR2: ok}
        self.assertEqual(roll_ksi(d, "KSI-CMT-VTD")["next"], [])
