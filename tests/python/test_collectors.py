import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
AR1, AR2 = "RSC.CMT.CTRL01.AR01", "RSC.CMT.CTRL01.AR02"

# A stand-in for `gh` keyed on the repository name: *ok* works, *unprot* is a
# branch with no protection, anything else is refused.
FAKE_GH = r"""#!/usr/bin/env bash
args="$*"
case "$args" in
  *"api graphql"*)
    name="$(sed -n 's/.*-f name=\([^ ]*\).*/\1/p' <<<"$args")"
    [[ "$name" == *ok* || "$name" == *unprot* ]] || { echo "gh: Resource not accessible by personal access token" >&2; exit 1; }
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo '{"data":{"repository":{"pullRequests":{"nodes":[{"number":7,"mergedAt":"'"$now"'","author":{"login":"a"},"reviewDecision":"APPROVED","mergedBy":{"login":"b"},"commits":{"nodes":[{"commit":{"statusCheckRollup":{"state":"SUCCESS"}}}]}}]}}}}'
    ;;
  *"/protection"*)
    case "$args" in
      *ok*) echo '{"enforce_admins":{"enabled":true}}' ;;
      *unprot*) echo "gh: Branch not protected (HTTP 404)" >&2; exit 1 ;;
      *) echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
    esac
    ;;
  *) echo "unexpected gh call: $args" >&2; exit 2 ;;
esac
"""


class Collectors(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        (t / "bin").mkdir()
        gh = t / "bin" / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
        self.out = t / "out"

    def run_collector(self, ar, repos):
        env = dict(os.environ, PATH=f"{self.tmp.name}/bin:{os.environ['PATH']}", GITHUB_TOKEN="x",
                   RSC_REPOS=" ".join(repos), RSC_EVIDENCE_DIR=str(self.out), RSC_BASE_REF="main",
                   RSC_ENV="integration")
        return subprocess.run([str(ROOT / "evidence" / f"{ar}.sh")], env=env, capture_output=True, text=True)

    def manifest(self, ar):
        return json.loads((self.out / ar / "manifest.json").read_text())

    def test_one_failing_repo_does_not_stop_the_others(self):
        for ar in (AR1, AR2):
            res = self.run_collector(ar, ["o/ok-a", "o/denied", "o/ok-b"])
            self.assertEqual(res.returncode, 0, res.stderr)
            targets = {t["name"]: t for t in self.manifest(ar)["targets"]}
            self.assertEqual(targets["o/ok-a"]["status"], "collected")
            self.assertEqual(targets["o/ok-b"]["status"], "collected")
            self.assertEqual(targets["o/denied"]["status"], "error")
            self.assertIn("not", targets["o/denied"]["error"].lower())
            self.assertTrue((self.out / ar / "ok-a.json").is_file())
            self.assertFalse((self.out / ar / "denied.json").exists())

    def test_evidence_declares_ar_and_repo_but_manifest_does_not(self):
        self.run_collector(AR2, ["o/ok-a"])
        ev = json.loads((self.out / AR2 / "ok-a.json").read_text())
        self.assertEqual((ev["assessment_requirement"], ev["repository"]), (AR2, "o/ok-a"))
        m = self.manifest(AR2)
        self.assertNotIn("assessment_requirement", m)  # the Rego would judge it as evidence
        self.assertEqual((m["ar"], m["environment"]), (AR2, "integration"))
        self.assertIn("generated_at", m)

    def test_unprotected_branch_is_evidence_not_an_error(self):
        res = self.run_collector(AR1, ["o/unprot", "o/ok"])
        self.assertEqual(res.returncode, 0, res.stderr)
        targets = {t["name"]: t["status"] for t in self.manifest(AR1)["targets"]}
        self.assertEqual(targets["o/unprot"], "collected")
        ev = json.loads((self.out / AR1 / "unprot.json").read_text())
        self.assertIs(ev["protected"], False)
        self.assertEqual(ev["protection"], {})
        self.assertIs(json.loads((self.out / AR1 / "ok.json").read_text())["protected"], True)

    def test_all_repos_failing_fails_the_collector(self):
        res = self.run_collector(AR2, ["o/denied-a", "o/denied-b"])
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual([t["status"] for t in self.manifest(AR2)["targets"]], ["error", "error"])

    def test_stale_evidence_is_cleared(self):
        self.run_collector(AR2, ["o/ok-a", "o/ok-b"])
        self.run_collector(AR2, ["o/ok-a"])
        self.assertFalse((self.out / AR2 / "ok-b.json").exists())

    def test_repos_default_to_scope_file(self):
        env = dict(os.environ, PATH=f"{self.tmp.name}/bin:{os.environ['PATH']}", GITHUB_TOKEN="x",
                   RSC_EVIDENCE_DIR=str(self.out), RSC_BASE_REF="main")
        env.pop("RSC_REPOS", None)
        subprocess.run([str(ROOT / "evidence" / f"{AR2}.sh")], env=env, capture_output=True, text=True)
        names = {t["name"] for t in self.manifest(AR2)["targets"]}
        self.assertEqual(len(names), 7)
        self.assertIn("openshift-online/rosa-seaplane-internal", names)


if __name__ == "__main__":
    unittest.main()
