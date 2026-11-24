import json
import os
from datetime import datetime, timedelta, timezone
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
    file="${FAKE_GH_DIR}/${name}.json"
    [[ "$args" == *"-f after="* ]] && file="${FAKE_GH_DIR}/${name}.2.json"
    if [[ -f "$file" ]]; then cat "$file"; exit 0; fi
    [[ "$name" == *ok* || "$name" == *unprot* ]] || { echo "gh: Resource not accessible by personal access token" >&2; exit 1; }
    cat "${FAKE_GH_DIR}/default.json"
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


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def user(login, bot=False):
    return {"login": login, "__typename": "Bot" if bot else "User"}


def pr(number, author="alice", labels=(), comments=(), reviews=(), opinionated=(), at=None, truncated=False):
    """A GraphQL pull request node. comments/reviews are (login, body[, time])."""
    t = at or now()
    return {
        "number": number, "mergedAt": t, "updatedAt": t,
        "author": user(author), "mergedBy": {"login": "openshift-merge-bot"},
        "labels": {"nodes": [{"name": n} for n in labels]},
        "latestOpinionatedReviews": {"nodes": [{"state": st, "author": user(a)} for a, st in opinionated]},
        "comments": {"pageInfo": {"hasNextPage": truncated},
                     "nodes": [{"author": user(c[0], len(c) > 3), "body": c[1], "createdAt": c[2] if len(c) > 2 else "2026-01-01T00:00:00Z"}
                               for c in comments]},
        "reviews": {"pageInfo": {"hasNextPage": False},
                    "nodes": [{"author": user(r[0]), "body": r[1], "submittedAt": r[2] if len(r) > 2 else "2026-01-01T00:00:00Z"}
                              for r in reviews]},
        "commits": {"nodes": [{"commit": {"statusCheckRollup": {"state": "SUCCESS"}}}]},
    }


def page(nodes, has_next=False, cursor="c1"):
    return {"data": {"repository": {"pullRequests": {
        "pageInfo": {"hasNextPage": has_next, "endCursor": cursor}, "nodes": nodes}}}}


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
        self.fake_dir = t / "fake"
        self.fake_dir.mkdir()
        self.graphql("default", page([pr(7, labels=["lgtm", "approved"], comments=[("bob", "/lgtm")])]))

    def graphql(self, name, body):
        (self.fake_dir / f"{name}.json").write_text(json.dumps(body))

    def run_collector(self, ar, repos):
        env = dict(os.environ, PATH=f"{self.tmp.name}/bin:{os.environ['PATH']}", GITHUB_TOKEN="x",
                   RSC_REPOS=" ".join(repos), RSC_EVIDENCE_DIR=str(self.out), RSC_BASE_REF="main",
                   RSC_ENV="integration", FAKE_GH_DIR=str(self.fake_dir))
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
                   RSC_EVIDENCE_DIR=str(self.out), RSC_BASE_REF="main", FAKE_GH_DIR=str(self.fake_dir))
        env.pop("RSC_REPOS", None)
        subprocess.run([str(ROOT / "evidence" / f"{AR2}.sh")], env=env, capture_output=True, text=True)
        names = {t["name"] for t in self.manifest(AR2)["targets"]}
        self.assertEqual(len(names), 7)
        self.assertIn("openshift-online/rosa-seaplane-internal", names)


class Approval(unittest.TestCase):
    """How the AR02 collector normalizes GitHub and Prow approvals."""

    def collect(self, node, repo="o/ok-x"):
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page([node]))
        res = c.run_collector(AR2, [repo])
        self.assertEqual(res.returncode, 0, res.stderr)
        prs = json.loads((c.out / AR2 / "ok-x.json").read_text())["pull_requests"]
        self.assertEqual(len(prs), 1)
        return prs[0]

    LABELS = ("lgtm", "approved")

    def test_github_review_approval(self):
        p = self.collect(pr(1, opinionated=[("bob", "APPROVED")]))
        self.assertEqual((p["approved_by"], p["approval_sources"]), (["bob"], ["github-review"]))

    def test_prow_approval_from_comment(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("bob", "looks good\n/lgtm\r\n/approve")]))
        self.assertEqual((p["approved_by"], p["approval_sources"]), (["bob"], ["prow"]))

    def test_prow_approval_from_review_body(self):
        p = self.collect(pr(1, labels=self.LABELS, reviews=[("bob", "/lgtm\n/approve")]))
        self.assertEqual(p["approved_by"], ["bob"])

    def test_both_sources(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("carol", "/lgtm")], opinionated=[("bob", "APPROVED")]))
        self.assertEqual(p["approved_by"], ["bob", "carol"])
        self.assertEqual(p["approval_sources"], ["github-review", "prow"])

    def test_authors_own_lgtm_never_counts(self):
        p = self.collect(pr(1, author="alice", labels=self.LABELS, comments=[("alice", "/lgtm")]))
        self.assertEqual(p["approved_by"], [])

    def test_authors_own_github_approval_never_counts(self):
        p = self.collect(pr(1, author="alice", opinionated=[("alice", "APPROVED")]))
        self.assertEqual(p["approved_by"], [])

    def test_command_without_labels_did_not_take_effect(self):
        # The real shape of rosa-seaplane PR 968: /lgtm in a comment, no labels.
        for labels in ((), ("lgtm",), ("approved",)):
            p = self.collect(pr(1, labels=labels, comments=[("bob", "/lgtm\n/approve")]))
            self.assertEqual(p["approved_by"], [], labels)

    def test_labels_without_any_human_command_do_not_prove_an_approver(self):
        # A bot author applying its own labels, as dependency-update bots do.
        p = self.collect(pr(1, author="dep-bot", labels=self.LABELS, comments=[("openshift-ci", "[APPROVALNOTIFIER]", "2026-01-01T00:00:00Z", "bot")]))
        self.assertEqual(p["approved_by"], [])

    def test_cancelled_lgtm_does_not_count_but_a_later_relgtm_does(self):
        cancelled = pr(1, labels=self.LABELS, comments=[("bob", "/lgtm", "2026-01-01T00:00:01Z"), ("bob", "/lgtm cancel", "2026-01-01T00:00:02Z")])
        self.assertEqual(self.collect(cancelled)["approved_by"], [])
        again = pr(1, labels=self.LABELS, comments=[("bob", "/lgtm cancel", "2026-01-01T00:00:01Z"), ("bob", "/lgtm", "2026-01-01T00:00:02Z")])
        self.assertEqual(self.collect(again)["approved_by"], ["bob"])

    def test_commands_must_start_a_line(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("bob", "please do not /lgtm yet\n> /lgtm quoted")]))
        self.assertEqual(p["approved_by"], [])

    def test_bot_commenters_are_not_approvers(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("some-bot", "/lgtm", "2026-01-01T00:00:00Z", "bot")]))
        self.assertEqual(p["approved_by"], [])

    def test_truncated_history_is_flagged(self):
        self.assertIs(self.collect(pr(1, truncated=True))["history_truncated"], True)
        self.assertIs(self.collect(pr(1))["history_truncated"], False)

    def test_no_review_decision_or_comment_text_in_evidence(self):
        p = self.collect(pr(1, labels=self.LABELS, comments=[("bob", "secret-ish text\n/lgtm")]))
        self.assertNotIn("review_decision", p)
        self.assertNotIn("secret-ish", json.dumps(p))

    def test_prs_outside_the_window_are_dropped(self):
        old = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page([pr(1), pr(2, at=old)]))
        c.run_collector(AR2, ["o/ok-x"])
        prs = json.loads((c.out / AR2 / "ok-x.json").read_text())["pull_requests"]
        self.assertEqual([p["number"] for p in prs], [1])

    def test_pagination_follows_until_the_window_is_covered(self):
        old = (datetime.now(timezone.utc) - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        c = Collectors("test_one_failing_repo_does_not_stop_the_others")
        c.setUp()
        self.addCleanup(c.tmp.cleanup)
        c.graphql("ok-x", page([pr(1), pr(2)], has_next=True))
        c.graphql("ok-x.2", page([pr(3), pr(4, at=old)], has_next=True, cursor="c2"))
        c.run_collector(AR2, ["o/ok-x"])
        prs = json.loads((c.out / AR2 / "ok-x.json").read_text())["pull_requests"]
        self.assertEqual([p["number"] for p in prs], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
