import json
import subprocess
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "evidence/lib"))

import iam_key_usage as k  # noqa: E402

# Fake key ids are built at run time, like every fake identifier in this repo.
KEY_A = "AKIA" + "A" * 12 + "AAA1"
KEY_B = "AKIA" + "B" * 12 + "BBB2"
NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)


def trail_event(name="AssumeRole", user="svc", key=KEY_A, kind="IAMUser", when="2026-11-23T10:00:00+00:00"):
    detail = {"eventName": name, "eventSource": "sts.amazonaws.com", "sourceIPAddress": "203.0.113.9",
              "userAgent": "agent/1.0", "requestParameters": {"roleArn": "secret-looking"},
              "userIdentity": {"type": kind, "userName": user, "accessKeyId": key}}
    return {"EventTime": when, "EventName": name, "EventSource": "sts.amazonaws.com", "Username": user,
            "AccessKeyId": key, "CloudTrailEvent": json.dumps(detail)}


class FakeAws:
    """Replaces subprocess.run for the aws CLI: answers by subcommand, records every call."""

    def __init__(self, users=None, keys=None, last_used=None, events=None, root_keys=0, fail=None, throttle=None):
        self.users, self.keys, self.last_used = users or [], keys or {}, last_used or {}
        self.events = events or {}   # (attribute value) -> list of pages (each a list of events)
        self.root_keys, self.fail, self.throttle = root_keys, fail or set(), throttle or {}
        self.calls, self.slept = [], []

    def run(self, cmd, capture_output=True, text=True):
        self.calls.append(cmd)
        a = cmd[5:]  # after: aws --profile P --output json
        line = " ".join(a)
        for needle in self.fail:
            if needle in line:
                return subprocess.CompletedProcess(cmd, 255, "", "An error occurred (AccessDenied): not allowed")
        if a[:2] == ["iam", "list-users"]:
            return self.ok({"Users": [{"UserName": u} for u in self.users]})
        if a[:2] == ["iam", "list-access-keys"]:
            user = a[a.index("--user-name") + 1]
            return self.ok({"AccessKeyMetadata": [{"AccessKeyId": i, "Status": s} for i, s in self.keys.get(user, [])]})
        if a[:2] == ["iam", "get-access-key-last-used"]:
            return self.ok({"AccessKeyLastUsed": self.last_used.get(a[a.index("--access-key-id") + 1], {})})
        if a[:2] == ["iam", "get-account-summary"]:
            return self.ok({"SummaryMap": {"AccountAccessKeysPresent": self.root_keys}})
        if a[:2] == ["cloudtrail", "lookup-events"]:
            value = a[a.index("--lookup-attributes") + 1].split("AttributeValue=")[1]
            token = a[a.index("--next-token") + 1] if "--next-token" in a else None
            n = self.throttle.get(value, 0)
            if n:
                self.throttle[value] = n - 1
                return subprocess.CompletedProcess(cmd, 254, "", "An error occurred (ThrottlingException) when calling the LookupEvents operation: Rate exceeded")
            pages = self.events.get(value, [[]])
            i = int(token) if token else 0
            out = {"Events": pages[i]}
            if i + 1 < len(pages):
                out["NextToken"] = str(i + 1)
            return self.ok(out)
        raise AssertionError(f"unexpected aws call: {line}")

    def ok(self, body):
        return subprocess.CompletedProcess([], 0, json.dumps(body), "")

    def aws(self, **kw):
        return k.Aws("rsc-x-ro", interval=0, retries=kw.get("retries", 3), backoff=0, run=self.run, sleep=self.slept.append)

    def lookups(self):
        return [c for c in self.calls if "lookup-events" in c]


def collect(fake, regions=("us-east-1",), days=30, **kw):
    return k.collect(fake.aws(**kw), "RSC.IAM.CTRL01.AR02", "regional", days, list(regions), NOW)


class Discovery(unittest.TestCase):
    def test_active_and_inactive_keys_are_both_checked(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active"), (KEY_B, "Inactive")]})
        ev = collect(f)
        self.assertEqual([(x["principal"], x["key_suffix"], x["active"]) for x in ev["keys"]],
                         [("svc", "AAA1", True), ("svc", "BBB2", False)])
        self.assertEqual(len(f.lookups()), 2)
        self.assertEqual(ev["collection"]["keys_checked"], 2)

    def test_no_users_is_a_complete_empty_collection(self):
        ev = collect(FakeAws())
        self.assertEqual((ev["keys"], ev["events"], ev["collection"]["complete"]), ([], [], True))

    def test_the_root_user_is_looked_up_by_name_only_when_it_has_keys(self):
        none = FakeAws(root_keys=0)
        collect(none)
        self.assertEqual(none.lookups(), [])
        some = FakeAws(root_keys=1, events={"root": [[trail_event(user="root", key="", kind="Root")]]})
        ev = collect(some)
        self.assertTrue(any("AttributeKey=Username,AttributeValue=root" in " ".join(c) for c in some.lookups()))
        self.assertEqual(ev["keys"][-1]["principal"], "root")
        self.assertEqual(ev["events"], [])  # a root console sign-in carries no key: not a finding

    def test_a_root_call_made_with_a_long_term_key_is_a_finding(self):
        f = FakeAws(root_keys=1, events={"root": [[trail_event(user="root", key=KEY_A, kind="Root")]]})
        ev = collect(f)
        self.assertEqual([(e["principal"], e["credential_type"]) for e in ev["events"]], [("root", "long-term")])
        self.assertEqual(ev["keys"][-1]["events_found"], 1)

    def test_unresolved_root_lookup_is_incomplete(self):
        pages = [[trail_event(user="root", key="", kind="Root")] for _ in range(k.ROOT_PAGE_CAP + 5)]
        ev = collect(FakeAws(root_keys=1, events={"root": pages}))
        self.assertFalse(ev["collection"]["complete"])

    def test_failing_to_list_the_inventory_is_an_error_not_evidence(self):
        for needle in ("list-users", "get-account-summary"):
            with self.assertRaises(k.CollectionError):
                collect(FakeAws(fail={needle}))
        with self.assertRaises(k.CollectionError):
            collect(FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, fail={"list-access-keys"}))


class Lookups(unittest.TestCase):
    def test_early_exit_after_the_first_page_with_events(self):
        pages = [[trail_event()] * 50, [trail_event()] * 50, [trail_event()] * 10]
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: pages})
        ev = collect(f)
        self.assertEqual(len(f.lookups()), 1)  # did not page on
        key = ev["keys"][0]
        self.assertEqual((key["events_found"], key["events_truncated"]), (50, True))

    def test_sample_is_bounded(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: [[trail_event()] * 50]})
        self.assertEqual(len(collect(f)["events"]), k.SAMPLE_PER_KEY)

    def test_a_key_with_no_events_is_paged_until_the_window_is_exhausted(self):
        pages = [[], [], []]  # empty pages that still carry a token
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: pages})
        ev = collect(f)
        self.assertEqual(len(f.lookups()), 3)
        self.assertEqual((ev["keys"][0]["events_found"], ev["collection"]["complete"]), (0, True))

    def test_lookup_is_bounded_to_the_window_newest_first_by_key(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]})
        collect(f, days=7)
        c = " ".join(f.lookups()[0])
        self.assertIn(f"AttributeKey=AccessKeyId,AttributeValue={KEY_A}", c)
        self.assertIn("--start-time 2026-11-17T12:00:00Z --end-time 2026-11-24T12:00:00Z", c)
        self.assertIn("--max-results 50", c)

    def test_every_region_is_searched_for_a_key_with_no_events_and_home_region_is_always_included(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]})
        ev = collect(f, regions=("eu-west-1",))
        self.assertEqual(ev["collection"]["regions"], ["us-east-1", "eu-west-1"])
        self.assertEqual(len(f.lookups()), 2)

    def test_events_found_in_the_home_region_skip_the_others(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: [[trail_event()]]})
        collect(f, regions=("eu-west-1",))
        self.assertEqual(len(f.lookups()), 1)

    def test_throttling_is_retried_with_backoff_then_succeeds(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: [[trail_event()]]}, throttle={KEY_A: 2})
        ev = collect(f)
        self.assertEqual(len(f.lookups()), 3)
        self.assertEqual(ev["keys"][0]["events_found"], 1)
        self.assertTrue(ev["collection"]["complete"])
        self.assertTrue(f.slept)  # it backed off

    def test_giving_up_on_throttling_makes_the_collection_incomplete_never_a_pass(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, throttle={KEY_A: 99})
        ev = collect(f, retries=2)
        self.assertEqual(len(f.lookups()), 3)  # first try + 2 retries, bounded
        self.assertFalse(ev["collection"]["complete"])
        self.assertEqual(ev["collection"]["lookup_errors"], 1)

    def test_a_lookup_error_is_incomplete_and_other_keys_are_still_checked(self):
        f = FakeAws(users=["a", "b"], keys={"a": [(KEY_A, "Active")], "b": [(KEY_B, "Active")]},
                    events={KEY_B: [[trail_event(user="b", key=KEY_B)]]}, fail={f"AttributeValue={KEY_A}"})
        ev = collect(f)
        self.assertFalse(ev["collection"]["complete"])
        self.assertEqual([x["events_found"] for x in ev["keys"]], [0, 1])

    def test_lookups_are_paced_per_region(self):
        slept = []
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: [[], []]})
        aws = k.Aws("p", interval=10, retries=0, backoff=0, run=f.run, sleep=slept.append)
        k.collect(aws, "ar", "t", 30, ["us-east-1"], NOW)
        self.assertTrue(slept and all(0 < s <= 10 for s in slept))


class CrossCheck(unittest.TestCase):
    def used(self, when, region="us-east-1"):
        return {"LastUsedDate": when, "ServiceName": "sts", "Region": region}

    def check(self, last, events=None, regions=("us-east-1",)):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, last_used={KEY_A: last}, events={KEY_A: events or [[]]})
        return collect(f, regions=regions)["keys"][0]

    def test_used_in_window_is_recorded(self):
        key = self.check(self.used("2026-11-20T00:00:00+00:00"), [[trail_event()]])
        self.assertEqual((key["last_used"], key["last_used_in_window"], key["cross_checked"]), ("2026-11-20T00:00:00Z", True, True))

    def test_used_before_the_window_is_not_in_window(self):
        key = self.check(self.used("2026-01-01T00:00:00+00:00"))
        self.assertFalse(key["last_used_in_window"])

    def test_never_used_has_no_last_used(self):
        key = self.check({})
        self.assertEqual((key["last_used"], key["last_used_in_window"], key["last_used_region"]), (None, False, None))

    def test_used_in_window_with_no_events_is_surfaced_as_facts_for_the_policy(self):
        key = self.check(self.used("2026-11-20T00:00:00+00:00"))
        self.assertEqual((key["last_used_in_window"], key["events_found"], key["cross_checked"]), (True, 0, True))

    def test_last_used_in_an_unsearched_region_is_flagged(self):
        key = self.check(self.used("2026-11-20T00:00:00+00:00", "eu-west-1"), [[trail_event()]])
        self.assertEqual((key["last_used_region"], key["last_used_region_checked"]), ("eu-west-1", False))

    def test_na_region_is_not_a_region(self):
        key = self.check(self.used("2026-11-20T00:00:00+00:00", "N/A"), [[trail_event()]])
        self.assertEqual((key["last_used_region"], key["last_used_region_checked"]), (None, True))

    def test_unreadable_last_used_makes_the_collection_incomplete(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, fail={"get-access-key-last-used"})
        ev = collect(f)
        self.assertFalse(ev["collection"]["complete"])
        self.assertFalse(ev["keys"][0]["cross_checked"])


class Normalization(unittest.TestCase):
    def one(self, **kw):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: [[trail_event(**kw)]]})
        return collect(f)["events"][0]

    def test_long_term_key_is_long_term(self):
        self.assertEqual(self.one()["credential_type"], "long-term")

    def test_an_iam_user_with_a_session_key_is_still_long_term(self):
        e = self.one(kind="IAMUser", key="ASIA" + "C" * 16)
        self.assertEqual(e["credential_type"], "long-term")

    def test_a_mere_assumed_role_session_is_not_long_term(self):
        e = self.one(kind="AssumedRole", key="ASIA" + "C" * 16)
        self.assertEqual((e["credential_type"], e["principal_type"]), ("temporary", "assumed-role"))

    def test_event_time_is_utc(self):
        self.assertEqual(self.one(when="2026-11-23T11:00:00+01:00")["time"], "2026-11-23T10:00:00Z")

    def test_evidence_never_holds_ips_agents_parameters_or_full_key_ids(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: [[trail_event()]]},
                    last_used={KEY_A: {"LastUsedDate": "2026-11-20T00:00:00+00:00", "Region": "us-east-1"}})
        text = json.dumps(collect(f))
        for secret in ("203.0.113.9", "agent/1.0", "secret-looking", KEY_A, "AKIAAAAA"):
            self.assertNotIn(secret, text)
        self.assertIn("AAA1", text)  # only the last four characters

    def test_session_names_are_never_used_as_principals(self):
        detail = {"userIdentity": {"type": "AssumedRole", "accessKeyId": "ASIA" + "C" * 16,
                                   "sessionContext": {"sessionIssuer": {"userName": "a-role"}}}}
        e = k.normalize_event({"EventTime": "2026-11-23T10:00:00Z", "EventName": "X", "EventSource": "y",
                               "Username": "a.person@example.com", "CloudTrailEvent": json.dumps(detail)}, "us-east-1")
        self.assertEqual(e["principal"], "a-role")


class Cli(unittest.TestCase):
    def test_window_must_be_within_what_event_history_keeps(self):
        import argparse
        self.assertEqual(k.window_days_arg("90"), 90)
        for bad in ("0", "91", "-1"):
            with self.assertRaises(argparse.ArgumentTypeError):
                k.window_days_arg(bad)

    def test_output_is_valid_json_for_the_schema_fields(self):
        ev = collect(FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}))
        for field in ("assessment_requirement", "target", "target_type", "collection", "keys", "events"):
            self.assertIn(field, ev)
        self.assertEqual(ev["collection"]["limitations"], k.LIMITATIONS)

    def test_only_read_calls_are_ever_made(self):
        f = FakeAws(users=["svc"], keys={"svc": [(KEY_A, "Active")]}, events={KEY_A: [[trail_event()]]}, root_keys=1)
        collect(f)
        for cmd in f.calls:
            self.assertEqual(cmd[1:3], ["--profile", "rsc-x-ro"])
            verb = cmd[6]
            self.assertTrue(verb.startswith(("list-", "get-", "lookup-")), cmd)


if __name__ == "__main__":
    unittest.main()
