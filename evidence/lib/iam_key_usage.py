#!/usr/bin/env python3
"""Collect long-term-credential usage evidence for one AWS account.

    iam_key_usage.py --ar <AR id> --target <logical account> --profile <read-only profile>
                     [--window-days 30] [--regions us-east-1,...]

Answers "did any principal authenticate with a long-term credential in the window?"
without scanning the whole audit log (CloudTrail's LookupEvents returns 50 events per
call at 2 calls per second per account and region, one filter at a time, so a full
scan of a busy account takes hours). Instead it asks for the events of each EXISTING
long-term key:

  1. list the IAM users and their access keys (active and inactive: an inactive key
     may have been active earlier in the window);
  2. for each key, look up CloudTrail events by access key, newest first, bounded to
     the window. One page with events already proves the key was used, so it stops
     there; a key with no events is paged until the window is exhausted;
  3. cross-check each key with IAM's own last-used record. If IAM says a key was used
     in the window but CloudTrail has no event for it (for example it was only used
     for data-plane calls, which event history does not record), or it was last used
     in a region that was not searched, that is reported as a fact the policy denies:
     the evidence is suspect and is never read as a pass;
  4. if the root user has any access key, look up events by user name `root`.

Read-only: list, get and lookup calls only, through the read-only profile. Evidence is
normalized (schemas/principal-key-usage.cue) and holds only a bounded sample of
trimmed events per key: never source IPs, user agents, request parameters or full key
ids (only the last four characters).

Limits it cannot get around, recorded in collection.limitations: keys deleted inside
the window cannot be listed so they are not checked; only management events of the
last 90 days are searched; sessions are not followed past the call made with the key.

Any lookup that fails or is throttled out makes collection.complete false, which the
policy denies. Failing to list the inventory at all is an error and writes no evidence.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone

MAX_WINDOW_DAYS = 90
SAMPLE_PER_KEY = 20
ROOT_PAGE_CAP = 40
HOME_REGION = "us-east-1"
SOURCE = "cloudtrail-event-history+iam-last-used"
LIMITATIONS = [
    "access keys deleted inside the window cannot be listed, so they are not checked",
    "only management events in CloudTrail event history (the last 90 days) are searched; data-plane calls are not",
    "a session started with a key is seen only as the call made with the key, not followed afterwards",
]
ID_RE = re.compile(r"[0-9]{12}")
THROTTLE_RE = re.compile(r"Throttling|Rate exceeded|TooManyRequests", re.I)


class AwsError(RuntimeError):
    pass


class CollectionError(RuntimeError):
    """The account's key inventory could not be read: no evidence can be written."""


def mask(text: str) -> str:
    return ID_RE.sub("<ID>", text)


def utc_iso(value) -> str:
    if isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(value, timezone.utc)
    else:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Aws:
    """Thin wrapper over the aws CLI: JSON in, JSON out, paced and retried lookups."""

    def __init__(self, profile, interval=None, retries=None, backoff=None, run=subprocess.run, sleep=time.sleep):
        self.profile = profile
        self.interval = float(os.environ.get("RSC_LOOKUP_INTERVAL", "0.55")) if interval is None else interval
        self.retries = int(os.environ.get("RSC_LOOKUP_RETRIES", "6")) if retries is None else retries
        self.backoff = float(os.environ.get("RSC_LOOKUP_BACKOFF", "1.0")) if backoff is None else backoff
        self._run, self._sleep, self._last = run, sleep, {}

    def call(self, *args: str, region: str = None) -> dict:
        """Run one aws call; throttling is retried with backoff, anything else raises."""
        cmd = ["aws", "--profile", self.profile, "--output", "json", *args]
        for attempt in range(self.retries + 1):
            if region is not None:
                # At most 2 lookups per second per account and region.
                wait = self.interval - (time.monotonic() - self._last.get(region, -1e9))
                if wait > 0:
                    self._sleep(wait)
                self._last[region] = time.monotonic()
            res = self._run(cmd, capture_output=True, text=True)
            if res.returncode == 0:
                return json.loads(res.stdout) if res.stdout.strip() else {}
            err = (res.stderr or res.stdout or "").strip()
            if THROTTLE_RE.search(err) and attempt < self.retries:
                self._sleep(min(self.backoff * (2 ** attempt), 30))
                continue
            raise AwsError(mask(err.splitlines()[-1] if err else "aws call failed")[:200])
        raise AwsError("throttled")  # pragma: no cover (loop always returns or raises)


def principal_of(identity: dict, fallback: str) -> str:
    kind = identity.get("type")
    if kind == "IAMUser":
        return identity.get("userName") or fallback or "unknown"
    if kind == "Root":
        return "root"
    # Never a session name: it can be a person. The role that issued it, if any.
    issuer = (identity.get("sessionContext") or {}).get("sessionIssuer") or {}
    return issuer.get("userName") or (kind or "unknown").lower()


def credential_type(identity: dict, key_id: str) -> str:
    kind = identity.get("type")
    if kind == "IAMUser" or key_id.startswith("AKIA"):
        # An IAM user's call is long-term even when the key is a session key: a session
        # derived from a long-term key still starts from one.
        return "long-term"
    if key_id.startswith("ASIA"):
        return "temporary"
    return "none"


def normalize_event(event: dict, region: str) -> dict:
    detail = json.loads(event.get("CloudTrailEvent") or "{}")
    identity = detail.get("userIdentity") or {}
    key_id = identity.get("accessKeyId") or event.get("AccessKeyId") or ""
    kind = identity.get("type") or "unknown"
    return {
        "time": utc_iso(event["EventTime"]),
        "event_name": event.get("EventName") or detail.get("eventName") or "unknown",
        "event_source": event.get("EventSource") or detail.get("eventSource") or "unknown",
        "principal_type": {"IAMUser": "iam-user", "Root": "root", "AssumedRole": "assumed-role"}.get(kind, kind.lower()),
        "principal": principal_of(identity, event.get("Username")),
        "credential_type": credential_type(identity, key_id),
        "region": region,
    }


def lookup_args(attribute: str, value: str, region: str, start: datetime, end: datetime, token: str = None) -> list:
    args = ["cloudtrail", "lookup-events", "--region", region,
            "--lookup-attributes", f"AttributeKey={attribute},AttributeValue={value}",
            "--start-time", utc_iso(start.timestamp()), "--end-time", utc_iso(end.timestamp()),
            "--max-results", "50"]
    return args + (["--next-token", token] if token else [])


def lookup_key(aws: Aws, key_id: str, region: str, start: datetime, end: datetime):
    """(sample, events_seen, truncated) for one key in one region. Stops at the first events."""
    sample, seen, token = [], 0, None
    while True:
        page = aws.call(*lookup_args("AccessKeyId", key_id, region, start, end, token), region=region)
        batch = page.get("Events") or []
        seen += len(batch)
        for e in batch:
            if len(sample) < SAMPLE_PER_KEY:
                sample.append(normalize_event(e, region))
        token = page.get("NextToken")
        if seen:  # any event made with a long-term key proves it authenticated in the window
            return sample, seen, bool(token) or seen > len(sample)
        if not token:
            return sample, 0, False


def lookup_root(aws: Aws, region: str, start: datetime, end: datetime):
    """(sample, long_term_seen, resolved): root events carry no key, so only calls made
    with a long-term key count. Unresolved if the page cap is hit without finding any."""
    sample, found, token, pages = [], 0, None, 0
    while pages < ROOT_PAGE_CAP:
        page = aws.call(*lookup_args("Username", "root", region, start, end, token), region=region)
        pages += 1
        for e in page.get("Events") or []:
            n = normalize_event(e, region)
            if n["credential_type"] == "long-term":
                found += 1
                if len(sample) < SAMPLE_PER_KEY:
                    sample.append(n)
        token = page.get("NextToken")
        if found:
            return sample, found, True
        if not token:
            return sample, 0, True
    return sample, 0, False


def list_keys(aws: Aws) -> list:
    try:
        users = aws.call("iam", "list-users").get("Users") or []
        keys = []
        for user in users:
            meta = aws.call("iam", "list-access-keys", "--user-name", user["UserName"]).get("AccessKeyMetadata") or []
            for k in meta:
                keys.append({"principal": user["UserName"], "key_id": k["AccessKeyId"], "active": k.get("Status") == "Active"})
        return keys
    except AwsError as e:
        raise CollectionError(f"could not list the account's access keys: {e}") from None


def root_has_keys(aws: Aws) -> bool:
    try:
        return int((aws.call("iam", "get-account-summary").get("SummaryMap") or {}).get("AccountAccessKeysPresent", 0)) > 0
    except AwsError as e:
        raise CollectionError(f"could not read the account summary: {e}") from None


def collect(aws: Aws, ar: str, target: str, window_days: int, regions: list, now: datetime = None) -> dict:
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=window_days)
    regions = [HOME_REGION] + [r for r in regions if r != HOME_REGION]
    inventory = list_keys(aws)
    root = root_has_keys(aws)
    errors, keys, events = 0, [], []

    for k in inventory:
        rec = {"principal_type": "iam-user", "principal": k["principal"], "key_suffix": k["key_id"][-4:],
               "active": k["active"], "last_used": None, "last_used_in_window": False, "last_used_region": None,
               "last_used_region_checked": True, "cross_checked": False, "events_found": 0, "events_truncated": False}
        try:
            used = aws.call("iam", "get-access-key-last-used", "--access-key-id", k["key_id"]).get("AccessKeyLastUsed") or {}
            rec["cross_checked"] = True
            if used.get("LastUsedDate"):
                rec["last_used"] = utc_iso(used["LastUsedDate"])
                rec["last_used_in_window"] = datetime.fromisoformat(rec["last_used"].replace("Z", "+00:00")) >= start
                region = used.get("Region")
                rec["last_used_region"] = region if region and region != "N/A" else None
                rec["last_used_region_checked"] = rec["last_used_region"] is None or rec["last_used_region"] in regions
        except AwsError:
            errors += 1
        for region in regions:
            try:
                sample, seen, truncated = lookup_key(aws, k["key_id"], region, start, now)
            except AwsError:
                errors += 1
                continue
            rec["events_found"] += seen
            rec["events_truncated"] = rec["events_truncated"] or truncated
            events.extend(sample)
            if seen:
                break  # proven; no need to search the other regions
        keys.append(rec)

    if root:
        rec = {"principal_type": "root", "principal": "root", "key_suffix": None, "active": True, "last_used": None,
               "last_used_in_window": False, "last_used_region": None, "last_used_region_checked": True,
               "cross_checked": False, "events_found": 0, "events_truncated": False}
        for region in regions:
            try:
                sample, found, resolved = lookup_root(aws, region, start, now)
            except AwsError:
                errors += 1
                continue
            if not resolved:
                errors += 1  # could not rule out use of a root key
            rec["events_found"] += found
            events.extend(sample)
            if found:
                break
        keys.append(rec)

    stamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "assessment_requirement": ar,
        "generated_at": stamp,
        "target": target,
        "target_type": "aws-account",
        "collection": {
            "complete": errors == 0, "source": SOURCE, "window_days": window_days,
            "window_start": utc_iso(start.timestamp()), "window_end": stamp, "regions": regions,
            "keys_checked": len(keys), "lookup_errors": errors, "limitations": LIMITATIONS, "generated_at": stamp,
        },
        "keys": keys,
        "events": sorted(events, key=lambda e: e["time"], reverse=True),
    }


def window_days_arg(value: str) -> int:
    n = int(value)
    if not 1 <= n <= MAX_WINDOW_DAYS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_WINDOW_DAYS} (CloudTrail event history keeps 90 days)")
    return n


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--ar", required=True)
    ap.add_argument("--target", required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--window-days", type=window_days_arg, default=30)
    ap.add_argument("--regions", default=HOME_REGION, help="comma or space separated; us-east-1 is always included")
    args = ap.parse_args()
    regions = [r for r in re.split(r"[,\s]+", args.regions) if r]
    try:
        print(json.dumps(collect(Aws(args.profile), args.ar, args.target, args.window_days, regions), indent=2))
    except (CollectionError, AwsError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
