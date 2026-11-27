#!/usr/bin/env python3
"""Build this run's RUN RECORD from the outputs of a run and append it to the history.

One record per run, with one entry per KSI per automated method (a method is an
assessment requirement, AR). A record is about ONE UTC day (`covers_date`, the half-open
interval [D 00:00:00Z, D+1 00:00:00Z)), which is not when the run happened. It is what a day's evidence looks like in the series that
the Class C rules ask for (SDR-CSX-KMT: daily metric data including the status of
persistent validation, up to a year). The record holds results and counts, never the
raw evidence, no account IDs or ARNs, no emails, no PR or event payloads. The
evidence it describes is pinned by a hash (`evidence_sha256`).

RESULT SEMANTICS (the same everywhere: README, the summaries, the viewer):
  pass   the collection is complete, every expected target was reached and there is
         no violation.
  fail   at least one violation. It wins over `error`: a known problem is reported even
         when part of the collection could not be judged (`incomplete` still counts it).
  error  the check could NOT be judged: evidence missing or incomplete, a target not
         reached, a collection error. Never `pass`, and never omitted: a method whose AR
         has no evidence at all in this run is an `error`.
  not_collected  this method cannot honestly be produced for that day. Only a BACKFILL
         (a run explicitly made for a past day) has them: it cannot reconstruct past
         state, so it never uses today's state as that day's (that would be a result
         rewritten after the fact). Never a pass.

BASIS (config/history/ar-basis.yaml): an `event` method judges items timestamped inside the
day (PR merges, key-usage events, pipeline executions) and can be recovered for any past day;
a `state` method judges the present at collection time (configuration, existing keys, health)
and records `collected_at`. An event method may declare `state_rules`, rules that read the
present: a backfill ignores them.

DATE: until the collectors take a date (the next step), a run covers the UTC day it is run
on, with the windows the collectors really used (recorded per method); an explicit DATE for a
past day is refused rather than mislabelling a run.

Built from existing outputs only (output/coverage.json, output/trace.json,
output/findings.json, the evidence manifests); it refuses to run when they are missing,
older than the evidence they describe, or when that evidence is too old to call a run.

    build_record.py [--date YYYY-MM-DD] [--check-date-only] [--no-append] [--max-evidence-age-hours N]
"""
import argparse
import hashlib
import json
import re
import subprocess
import sys
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

import history  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_FILE = ROOT / "schemas/run-record.schema.json"
SCHEMA_VERSION = 1
TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
KINDS = ("intent", "behavioral")
BASES = ("event", "state")
BASIS_FILE = ROOT / "config/history/ar-basis.yaml"
LEAK_PATTERNS = (r"/Users/", r"file://", r"(?<![0-9])[0-9]{12}(?![0-9])", r"arn:aws", r"[\w.+-]+@[\w-]+\.[\w.-]+")
POLICY_GLOBS = ("opa/*/policy/*.rego", "gemara/*/*.yaml", "mappings/*.mapping.yaml",
                "config/findings/rules.yaml", "config/prowler/checks.yaml", "schemas/*")
DEFAULT_MAX_EVIDENCE_AGE_HOURS = 24


class RecordError(RuntimeError):
    pass


def parse_ts(text: str) -> datetime:
    return datetime.strptime(text, TS_FMT).replace(tzinfo=timezone.utc)


def fmt_ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(TS_FMT)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def tree_hash(files: list, root: Path) -> str:
    """One hash over a set of files: their relative names and their own hashes, sorted."""
    lines = sorted(f"{p.relative_to(root).as_posix()} {sha256_file(p)}" for p in files)
    return hashlib.sha256(("\n".join(lines) + "\n").encode()).hexdigest()


def evidence_hash(ar_dir: Path):
    """Hash of the AR's evidence files (manifest included); None when there is none."""
    if not ar_dir.is_dir():
        return None
    files = [p for p in ar_dir.iterdir() if p.is_file()]
    return tree_hash(files, ar_dir) if files else None


def load_basis(path: Path = BASIS_FILE) -> dict:
    """AR -> {basis, state_rules}, from the tracked declaration. A malformed file is an error."""
    doc = yaml.safe_load(Path(path).read_text()) or {}
    out = {}
    for ar, spec in doc.items():
        spec = spec or {}
        if spec.get("basis") not in BASES:
            raise RecordError(f"{path.name}: {ar} needs basis: event or state")
        rules = spec.get("state_rules") or []
        if rules and spec["basis"] != "event":
            raise RecordError(f"{path.name}: {ar} is a state AR, so it has no state_rules")
        if not isinstance(rules, list) or not all(isinstance(x, str) for x in rules):
            raise RecordError(f"{path.name}: {ar}: state_rules must be a list of rule ids")
        out[ar] = {"basis": spec["basis"], "state_rules": set(rules)}
    return out


def resolve_covers_date(requested, now: datetime):
    """(covers_date, backfill) for a run. Until the collectors take a date, a run covers the day
    it runs on; a past date is refused instead of mislabelling a run made with today's window."""
    today = now.astimezone(timezone.utc).date()
    if requested in (None, ""):
        return today.isoformat(), False
    try:
        day = date.fromisoformat(requested)
    except ValueError:
        raise RecordError(f"DATE must be YYYY-MM-DD, not {requested!r}") from None
    if day == today:
        return day.isoformat(), False
    if day > today:
        raise RecordError(f"DATE {requested} is in the future")
    raise RecordError(f"DATE {requested} is a past day: a backfill arrives with the next step, when the collectors take a "
                      "date. Refusing to label a run made with the current window as that day.")


def collected_at(ar_dir: Path):
    """When a state method looked at the system: the newest `generated_at` in its evidence."""
    newest = None
    for _name, doc in evidence_files(ar_dir):
        if not isinstance(doc, dict):
            continue
        gen = doc.get("generated_at") or (doc.get("collection") or {}).get("generated_at")
        try:
            t = parse_ts(gen) if gen else None
        except ValueError:
            t = None
        newest = t if t is not None and (newest is None or t > newest) else newest
    return fmt_ts(newest) if newest else None


def policy_hash(root: Path) -> str:
    """Identity of the rules that produced the verdicts: the policies, catalogs, mappings,
    findings catalog and schemas, hashed together."""
    files = sorted({p for g in POLICY_GLOBS for p in root.glob(g) if p.is_file()})
    return tree_hash(files, root)


def evidence_files(ar_dir: Path) -> list:
    out = []
    if ar_dir.is_dir():
        for p in sorted(ar_dir.glob("*.json")):
            try:
                out.append((p.name, json.loads(p.read_text())))
            except ValueError:
                out.append((p.name, None))
    return out


def ar_window(ar_dir: Path):
    """The period an AR's evidence covers, when it has one: {start, end} from each file's
    generated_at and its window (days or minutes). None for state checks."""
    starts, ends = [], []
    for name, doc in evidence_files(ar_dir):
        if name == "manifest.json" or not isinstance(doc, dict):
            continue
        coll = doc.get("collection") if isinstance(doc.get("collection"), dict) else {}
        span = None
        for key, unit in (("window_days", "days"), ("window_hours", "hours"), ("window_minutes", "minutes")):
            val = doc.get(key, coll.get(key))
            if isinstance(val, (int, float)) and val > 0:
                span = timedelta(**{unit: val})
                break
        gen = doc.get("generated_at") or coll.get("generated_at")
        if span is None or not gen:
            continue
        try:
            end = parse_ts(gen)
        except ValueError:
            continue
        starts.append(end - span)
        ends.append(end)
    if not starts:
        return None
    return {"start": fmt_ts(min(starts)), "end": fmt_ts(max(ends))}


def evidence_incomplete(ar_dir: Path) -> bool:
    """A collector that says its own collection is incomplete, whatever else was found."""
    for name, doc in evidence_files(ar_dir):
        if name == "manifest.json":
            continue
        if doc is None:
            return True
        coll = doc.get("collection") if isinstance(doc.get("collection"), dict) else {}
        if coll.get("complete") is False:
            return True
    return False


def newest_evidence_time(evidence_dir: Path):
    """Newest `generated_at` in any manifest or evidence file under the evidence dir."""
    newest = None
    for p in evidence_dir.glob("*/*.json"):
        try:
            doc = json.loads(p.read_text())
        except ValueError:
            continue
        gen = (doc or {}).get("generated_at") if isinstance(doc, dict) else None
        if not gen:
            continue
        try:
            t = parse_ts(gen)
        except ValueError:
            continue
        newest = t if newest is None or t > newest else newest
    return newest


def check_fresh(outputs: dict, evidence_dir: Path, now: datetime, max_age_hours) -> None:
    """Refuse to build a record from outputs older than the evidence they describe, or from
    evidence too old to be called this run. `outputs` maps a name to its generated_at."""
    newest = newest_evidence_time(evidence_dir)
    if newest is None:
        raise RecordError(f"no evidence found in {evidence_dir}: run `make run-local` first")
    for name, gen in outputs.items():
        if not gen:
            raise RecordError(f"{name} has no generation time: rebuild it")
        if parse_ts(gen) < newest:
            raise RecordError(f"{name} is older than the evidence it should describe: rebuild it "
                              "(`make findings trace`, or run `make daily`)")
    if max_age_hours is not None and now - newest > timedelta(hours=max_age_hours):
        raise RecordError(f"the newest evidence is from {fmt_ts(newest)}, over {max_age_hours} hours old: "
                          "run `make run-local` again, or raise --max-evidence-age-hours")


def method_outcome(violations: int, incomplete: int, flags: list) -> str:
    """fail > error > pass. `flags` are reasons the check could not be judged."""
    if violations > 0:
        return "fail"
    if incomplete > 0 or flags:
        return "error"
    return "pass"


def build_methods(coverage: dict, trace: dict, findings: dict, evidence_dir: Path, basis: dict, backfill: bool = False) -> list:
    methods = []
    for ksi in sorted(coverage["ksis"], key=lambda k: k["id"]):
        for m in sorted(ksi["methods"], key=lambda m: m["ar"]):
            if not m.get("implemented"):
                continue
            ar = m["ar"]
            info = basis.get(ar)
            if info is None:
                raise RecordError(f"{ar} has no basis: declare it (event or state) in config/history/ar-basis.yaml")
            kind = (m.get("kind") or "").lower()
            entry = {"ksi": ksi["id"], "ar": ar, "method_kind": kind if kind in KINDS else "other", "basis": info["basis"]}
            if backfill and info["basis"] == "state":
                # The past state of a system cannot be reconstructed: never use today's as that day's.
                entry.update({"result": "not_collected", "violations": 0, "incomplete": 0, "targets_expected": 0,
                              "targets_reached": 0, "window": None, "collected_at": None, "evidence_sha256": None,
                              "rules_failed": []})
                methods.append(entry)
                continue
            ignore = info["state_rules"] if backfill else set()
            slot = {"violation": 0, "incomplete": 0, "rules": {}}
            for f in findings["findings"]:
                if f["ar"] != ar or f["rule"] in ignore:
                    continue
                slot["violation" if f["kind"] == "violation" else "incomplete"] += 1
                slot["rules"][f["rule"]] = slot["rules"].get(f["rule"], 0) + 1
            ar_dir = evidence_dir / ar
            scope = (trace.get("scope") or {}).get(ar) or {}
            expected = len(scope.get("expected") or [])
            reached = sum(1 for t in scope.get("targets") or [] if t.get("status") == "reached")
            digest = evidence_hash(ar_dir)
            flags = []
            if digest is None:
                flags.append("no evidence")
            if not scope.get("run"):
                flags.append("no manifest")
            if expected == 0 or reached < expected:
                flags.append("targets not reached")
            if evidence_incomplete(ar_dir):
                flags.append("evidence incomplete")
            entry.update({
                "result": method_outcome(slot["violation"], slot["incomplete"], flags),
                "violations": slot["violation"], "incomplete": slot["incomplete"],
                "targets_expected": expected, "targets_reached": min(reached, expected) if expected else reached,
                "window": ar_window(ar_dir) if info["basis"] == "event" else None,
                "collected_at": collected_at(ar_dir) if info["basis"] == "state" else None,
                "evidence_sha256": digest,
                "rules_failed": [{"rule": r, "count": c} for r, c in sorted(slot["rules"].items())],
            })
            methods.append(entry)
    return methods


def git_state(root: Path) -> dict:
    def run(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    head = run("rev-parse", "HEAD")
    if head.returncode != 0:
        raise RecordError("this is not a git checkout: cannot record the pipeline commit")
    dirty = bool(run("status", "--porcelain").stdout.strip())
    return {"commit": head.stdout.strip(), "dirty": dirty}


def tool_versions(root: Path) -> dict:
    tools = {}
    p = root / "config/prowler/checks.yaml"
    if p.is_file():
        v = (yaml.safe_load(p.read_text()) or {}).get("prowler-version")
        if v:
            tools["prowler"] = str(v)
    return tools


def assert_clean(record: dict) -> None:
    text = json.dumps(record)
    for pat in LEAK_PATTERNS:
        if re.search(pat, text):
            raise RecordError(f"the record matches a sensitive pattern ({pat}); refusing to write it")


def validate(record: dict) -> None:
    import jsonschema
    schema = json.loads(SCHEMA_FILE.read_text())
    jsonschema.Draft202012Validator(schema, format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER).validate(record)


def check_record(record: dict) -> None:
    """Schema plus the one rule a schema cannot say: a record never covers a day after it was made.
    The summaries use this to reject any stored record that is not well formed."""
    validate(record)
    if date.fromisoformat(record["covers_date"]) > parse_ts(record["recorded_at"]).date():
        raise RecordError("the record covers a day after it was recorded")


def build_record(coverage: dict, trace: dict, findings: dict, evidence_dir: Path, root: Path,
                 now: datetime, git: dict, run_id: str = None, max_age_hours=DEFAULT_MAX_EVIDENCE_AGE_HOURS,
                 covers_date: str = None, backfill: bool = False, basis: dict = None) -> dict:
    check_fresh({"output/coverage.json": coverage.get("generated_at"),
                 "output/trace.json": (trace.get("meta") or {}).get("generated_at"),
                 "output/findings.json": (findings.get("meta") or {}).get("generated_at")},
                evidence_dir, now, max_age_hours)
    covers_date = covers_date or now.astimezone(timezone.utc).date().isoformat()
    if date.fromisoformat(covers_date) > now.astimezone(timezone.utc).date():
        raise RecordError(f"covers_date {covers_date} is in the future")
    basis = load_basis() if basis is None else basis
    ev = findings["meta"]["evidence_generated_at"]
    finished = max(parse_ts(g) for g in (coverage["generated_at"], trace["meta"]["generated_at"], findings["meta"]["generated_at"]))
    record = {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id or history.new_run_id(now),
        "covers_date": covers_date,
        "backfill": bool(backfill),
        "recorded_at": fmt_ts(now),
        "started_at": ev["oldest"],
        "finished_at": fmt_ts(finished),
        "environment": coverage["environment"],
        "pipeline": git,
        "policy_sha256": policy_hash(root),
        "tools": tool_versions(root),
        "methods": build_methods(coverage, trace, findings, evidence_dir, basis, backfill),
    }
    assert_clean(record)
    check_record(record)
    return record


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--coverage", default=str(ROOT / "output/coverage.json"))
    ap.add_argument("--trace", default=str(ROOT / "output/trace.json"))
    ap.add_argument("--findings", default=str(ROOT / "output/findings.json"))
    ap.add_argument("--evidence-dir", default=str(ROOT / "evidence/output"))
    ap.add_argument("--max-evidence-age-hours", type=float, default=DEFAULT_MAX_EVIDENCE_AGE_HOURS)
    ap.add_argument("--date", default=None, help="UTC day the record covers (default: the day of the run; a past day is refused for now)")
    ap.add_argument("--check-date-only", action="store_true", help="only validate --date and exit (used by `make daily` before the long run)")
    ap.add_argument("--no-append", action="store_true", help="build and print the record, do not append it")
    args = ap.parse_args()
    try:
        now = datetime.now(timezone.utc)
        covers_date, backfill = resolve_covers_date(args.date, now)
        if args.check_date_only:
            print(f"A record made now would cover {covers_date}.")
            return
        docs = {}
        for name in ("coverage", "trace", "findings"):
            p = Path(getattr(args, name))
            if not p.is_file():
                raise RecordError(f"{p} not found: run `make daily`, or `make coverage findings trace` after `make run-local`")
            docs[name] = json.loads(p.read_text())
        record = build_record(docs["coverage"], docs["trace"], docs["findings"], Path(args.evidence_dir), ROOT,
                              now, git_state(ROOT), max_age_hours=args.max_evidence_age_hours,
                              covers_date=covers_date, backfill=backfill)
        if args.no_append:
            print(json.dumps(record, indent=2, sort_keys=True))
            return
        store = history.open_store()
        key = store.put_record(record)
        counts = {r: sum(1 for m in record["methods"] if m["result"] == r) for r in ("pass", "fail", "error", "not_collected")}
        print(f"Appended run record {record['run_id']} covering {record['covers_date']} ({len(record['methods'])} methods: "
              f"{counts['pass']} pass, {counts['fail']} fail, {counts['error']} error, {counts['not_collected']} not collected) "
              f"to {store.backend.where}{key}")
    except (RecordError, history.StoreError) as e:
        sys.exit(f"ERROR: {e}")


if __name__ == "__main__":
    main()
