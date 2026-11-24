#!/usr/bin/env python3
"""Create, inspect or delete the compliance read-only role in one AWS account.

The role and every permission it needs are defined in
config/aws/compliance-readonly-role.yaml. This script applies that file to the
account an AWS profile points at. It is a stopgap until the role lives in the
platform's Terraform.

    aws_readonly_role.py plan   --profile P     show what would change (no writes)
    aws_readonly_role.py apply  --profile P --yes   create or update the role
    aws_readonly_role.py verify --profile P     assume the role and prove it reads
                                                and cannot write
    aws_readonly_role.py delete --profile P --yes   remove the role

`plan` is the default and never writes. Output never includes account IDs: they are
masked, and the profile must be an administrator for `apply` and `delete`.
"""
import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
DEFINITION = ROOT / "config/aws/compliance-readonly-role.yaml"
ID_RE = re.compile(r"[0-9]{12}")
WRITE_PROBES = ["iam:CreateUser", "iam:AttachRolePolicy", "s3:PutObject", "ec2:TerminateInstances"]


class DefinitionError(ValueError):
    pass


def mask(text: str) -> str:
    return ID_RE.sub("<ID>", text)


def load_definition(path: Path = DEFINITION) -> dict:
    d = yaml.safe_load(Path(path).read_text()) or {}
    if ID_RE.search(Path(path).read_text()) or "arn:aws:iam::" in "".join(
            line for line in Path(path).read_text().splitlines() if not line.lstrip().startswith("#")
            and "arn:aws:iam::aws:policy" not in line):
        raise DefinitionError("the role definition must not contain account IDs or account-scoped ARNs")
    for key in ("role-name", "trust", "managed-policies", "actions"):
        if key not in d:
            raise DefinitionError(f"missing {key}")
    if d["trust"] != "same-account":
        raise DefinitionError("only trust: same-account is supported")
    for p in d["managed-policies"]:
        if not p.get("arn", "").startswith("arn:aws:iam::aws:policy/") or not p.get("needed-by"):
            raise DefinitionError(f"managed policy needs an AWS-managed arn and needed-by: {p}")
    for a in d["actions"]:
        if not re.fullmatch(r"[a-z0-9-]+:[A-Za-z*]+", a.get("action", "")) or not a.get("needed-by"):
            raise DefinitionError(f"action needs service:Action and needed-by: {a}")
        if not re.match(r"(?:[a-z0-9-]+:)(Get|List|Describe|Lookup|Generate|View|Batch)", a["action"].replace("*", "")):
            raise DefinitionError(f"{a['action']} does not look read-only")
    return d


def trust_policy(account_id: str) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"}, "Action": "sts:AssumeRole"}]}


def inline_policy(d: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": [{
        "Sid": "ExplicitReadOnly", "Effect": "Allow", "Action": sorted({a["action"] for a in d["actions"]}), "Resource": "*"}]}


def aws(profile: str, *args: str, check: bool = True) -> str:
    cmd = ["aws", "--profile", profile, "--output", "json", *args]
    res = subprocess.run(cmd, capture_output=True, text=True, env={**__import__("os").environ, "AWS_PAGER": ""})
    if res.returncode != 0:
        if check:
            raise SystemExit("ERROR: " + mask(res.stderr.strip() or res.stdout.strip()))
        return ""
    return res.stdout


def account_id(profile: str) -> str:
    return json.loads(aws(profile, "sts", "get-caller-identity"))["Account"]


def existing(profile: str, name: str):
    out = aws(profile, "iam", "get-role", "--role-name", name, check=False)
    return json.loads(out)["Role"] if out else None


def cmd_plan(args, d) -> None:
    acct = account_id(args.profile)
    role = existing(args.profile, d["role-name"])
    print(f"profile {args.profile}: account <ID>")
    print(f"role {d['role-name']}: {'EXISTS' if role else 'does not exist'}")
    print("would apply:")
    print("  trust policy: same-account root principal (account filled in at apply time)")
    for p in d["managed-policies"]:
        print(f"  attach {p['arn']}")
    print(f"  inline policy ExplicitReadOnly: {', '.join(sorted(a['action'] for a in d['actions']))}")
    print(f"  tags: {d.get('tags', {})}")
    print("No changes made (plan only).")
    del acct


def cmd_apply(args, d) -> None:
    if not args.yes:
        raise SystemExit("ERROR: refusing to write without --yes (run `plan` first)")
    acct = account_id(args.profile)
    name = d["role-name"]
    tags = [f"Key={k},Value={v}" for k, v in d.get("tags", {}).items()]
    if existing(args.profile, name):
        aws(args.profile, "iam", "update-assume-role-policy", "--role-name", name,
            "--policy-document", json.dumps(trust_policy(acct)))
        aws(args.profile, "iam", "update-role", "--role-name", name, "--max-session-duration", str(d["max-session-seconds"]))
        print(f"updated role {name} in <ID>")
    else:
        aws(args.profile, "iam", "create-role", "--role-name", name, "--description", d["description"],
            "--max-session-duration", str(d["max-session-seconds"]),
            "--assume-role-policy-document", json.dumps(trust_policy(acct)), "--tags", *tags)
        print(f"created role {name} in <ID>")
    for p in d["managed-policies"]:
        aws(args.profile, "iam", "attach-role-policy", "--role-name", name, "--policy-arn", p["arn"])
    aws(args.profile, "iam", "put-role-policy", "--role-name", name, "--policy-name", "ExplicitReadOnly",
        "--policy-document", json.dumps(inline_policy(d)))
    print("attached managed policies and the inline policy. Run `verify` next.")


def cmd_verify(args, d) -> None:
    acct = account_id(args.profile)
    arn = f"arn:aws:iam::{acct}:role/{d['role-name']}"
    role = existing(args.profile, d["role-name"])
    if not role:
        raise SystemExit("ERROR: the role does not exist; run apply first")
    # Write probes use the policy simulator from the admin session: nothing is executed.
    sim = json.loads(aws(args.profile, "iam", "simulate-principal-policy", "--policy-source-arn", arn,
                         "--action-names", *WRITE_PROBES))
    allowed = [r["EvalActionName"] for r in sim["EvaluationResults"] if r["EvalDecision"] == "allowed"]
    print("write probes the role would be allowed (must be none):", allowed or "none")
    if allowed:
        raise SystemExit("ERROR: the role can write; refusing to call it read-only")
    creds = json.loads(aws(args.profile, "sts", "assume-role", "--role-arn", arn,
                           "--role-session-name", "rsc-verify", "--duration-seconds", "900"))["Credentials"]
    env = {**__import__("os").environ, "AWS_ACCESS_KEY_ID": creds["AccessKeyId"], "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
           "AWS_SESSION_TOKEN": creds["SessionToken"], "AWS_PAGER": "", "AWS_PROFILE": ""}
    env.pop("AWS_PROFILE")
    checks = [("iam generate-credential-report", ["iam", "generate-credential-report"]),
              ("cloudtrail lookup-events", ["cloudtrail", "lookup-events", "--max-results", "1", "--region", "us-east-1"]),
              ("iam list-users", ["iam", "list-users", "--max-items", "1"])]
    bad = False
    for label, a in checks:
        res = subprocess.run(["aws", *a, "--output", "json"], capture_output=True, text=True, env=env)
        ok = res.returncode == 0
        bad = bad or not ok
        print(f"  {'ok  ' if ok else 'FAIL'} {label}" + ("" if ok else f": {mask(res.stderr.strip())[:160]}"))
    if bad:
        raise SystemExit("ERROR: the role cannot do something it needs")
    print("verified: reads work, writes are not allowed.")


def cmd_delete(args, d) -> None:
    if not args.yes:
        raise SystemExit("ERROR: refusing to write without --yes")
    name = d["role-name"]
    if not existing(args.profile, name):
        print("role does not exist; nothing to do")
        return
    for p in json.loads(aws(args.profile, "iam", "list-attached-role-policies", "--role-name", name))["AttachedPolicies"]:
        aws(args.profile, "iam", "detach-role-policy", "--role-name", name, "--policy-arn", p["PolicyArn"])
    for n in json.loads(aws(args.profile, "iam", "list-role-policies", "--role-name", name))["PolicyNames"]:
        aws(args.profile, "iam", "delete-role-policy", "--role-name", name, "--policy-name", n)
    aws(args.profile, "iam", "delete-role", "--role-name", name)
    print(f"deleted role {name}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["plan", "apply", "verify", "delete"])
    ap.add_argument("--profile", required=True)
    ap.add_argument("--yes", action="store_true", help="required for apply and delete")
    args = ap.parse_args()
    try:
        d = load_definition()
    except DefinitionError as e:
        sys.exit(f"ERROR: {e}")
    {"plan": cmd_plan, "apply": cmd_apply, "verify": cmd_verify, "delete": cmd_delete}[args.command](args, d)


if __name__ == "__main__":
    main()
