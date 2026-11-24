#!/usr/bin/env python3
"""Load an environment definition (config/environments/<name>.yaml).

The definition holds regions, logical account names and where each account's ID
sits in the platform's account snapshot, and nothing sensitive. AWS access for it
is set up by scripts/aws_access.py.

    environment.py [name]               print the environment (default: $RSC_ENV or
                                        integration) and whether its accounts can be resolved
    environment.py --accounts [name]    print only the logical account names, one per line
"""
import os
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
ENV_DIR = ROOT / "config/environments"
DEFAULT_ENV = "integration"


class EnvironmentError_(ValueError):
    pass


def available(env_dir: Path = ENV_DIR) -> list:
    return sorted(p.stem for p in env_dir.glob("*.yaml"))


def load(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> dict:
    """{name, regions, snapshot, saml_role, accounts: [{name, snapshot_path}]}."""
    environ = os.environ if environ is None else environ
    name = name or environ.get("RSC_ENV") or DEFAULT_ENV
    path = env_dir / f"{name}.yaml"
    if not re.fullmatch(r"[a-z0-9-]+", name) or not path.is_file():
        raise EnvironmentError_(f"unknown environment {name!r}; available: {', '.join(available(env_dir))}")
    doc = yaml.safe_load(path.read_text()) or {}
    if doc.get("name") != name:
        raise EnvironmentError_(f"{path.name}: name must be {name!r}")
    for key in ("snapshot", "saml-role", "accounts"):
        if not doc.get(key):
            raise EnvironmentError_(f"{path.name}: missing {key}")
    if not re.fullmatch(r"[a-z0-9-]+", str(doc["snapshot"])):
        raise EnvironmentError_(f"{path.name}: bad snapshot name")
    accounts = []
    for account, spec in doc["accounts"].items():
        if not re.fullmatch(r"[a-z0-9-]+", account) or not (spec or {}).get("snapshot-path"):
            raise EnvironmentError_(f"{path.name}: account {account!r} needs a name and a snapshot-path")
        accounts.append({"name": account, "snapshot_path": spec["snapshot-path"]})
    return {"name": name, "regions": list(doc.get("regions") or []), "snapshot": doc["snapshot"],
            "saml_role": doc["saml-role"], "accounts": accounts}


def account_names(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> list:
    """Logical account names of an environment: what checks must reach (never IDs)."""
    return [a["name"] for a in load(name, environ, env_dir)["accounts"]]


def main() -> None:
    args = [a for a in sys.argv[1:] if a not in ("--accounts", "--regions")]
    if "--regions" in sys.argv[1:]:
        try:
            print(",".join(load(args[0] if args else None)["regions"]))
        except EnvironmentError_ as e:
            sys.exit(f"ERROR: {e}")
        return
    if "--accounts" in sys.argv[1:]:
        try:
            print("\n".join(a["name"] for a in load(args[0] if args else None)["accounts"]))
        except EnvironmentError_ as e:
            sys.exit(f"ERROR: {e}")
        return
    import aws_access
    try:
        env = load(args[0] if args else None)
        status = aws_access.describe(env)
    except (EnvironmentError_, aws_access.AccessError) as e:
        sys.exit(f"ERROR: {e}")
    print(f"environment: {env['name']}  regions: {', '.join(env['regions'])}")
    print(f"  account snapshot: {status['snapshot']}")
    for a in env["accounts"]:
        print(f"  {a['name']:<20} {'resolvable' if status['resolved'].get(a['name']) else 'NOT FOUND in snapshot'}")


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    main()
