#!/usr/bin/env python3
"""Resolve an environment (config/environments/<name>.yaml) and its AWS profiles.

The config holds only regions and logical account names. Which AWS profile
reaches each account comes from environment variables, so nothing sensitive is
committed:

    RSC_AWS_PROFILE_<ENV>_<ACCOUNT>   e.g. RSC_AWS_PROFILE_INTEGRATION_REGIONAL

    environment.py [name]       print the resolved environment (default: $RSC_ENV
                                or integration); profile *names* are not printed
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


def profile_var(env: str, account: str) -> str:
    return "RSC_AWS_PROFILE_" + re.sub(r"[^A-Za-z0-9]", "_", f"{env}_{account}").upper()


def available(env_dir: Path = ENV_DIR) -> list:
    return sorted(p.stem for p in env_dir.glob("*.yaml"))


def load(name: str = None, environ: dict = None, env_dir: Path = ENV_DIR) -> dict:
    """{name, regions, accounts: [{name, profile_var, profile}]}; profile is None if unset."""
    environ = os.environ if environ is None else environ
    name = name or environ.get("RSC_ENV") or DEFAULT_ENV
    path = env_dir / f"{name}.yaml"
    if not re.fullmatch(r"[a-z0-9-]+", name) or not path.is_file():
        raise EnvironmentError_(f"unknown environment {name!r}; available: {', '.join(available(env_dir))}")
    doc = yaml.safe_load(path.read_text()) or {}
    if doc.get("name") != name:
        raise EnvironmentError_(f"{path.name}: name must be {name!r}")
    accounts = []
    for account in doc.get("accounts") or []:
        var = profile_var(name, account)
        accounts.append({"name": account, "profile_var": var, "profile": environ.get(var) or None})
    return {"name": name, "regions": list(doc.get("regions") or []), "accounts": accounts}


def main() -> None:
    try:
        env = load(sys.argv[1] if len(sys.argv) > 1 else None)
    except EnvironmentError_ as e:
        sys.exit(f"ERROR: {e}")
    print(f"environment: {env['name']}  regions: {', '.join(env['regions'])}")
    for a in env["accounts"]:
        state = "set" if a["profile"] else "NOT SET"
        print(f"  {a['name']:<20} {a['profile_var']} {state}")


if __name__ == "__main__":
    main()
