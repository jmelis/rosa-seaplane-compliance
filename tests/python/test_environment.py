import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import environment  # noqa: E402


class Environments(unittest.TestCase):
    def test_shipped_environments(self):
        self.assertEqual(environment.available(), ["integration", "stage"])

    def test_profile_var_names(self):
        self.assertEqual(environment.profile_var("integration", "regional"), "RSC_AWS_PROFILE_INTEGRATION_REGIONAL")
        self.assertEqual(environment.profile_var("stage", "management-cluster"),
                         "RSC_AWS_PROFILE_STAGE_MANAGEMENT_CLUSTER")

    def test_default_is_integration(self):
        self.assertEqual(environment.load(environ={})["name"], "integration")

    def test_stage_differs_only_in_profiles(self):
        environ = {"RSC_AWS_PROFILE_INTEGRATION_REGIONAL": "p-int", "RSC_AWS_PROFILE_STAGE_REGIONAL": "p-stg"}
        a = environment.load("integration", environ)
        b = environment.load("stage", environ)
        strip = lambda env: [{k: v for k, v in acc.items() if k not in ("profile", "profile_var")}
                             for acc in env["accounts"]]
        self.assertEqual(strip(a), strip(b))
        self.assertEqual(a["regions"], b["regions"])
        self.assertEqual({x["name"]: x["profile"] for x in a["accounts"]}["regional"], "p-int")
        self.assertEqual({x["name"]: x["profile"] for x in b["accounts"]}["regional"], "p-stg")

    def test_unset_profile_is_none(self):
        env = environment.load("integration", {})
        self.assertTrue(all(a["profile"] is None for a in env["accounts"]))

    def test_rsc_env_selects_environment(self):
        self.assertEqual(environment.load(environ={"RSC_ENV": "stage"})["name"], "stage")

    def test_unknown_or_hostile_name_rejected(self):
        for bad in ("prod", "../x", "Integration", ""):
            if bad == "":
                continue
            with self.assertRaises(environment.EnvironmentError_):
                environment.load(bad, {})

    def test_configs_hold_no_identifiers(self):
        import re
        for p in (ROOT / "config/environments").glob("*.yaml"):
            text = p.read_text()
            self.assertIsNone(re.search(r"[0-9]{12}|arn:aws", text), p.name)
            self.assertNotIn("profile:", text)


if __name__ == "__main__":
    unittest.main()
