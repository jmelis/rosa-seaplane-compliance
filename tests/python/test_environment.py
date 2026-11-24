import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

import environment  # noqa: E402


class Environments(unittest.TestCase):
    def test_shipped_environments(self):
        self.assertEqual(environment.available(), ["integration", "stage"])

    def test_integration_shape(self):
        env = environment.load("integration", {})
        self.assertEqual((env["snapshot"], env["regions"]), ("int", ["us-east-1"]))
        self.assertEqual([a["name"] for a in env["accounts"]], ["central", "regional", "management-mc01"])
        self.assertEqual(env["saml_role"], "rosa-hyperfleet-int-admin")

    def test_stage_has_two_management_accounts(self):
        names = [a["name"] for a in environment.load("stage", {})["accounts"]]
        self.assertEqual(names, ["central", "regional", "management-mc01", "management-mc02"])

    def test_default_is_integration(self):
        self.assertEqual(environment.load(environ={})["name"], "integration")

    def test_rsc_env_selects_environment(self):
        self.assertEqual(environment.load(environ={"RSC_ENV": "stage"})["name"], "stage")

    def test_stage_differs_from_integration_only_in_data(self):
        a, b = environment.load("integration", {}), environment.load("stage", {})
        self.assertEqual(a["regions"], b["regions"])
        self.assertEqual([x["snapshot_path"] for x in a["accounts"][:2]], [x["snapshot_path"] for x in b["accounts"][:2]])

    def test_unknown_or_hostile_name_rejected(self):
        for bad in ("prod", "../x", "Integration"):
            with self.assertRaises(environment.EnvironmentError_):
                environment.load(bad, {})

    def test_configs_hold_no_identifiers_or_profile_names(self):
        import re
        for p in (ROOT / "config/environments").glob("*.yaml"):
            text = p.read_text()
            self.assertIsNone(re.search(r"[0-9]{12}|arn:aws", text), p.name)
            self.assertNotIn("profile:", text)


if __name__ == "__main__":
    unittest.main()
