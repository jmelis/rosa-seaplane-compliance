import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("entrypoint", ROOT / "containers/complyctl/entrypoint.py")
entrypoint = importlib.util.module_from_spec(spec)
spec.loader.exec_module(entrypoint)

AR1, AR2 = "RSC.CMT.CTRL01.AR01", "RSC.CMT.CTRL01.AR02"


def write(root: Path, ar: str, declared: str, name="evidence.json"):
    d = root / ar
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps({"assessment_requirement": declared}))


class MissingEvidence(unittest.TestCase):
    def test_all_present(self):
        with tempfile.TemporaryDirectory() as t:
            write(Path(t), AR1, AR1)
            write(Path(t), AR2, AR2)
            self.assertEqual(entrypoint.missing_evidence([AR1, AR2], Path(t)), [])

    def test_missing_directory_is_reported(self):
        with tempfile.TemporaryDirectory() as t:
            write(Path(t), AR1, AR1)
            self.assertEqual(entrypoint.missing_evidence([AR1, AR2], Path(t)), [AR2])

    def test_empty_directory_is_reported(self):
        with tempfile.TemporaryDirectory() as t:
            (Path(t) / AR1).mkdir()
            self.assertEqual(entrypoint.missing_evidence([AR1], Path(t)), [AR1])

    def test_evidence_declaring_another_ar_does_not_count(self):
        with tempfile.TemporaryDirectory() as t:
            write(Path(t), AR1, AR2)
            self.assertEqual(entrypoint.missing_evidence([AR1], Path(t)), [AR1])

    def test_unparseable_evidence_does_not_count(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t) / AR1
            d.mkdir()
            (d / "evidence.json").write_text("not json")
            self.assertEqual(entrypoint.missing_evidence([AR1], Path(t)), [AR1])


class PolicyArs(unittest.TestCase):
    def test_reads_ars_from_policies(self):
        import os
        cwd = os.getcwd()
        os.chdir(ROOT)
        try:
            self.assertEqual(entrypoint.policy_ars(), [AR1, AR2])
        finally:
            os.chdir(cwd)


if __name__ == "__main__":
    unittest.main()
