import importlib.util
import json
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path


FORKCTL_PATH = Path(__file__).resolve().parents[1] / "forkctl"
SPEC = importlib.util.spec_from_loader("forkctl", SourceFileLoader("forkctl", str(FORKCTL_PATH)))
forkctl = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules["forkctl"] = forkctl
SPEC.loader.exec_module(forkctl)


class ForkctlTests(unittest.TestCase):
    def test_component_registry_has_expected_components(self):
        names = [component.name for component in forkctl.COMPONENTS]
        self.assertEqual(len(names), 11)
        self.assertEqual(len(set(names)), 11)
        self.assertIn("openvas-scanner", names)
        self.assertIn("gvm-tools", names)

    def test_aggregate_status_prefers_highest_severity(self):
        findings = [
            {"status": "pass"},
            {"status": "warn"},
            {"status": "fail"},
        ]
        self.assertEqual(forkctl.aggregate_status(findings), "fail")

    def test_result_json_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = forkctl.make_result("status", root, "summary", [{"status": "pass", "check": "x", "message": "ok"}])
            encoded = json.dumps(result)
            decoded = json.loads(encoded)
            self.assertEqual(decoded["status"], "pass")
            self.assertIn("summary", decoded)
            self.assertIn("findings", decoded)
            self.assertIn("artifacts", decoded)
            self.assertIn("metadata", decoded)

    def test_inventory_reports_missing_components(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = forkctl.command_inventory(root)
            self.assertEqual(result["status"], "fail")
            missing = [item for item in result["findings"] if item["status"] == "fail"]
            self.assertEqual(len(missing), 11)

    def test_nested_git_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            nested = root / "components" / "example" / ".git"
            nested.mkdir(parents=True)
            self.assertEqual(forkctl.nested_git_dirs(root), ["components/example/.git"])


if __name__ == "__main__":
    unittest.main()
