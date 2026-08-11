import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RepositoryContractTests(unittest.TestCase):
    def test_release_contract_script_passes(self):
        result = subprocess.run(
            ["python3", "tools/check_release.py"], cwd=ROOT,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("release contract: ok", result.stdout)

    def test_runtime_does_not_contain_old_sniproxy_entrypoints(self):
        for relative in (
            "deploy/bin/build-sniproxy.sh",
            "deploy/templates/sniproxy.service.tmpl",
            "tools/validator.py",
            "inventory.production.json",
        ):
            self.assertFalse((ROOT / relative).exists(), relative)


if __name__ == "__main__":
    unittest.main()
