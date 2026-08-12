import subprocess
import os
import tempfile
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

    def test_bootstrap_cache_busts_branch_archive_download(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            source = temporary / "fixture" / "AdguardHomeDoH-main" / "deploy"
            source.mkdir(parents=True)
            installer = source / "install.sh"
            installer.write_text("#!/bin/sh\nprintf 'installer ok\\n'\n", encoding="utf-8")
            installer.chmod(0o755)
            archive = temporary / "fixture.tar.gz"
            subprocess.run(
                ["tar", "-czf", str(archive), "AdguardHomeDoH-main"],
                cwd=temporary / "fixture", check=True,
            )
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            url_log = temporary / "url"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/bin/sh\n"
                "set -eu\n"
                "url=\noutput=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  case \"$1\" in\n"
                "    https://*) url=$1; shift ;;\n"
                "    -o) output=$2; shift 2 ;;\n"
                "    *) shift ;;\n"
                "  esac\n"
                "done\n"
                "printf '%s\\n' \"$url\" > \"$ADGUARDHOME_DOH_TEST_URL_LOG\"\n"
                "cp \"$ADGUARDHOME_DOH_TEST_ARCHIVE\" \"$output\"\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)
            env = dict(os.environ)
            env.update({
                "PATH": f"{fake_bin}:{env['PATH']}",
                "ADGUARDHOME_DOH_CACHE_BUSTER": "fixed-nonce",
                "ADGUARDHOME_DOH_TEST_ARCHIVE": str(archive),
                "ADGUARDHOME_DOH_TEST_URL_LOG": str(url_log),
            })
            result = subprocess.run(
                [str(ROOT / "bootstrap.sh")], env=env, text=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("installer ok\n", result.stdout)
            self.assertEqual(
                "https://codeload.github.com/evgenykhripach/AdguardHomeDoH/"
                "tar.gz/main?cache=fixed-nonce\n",
                url_log.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
