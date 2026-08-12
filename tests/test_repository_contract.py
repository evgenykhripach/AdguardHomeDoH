import hashlib
import os
import subprocess
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
            "deploy/bin/build-sniproxy.sh", "deploy/templates/sniproxy.service.tmpl",
            "tools/validator.py", "inventory.production.json",
        ):
            self.assertFalse((ROOT / relative).exists(), relative)

    def test_bootstrap_uses_latest_stable_release_and_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            source_root = temporary / "fixture" / "adguardhome-doh-1.0.0"
            source = source_root / "deploy"
            source.mkdir(parents=True)
            installer = source / "install.sh"
            installer.write_text("#!/bin/sh\nprintf 'installer ok\\n'\n", encoding="utf-8")
            installer.chmod(0o755)
            for relative in (
                "VERSION", "bootstrap.sh", "deploy/manage.py", "config/services.csv",
                "config/domains.csv", "config/service-domains.csv", "config/service-probes.csv",
            ):
                path = source_root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("1.0.0\n" if relative == "VERSION" else "fixture\n", encoding="utf-8")
            archive = temporary / "fixture.tar.gz"
            subprocess.run(["tar", "-czf", str(archive), "adguardhome-doh-1.0.0"],
                           cwd=temporary / "fixture", check=True)
            checksum = temporary / "fixture.sha256"
            checksum.write_text("%s  adguardhome-doh.tar.gz\n" %
                                hashlib.sha256(archive.read_bytes()).hexdigest(), encoding="utf-8")
            metadata = temporary / "release.json"
            metadata.write_text(
                '{"tag_name":"v1.0.0","draft":false,"prerelease":false,"assets":['
                '{"name":"adguardhome-doh.tar.gz","browser_download_url":"https://fixture/archive"},'
                '{"name":"adguardhome-doh.tar.gz.sha256","browser_download_url":"https://fixture/checksum"}]}',
                encoding="utf-8",
            )
            fake_bin = temporary / "bin"
            fake_bin.mkdir()
            url_log = temporary / "url"
            fake_curl = fake_bin / "curl"
            fake_curl.write_text(
                "#!/bin/sh\nset -eu\nurl=\noutput=\n"
                "while [ \"$#\" -gt 0 ]; do case \"$1\" in https://*) url=$1; shift;; -o) output=$2; shift 2;; *) shift;; esac; done\n"
                "printf '%s\\n' \"$url\" >> \"$ADGUARDHOME_DOH_TEST_URL_LOG\"\n"
                "case \"$url\" in *api.github.com*) cp \"$ADGUARDHOME_DOH_TEST_METADATA\" \"$output\";; *checksum) cp \"$ADGUARDHOME_DOH_TEST_CHECKSUM\" \"$output\";; *) cp \"$ADGUARDHOME_DOH_TEST_ARCHIVE\" \"$output\";; esac\n",
                encoding="utf-8",
            )
            fake_curl.chmod(0o755)
            env = dict(os.environ)
            env.update({
                "PATH": f"{fake_bin}:{env['PATH']}",
                "ADGUARDHOME_DOH_TEST_ARCHIVE": str(archive),
                "ADGUARDHOME_DOH_TEST_CHECKSUM": str(checksum),
                "ADGUARDHOME_DOH_TEST_METADATA": str(metadata),
                "ADGUARDHOME_DOH_TEST_URL_LOG": str(url_log),
            })
            result = subprocess.run([str(ROOT / "bootstrap.sh")], env=env,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual("installer ok\n", result.stdout)
            self.assertEqual(
                "https://api.github.com/repos/evgenykhripach/AdguardHomeDoH/releases/latest\n"
                "https://fixture/archive\nhttps://fixture/checksum\n",
                url_log.read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
