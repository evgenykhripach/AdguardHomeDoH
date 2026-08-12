import hashlib
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from deploy.lib.releases import download, parse_release, parse_semver, verify_archive


class ReleaseTests(unittest.TestCase):
    def test_download_sends_asset_headers(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"asset"
        with mock.patch("deploy.lib.releases.urlopen", return_value=response) as opener:
            self.assertEqual(b"asset", download("https://example.invalid/asset"))
        request = opener.call_args.args[0]
        self.assertEqual("application/octet-stream", request.get_header("Accept"))
        self.assertEqual("adguardhome-doh-updater", request.get_header("User-agent"))
    def test_semver_and_stable_release_validation(self):
        version = parse_semver("v1.2.3")
        self.assertEqual((1, 2, 3), (version.major, version.minor, version.patch))
        with self.assertRaises(ValueError):
            parse_semver("v1.2")
        release = parse_release({
            "tag_name": "v1.2.3", "draft": False, "prerelease": False,
            "assets": [
                {"name": "adguardhome-doh.tar.gz", "browser_download_url": "archive"},
                {"name": "adguardhome-doh.tar.gz.sha256", "browser_download_url": "checksum"},
            ],
        })
        self.assertEqual("1.2.3", release.version.text())

    def test_archive_checksum_and_version_are_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "adguardhome-doh-1.0.0"
            for relative in ("VERSION", "bootstrap.sh", "deploy/install.sh", "deploy/manage.py",
                             "config/services.csv", "config/domains.csv",
                             "config/service-domains.csv", "config/service-probes.csv"):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("1.0.0\n" if relative == "VERSION" else "ok\n", encoding="utf-8")
            archive = root / "adguardhome-doh.tar.gz"
            subprocess.run(["tar", "-czf", str(archive), source.name], cwd=root, check=True)
            checksum = root / "adguardhome-doh.tar.gz.sha256"
            checksum.write_text("%s  adguardhome-doh.tar.gz\n" %
                                hashlib.sha256(archive.read_bytes()).hexdigest(), encoding="utf-8")
            self.assertTrue(any(item.endswith("/VERSION") or item == "VERSION"
                                for item in verify_archive(archive, checksum, version="1.0.0")))
            checksum.write_text("0" * 64 + "  adguardhome-doh.tar.gz\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                verify_archive(archive, checksum, version="1.0.0")


if __name__ == "__main__":
    unittest.main()
