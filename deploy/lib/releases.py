#!/usr/bin/env python3
"""Small, dependency-free GitHub Release validation helpers.

The bootstrapper deliberately trusts neither a tag nor an asset name until
the release metadata, archive checksum, and archive contents have all been
validated.  This module is also used by the interactive manager for update
checks, so the rules stay identical in both entry points.
"""

from __future__ import annotations

import hashlib
import json
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


SEMVER_RE = re.compile(r"^(?:v)?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
ARCHIVE_NAME = "adguardhome-doh.tar.gz"
CHECKSUM_NAME = "adguardhome-doh.tar.gz.sha256"
REQUIRED_FILES = (
    "VERSION",
    "bootstrap.sh",
    "deploy/install.sh",
    "deploy/manage.py",
    "config/services.csv",
    "config/domains.csv",
    "config/service-domains.csv",
    "config/service-probes.csv",
)


@dataclass(frozen=True, order=True)
class Version:
    major: int
    minor: int
    patch: int
    prerelease: str = ""

    @property
    def stable(self) -> bool:
        return not self.prerelease

    def text(self) -> str:
        return "%d.%d.%d%s" % (
            self.major, self.minor, self.patch,
            ("-" + self.prerelease) if self.prerelease else "",
        )


@dataclass(frozen=True)
class Release:
    version: Version
    tag: str
    archive_url: str
    checksum_url: str


def parse_semver(value: str) -> Version:
    match = SEMVER_RE.fullmatch(str(value).strip())
    if not match:
        raise ValueError("invalid semver: %s" % value)
    return Version(int(match.group(1)), int(match.group(2)), int(match.group(3)), match.group(4) or "")


def _asset_url(assets: Iterable[Mapping[str, Any]], name: str) -> str:
    for asset in assets:
        if str(asset.get("name", "")) == name and isinstance(asset.get("browser_download_url"), str):
            return str(asset["browser_download_url"])
    raise ValueError("release asset missing: %s" % name)


def parse_release(payload: Mapping[str, Any], *, expected_version: Optional[str] = None) -> Release:
    if payload.get("draft") is True or payload.get("prerelease") is True:
        raise ValueError("release is not stable")
    tag = str(payload.get("tag_name", ""))
    if not tag.startswith("v"):
        raise ValueError("release tag must start with v")
    version = parse_semver(tag[1:])
    if not version.stable:
        raise ValueError("release is not stable")
    if expected_version is not None and version != parse_semver(expected_version):
        raise ValueError("release version does not match expected version")
    assets = payload.get("assets", [])
    if not isinstance(assets, list):
        raise ValueError("release assets are invalid")
    return Release(
        version=version,
        tag=tag,
        archive_url=_asset_url(assets, ARCHIVE_NAME),
        checksum_url=_asset_url(assets, CHECKSUM_NAME),
    )


def latest_release(repository: str, *, opener=urlopen) -> Optional[Release]:
    """Return latest stable release, mapping GitHub's 404 to no release."""

    url = "https://api.github.com/repos/%s/releases/latest" % repository
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "adguardhome-doh"})
    try:
        with opener(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    except (URLError, OSError, ValueError) as exc:
        raise RuntimeError("unable to query GitHub Releases") from exc
    if not isinstance(payload, Mapping):
        raise ValueError("GitHub release response is invalid")
    return parse_release(payload)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_checksum(path: Path, archive_name: str = ARCHIVE_NAME) -> str:
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        fields = line.strip().split()
        if len(fields) >= 2 and fields[-1].lstrip("*") in (archive_name, "./" + archive_name):
            value = fields[0].lower()
            if re.fullmatch(r"[0-9a-f]{64}", value):
                return value
    raise ValueError("checksum missing for %s" % archive_name)


def verify_archive(archive: Path, checksum_file: Path, *, version: Optional[str] = None) -> Tuple[str, ...]:
    expected = read_checksum(checksum_file)
    actual = sha256(archive)
    if actual != expected:
        raise ValueError("archive checksum mismatch")
    required = list(REQUIRED_FILES)
    with tarfile.open(archive, "r:gz") as stream:
        names = {name.lstrip("./") for name in stream.getnames()
                 if not Path(name).name.startswith("._")}
        roots = {name.split("/", 1)[0] for name in names}
        for required_name in required:
            if required_name not in names and not any(name.endswith("/" + required_name) for name in names):
                raise ValueError("archive missing required file: %s" % required_name)
        version_names = [name for name in names if name == "VERSION" or name.endswith("/VERSION")]
        if version is not None:
            found = None
            for name in version_names:
                member = stream.extractfile(name)
                if member is not None:
                    found = member.read().decode("utf-8").strip()
                    break
            if parse_semver(found or "") != parse_semver(version):
                raise ValueError("archive VERSION does not match release tag")
        if len(roots) != 1:
            raise ValueError("archive must contain one source root")
    return tuple(sorted(names))


def main(argv=None) -> int:
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--metadata", type=Path)
    parser.add_argument("--expected-version")
    parser.add_argument("--archive", type=Path)
    parser.add_argument("--checksum", type=Path)
    args = parser.parse_args(argv)
    if args.metadata:
        payload = json.loads(args.metadata.read_text(encoding="utf-8"))
        release = parse_release(payload, expected_version=args.expected_version)
        print(release.tag)
        print(release.archive_url)
        print(release.checksum_url)
        return 0
    if args.archive and args.checksum:
        verify_archive(args.archive, args.checksum, version=args.expected_version)
        print("archive: ok")
        return 0
    parser.error("metadata or archive/checksum is required")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(argv=None))
