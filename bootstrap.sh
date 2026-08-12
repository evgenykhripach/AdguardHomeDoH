#!/usr/bin/env bash
set -eEuo pipefail

REPOSITORY="${ADGUARDHOME_DOH_REPOSITORY:-evgenykhripach/AdguardHomeDoH}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT
command -v curl >/dev/null 2>&1 || { printf 'error: curl is required\n' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { printf 'error: tar is required\n' >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { printf 'error: python3 is required\n' >&2; exit 1; }

metadata="$WORK_DIR/release.json"
archive="$WORK_DIR/adguardhome-doh.tar.gz"
checksum="$WORK_DIR/adguardhome-doh.tar.gz.sha256"
curl --fail --silent --show-error --location \
    --header 'Accept: application/vnd.github+json' \
    "https://api.github.com/repos/${REPOSITORY}/releases/latest" -o "$metadata" || {
    printf 'error: no stable release is available for %s\n' "$REPOSITORY" >&2
    exit 1
}

release_info="$WORK_DIR/release.info"
python3 - "$metadata" > "$release_info" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    payload = json.load(stream)
if payload.get("draft") or payload.get("prerelease"):
    raise SystemExit("release is not stable")
tag = str(payload.get("tag_name", ""))
match = re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag)
if not match:
    raise SystemExit("release tag is not stable semver")
assets = payload.get("assets", [])
by_name = {str(item.get("name")): item for item in assets if isinstance(item, dict)}
archive = by_name.get("adguardhome-doh.tar.gz", {})
checksum = by_name.get("adguardhome-doh.tar.gz.sha256", {})
if not archive.get("browser_download_url") or not checksum.get("browser_download_url"):
    raise SystemExit("release assets are incomplete")
print(tag)
print(archive["browser_download_url"])
print(checksum["browser_download_url"])
print(".".join(match.group(index) for index in (1, 2, 3)))
PY
release_tag="$(sed -n '1p' "$release_info")"
archive_url="$(sed -n '2p' "$release_info")"
checksum_url="$(sed -n '3p' "$release_info")"
version="$(sed -n '4p' "$release_info")"
[[ -n "$release_tag" && -n "$archive_url" && -n "$checksum_url" && -n "$version" ]] || {
    printf 'error: invalid release metadata\n' >&2
    exit 1
}
curl --fail --silent --show-error --location "$archive_url" -o "$archive"
curl --fail --silent --show-error --location "$checksum_url" -o "$checksum"

python3 - "$archive" "$checksum" "$version" <<'PY'
import hashlib
import re
import sys
import tarfile
from pathlib import Path

archive = Path(sys.argv[1])
checksum = Path(sys.argv[2])
version = sys.argv[3]
expected = None
for line in checksum.read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) >= 2 and fields[-1].lstrip("*") in ("adguardhome-doh.tar.gz", "./adguardhome-doh.tar.gz"):
        expected = fields[0].lower()
        break
if not expected or not re.fullmatch(r"[0-9a-f]{64}", expected):
    raise SystemExit("archive checksum is missing")
if hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
    raise SystemExit("archive checksum mismatch")
required = ("VERSION", "bootstrap.sh", "deploy/install.sh", "deploy/manage.py",
            "config/services.csv", "config/domains.csv", "config/service-domains.csv",
            "config/service-probes.csv")
with tarfile.open(archive, "r:gz") as stream:
    names = {name.lstrip("./") for name in stream.getnames()
             if not name.rsplit("/", 1)[-1].startswith("._")}
    for required_name in required:
        if not any(name == required_name or name.endswith("/" + required_name) for name in names):
            raise SystemExit("archive missing required file: " + required_name)
    version_name = next(name for name in names if name == "VERSION" or name.endswith("/VERSION"))
    member = stream.extractfile(version_name)
    found = member.read().decode("utf-8").strip() if member else ""
    if found != version:
        raise SystemExit("archive VERSION does not match release tag")
PY

tar -xzf "$archive" -C "$WORK_DIR"
source_dir="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d ! -name '.*' -print -quit)"
[[ -n "$source_dir" && -x "$source_dir/deploy/install.sh" ]] || {
    printf 'error: downloaded release has no deploy/install.sh\n' >&2
    exit 1
}
exec "$source_dir/deploy/install.sh" "$@"
