#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ROOT=/
INPUT=
SHA256=
SHA256_FILE=
DATABASE_URL=https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-without-asn.mmdb
SHA256_URL=https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country-without-asn.mmdb.sha256sum
EXPECTED_FILENAME=Country-without-asn.mmdb

usage() {
    printf 'usage: %s [--root PATH] [--input Country-without-asn.mmdb] [--sha256 HEX|--sha256-file PATH] [--database-url URL --sha256-url URL]\n' "$0"
}

while (($#)); do
    case "$1" in
        --root) ROOT="$2"; shift 2 ;;
        --input) INPUT="$2"; shift 2 ;;
        --sha256) SHA256="$2"; shift 2 ;;
        --sha256-file) SHA256_FILE="$2"; shift 2 ;;
        --database-url) DATABASE_URL="$2"; shift 2 ;;
        --sha256-url) SHA256_URL="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; dohdns_die "unknown argument: $1" ;;
    esac
done
ROOT="$(dohdns_abs_root "$ROOT")"
dohdns_require_root_for_host "$ROOT"
DEST_DIR="$(dohdns_under_root "$ROOT" /var/lib/dohdns/geoip)"
DEST="$DEST_DIR/$EXPECTED_FILENAME"
dohdns_mkdir "$DEST_DIR" 0750
chmod 0750 "$DEST_DIR"
if [[ "$ROOT" == "/" ]] && id sniproxy >/dev/null 2>&1; then
    chown root:sniproxy -- "$DEST_DIR"
fi

if [[ -n "$INPUT" ]]; then
    [[ "$(basename -- "$INPUT")" == "$EXPECTED_FILENAME" ]] || dohdns_die "input filename must be $EXPECTED_FILENAME"
    [[ -f "$INPUT" ]] || dohdns_die "GeoIP input missing: $INPUT"
else
    dohdns_is_sandbox "$ROOT" && dohdns_die "sandbox update requires --input and --sha256"
    command -v curl >/dev/null 2>&1 || dohdns_die "curl is required for GeoIP update"
fi

temporary="$(mktemp "$DEST_DIR/.${EXPECTED_FILENAME}.tmp.XXXXXX")"
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT
if [[ -n "$INPUT" ]]; then
    cp -- "$INPUT" "$temporary"
else
    curl --fail --location --silent --show-error --output "$temporary" "$DATABASE_URL"
fi
[[ -s "$temporary" ]] || dohdns_die "downloaded GeoIP database is empty"

if [[ -n "$SHA256_FILE" ]]; then
    [[ -f "$SHA256_FILE" ]] || dohdns_die "checksum file missing: $SHA256_FILE"
    checksum_line="$(grep -E "(^|[[:space:]])${EXPECTED_FILENAME}([[:space:]]|$)" "$SHA256_FILE" | head -n 1 || true)"
    [[ -n "$checksum_line" ]] || dohdns_die "checksum file does not name $EXPECTED_FILENAME"
    SHA256="$(printf '%s\n' "$checksum_line" | awk '{print $1}')"
elif [[ -z "$SHA256" && -n "$INPUT" ]]; then
    dohdns_die "sandbox update requires --sha256 or --sha256-file"
elif [[ -z "$SHA256" ]]; then
    checksum_temporary="$(mktemp "$DEST_DIR/.${EXPECTED_FILENAME}.sha.tmp.XXXXXX")"
    trap 'rm -f -- "$temporary" "$checksum_temporary"' EXIT
    curl --fail --location --silent --show-error --output "$checksum_temporary" "$SHA256_URL"
    checksum_line="$(grep -E "(^|[[:space:]])${EXPECTED_FILENAME}([[:space:]]|$)" "$checksum_temporary" | head -n 1 || true)"
    [[ -n "$checksum_line" ]] || dohdns_die "remote checksum does not name $EXPECTED_FILENAME"
    SHA256="$(printf '%s\n' "$checksum_line" | awk '{print $1}')"
fi
[[ "$SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || dohdns_die "expected SHA256 is invalid"
actual="$(dohdns_sha256 "$temporary")"
actual_lower="$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')"
expected_lower="$(printf '%s' "$SHA256" | tr '[:upper:]' '[:lower:]')"
[[ "$actual_lower" == "$expected_lower" ]] || dohdns_die "GeoIP SHA256 mismatch"

if [[ "${DOHDNS_SKIP_MMDBLOOKUP:-0}" != "1" ]]; then
    "$SCRIPT_DIR/validate-mmdb.sh" --path "$temporary"
fi

if [[ -f "$DEST" ]]; then
    cp -p -- "$DEST" "$DEST.previous"
fi
mv -f -- "$temporary" "$DEST"
chmod 0640 "$DEST"
if [[ "$ROOT" == "/" ]] && id sniproxy >/dev/null 2>&1; then
    chown root:sniproxy -- "$DEST" "$DEST.previous" 2>/dev/null || true
fi
trap - EXIT
printf 'updated %s (%s)\n' "$DEST" "$actual"
