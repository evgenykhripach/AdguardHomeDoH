#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ROOT=/
PATH_VALUE=
while (($#)); do
    case "$1" in
        --root) ROOT="$2"; shift 2 ;;
        --path) PATH_VALUE="$2"; shift 2 ;;
        --help|-h)
            printf 'usage: %s [--root PATH] [--path MMDB]\n' "$0"
            exit 0
            ;;
        *) dohdns_die "unknown argument: $1" ;;
    esac
done
ROOT="$(dohdns_abs_root "$ROOT")"
if [[ -z "$PATH_VALUE" ]]; then
    PATH_VALUE="$(dohdns_under_root "$ROOT" /var/lib/dohdns/geoip/Country-without-asn.mmdb)"
elif [[ "$ROOT" != "/" && "$PATH_VALUE" == /* ]]; then
    # Absolute paths in sandbox mode are interpreted inside that root.
    PATH_VALUE="$(dohdns_under_root "$ROOT" "$PATH_VALUE")"
fi

[[ -f "$PATH_VALUE" ]] || dohdns_die "GeoIP database missing: $PATH_VALUE"
[[ -s "$PATH_VALUE" ]] || dohdns_die "GeoIP database is empty: $PATH_VALUE"

if [[ "${DOHDNS_SKIP_MMDBLOOKUP:-0}" == "1" ]]; then
    printf 'valid MMDB (lookup skipped for isolated test): %s\n' "$PATH_VALUE"
    exit 0
fi
command -v mmdblookup >/dev/null 2>&1 || dohdns_die "mmdblookup is required to validate GeoIP database"
# A known public address exercises both metadata parsing and the database
# reader. The result may be any country; policy enforcement happens in
# sniproxy with the local RU database.
mmdblookup --file "$PATH_VALUE" --ip 1.1.1.1 >/dev/null 2>&1 || dohdns_die "mmdblookup rejected GeoIP database: $PATH_VALUE"
printf 'valid MMDB: %s\n' "$PATH_VALUE"
