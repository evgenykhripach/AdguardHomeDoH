#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ROOT=/
RULES=
while (($#)); do
    case "$1" in
        --root) ROOT="$2"; shift 2 ;;
        --rules) RULES="$2"; shift 2 ;;
        --help|-h)
            printf 'usage: %s [--root PATH] [--rules PATH]\n' "$0"
            exit 0
            ;;
        *) dohdns_die "unknown argument: $1" ;;
    esac
done
ROOT="$(dohdns_abs_root "$ROOT")"
dohdns_require_root_for_host "$ROOT"
if [[ -z "$RULES" ]]; then
    RULES="$(dohdns_under_root "$ROOT" /etc/nftables.d/dohdns.nft)"
fi
[[ -f "$RULES" ]] || dohdns_die "nftables include missing: $RULES"
grep -Eq '^[[:space:]]*table[[:space:]]+inet[[:space:]]+dohdns[[:space:]]*\{' "$RULES" || dohdns_die "rules must define table inet dohdns"
if grep -Eq 'flush[[:space:]]+ruleset|delete[[:space:]]+table[[:space:]]+(ip|ip6|bridge|arp)' "$RULES"; then
    dohdns_die "rules may only describe table inet dohdns"
fi

if dohdns_is_sandbox "$ROOT"; then
    destination="$(dohdns_under_root "$ROOT" /etc/nftables.d/dohdns.nft)"
    dohdns_copy_mode "$RULES" "$destination" 0644
    printf 'sandbox nftables include installed: %s\n' "$destination"
    exit 0
fi

command -v nft >/dev/null 2>&1 || dohdns_die "nft is required on the real host"
# Delete only our own table. A first install has no table, so tolerate that
# error; never flush the complete ruleset or touch fail2ban/other tables.
nft delete table inet dohdns >/dev/null 2>&1 || true
nft -f "$RULES"
printf 'applied isolated nftables table inet dohdns\n'
