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
awk '
    {
        line = $0
        sub(/[[:space:]]*#.*/, "", line)
        if (line ~ /^[[:space:]]*table[[:space:]]+/) {
            tables++
            if (line !~ /^[[:space:]]*table[[:space:]]+inet[[:space:]]+dohdns[[:space:]]*\{[[:space:]]*$/) bad_table=1
        }
        if (line ~ /(^|[[:space:]])(include|define|flush|add|delete)([[:space:]]|$)/) bad_directive=1
    }
    END {
        if (tables != 1 || bad_table || bad_directive) exit 1
    }
' "$RULES" || dohdns_die "rules must contain exactly one table inet dohdns and no include/define/flush/add/delete directives"

if dohdns_is_sandbox "$ROOT"; then
    destination="$(dohdns_under_root "$ROOT" /etc/nftables.d/dohdns.nft)"
    dohdns_copy_mode "$RULES" "$destination" 0644
    printf 'sandbox nftables include installed: %s\n' "$destination"
    exit 0
fi

command -v nft >/dev/null 2>&1 || dohdns_die "nft is required on the real host"
# Syntax-check the input before changing any live rules. When replacing an
# existing table, delete and recreate only our table in one nft transaction;
# nft keeps the prior transaction intact if either statement fails. The
# existing-table preflight must use the same delete-plus-rules batch, because a
# standalone check of the create-only file can conflict with live objects.
if nft list table inet dohdns >/dev/null 2>&1; then
    nft_batch() {
        printf 'delete table inet dohdns\n'
        cat -- "$RULES"
    }
    nft_batch | nft -c -f -
    nft_batch | nft -f -
else
    nft -c -f "$RULES"
    nft -f "$RULES"
fi
printf 'applied isolated nftables table inet dohdns\n'
