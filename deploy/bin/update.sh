#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ROOT=/
INVENTORY=
ARGS=()
while (($#)); do
    case "$1" in
        --root) ROOT="$2"; ARGS+=(--root "$2"); shift 2 ;;
        --inventory) INVENTORY="$2"; ARGS+=(--inventory "$2"); shift 2 ;;
        --help|-h)
            printf 'usage: %s [--root PATH] [--inventory PATH] [install options]\n' "$0"
            exit 0
            ;;
        *) ARGS+=("$1"); shift ;;
    esac
done
ROOT="$(dohdns_abs_root "$ROOT")"
if [[ -z "$INVENTORY" ]]; then
    if [[ "$ROOT" == "/" ]]; then
        INVENTORY="$DOHDNS_PROJECT_ROOT/inventory.example.json"
    else
        INVENTORY="$(dohdns_under_root "$ROOT" /etc/dohdns/inventory.json)"
    fi
    ARGS+=(--inventory "$INVENTORY")
fi
exec "$SCRIPT_DIR/install.sh" --update "${ARGS[@]}"
