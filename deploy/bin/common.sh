#!/usr/bin/env bash
set -euo pipefail

# Shared, deliberately small shell helpers. Every mutating command receives a
# caller-selected root, which lets tests exercise the exact install layout in
# an isolated directory without invoking host package/service tooling.

DOHDNS_SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
DOHDNS_PROJECT_ROOT="${DOHDNS_PROJECT_ROOT:-$(cd -- "$DOHDNS_SCRIPT_DIR/../.." && pwd -P)}"

dohdns_die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

dohdns_abs_root() {
    local value="${1:-/}"
    [[ "$value" == /* ]] || dohdns_die "root must be an absolute path: $value"
    case "/$value/" in
        */../*|*/./*) dohdns_die "root must not contain lexical traversal: $value" ;;
    esac
    value="${value%/}"
    [[ -n "$value" ]] || value=/
    if [[ "$value" == "/" ]]; then
        printf '/\n'
        return 0
    fi

    # macOS exposes /tmp and /var as compatibility symlinks. Canonicalize those
    # two system aliases, then reject every caller-owned symlink component.
    local alias target suffix probe canonical_probe
    for alias in /tmp /var; do
        if [[ "$value" == "$alias" || "$value" == "$alias"/* ]] && [[ -L "$alias" ]]; then
            target="$(cd -- "$alias" && pwd -P)"
            suffix="${value#"$alias"}"
            value="$target$suffix"
            break
        fi
    done

    probe="$value"
    while [[ ! -e "$probe" && "$probe" != "/" ]]; do
        probe="${probe%/*}"
        [[ -n "$probe" ]] || probe=/
    done
    [[ -d "$probe" ]] || dohdns_die "root parent is not a directory: $probe"
    canonical_probe="$(cd -- "$probe" && pwd -P)" || dohdns_die "cannot canonicalize root parent: $probe"
    [[ "$probe" == "$canonical_probe" ]] || dohdns_die "root contains symlink traversal: $value"
    [[ ! -e "$value" || -d "$value" ]] || dohdns_die "root is not a directory: $value"
    printf '%s\n' "$value"
}

dohdns_is_sandbox() {
    [[ "${1:-/}" != "/" ]]
}

dohdns_under_root() {
    local root="$1" path="$2"
    if [[ "$root" == "/" ]]; then
        printf '%s\n' "$path"
    else
        printf '%s\n' "$root/${path#/}"
    fi
}

dohdns_mkdir() {
    install -d -m "${2:-0755}" -- "$1"
}

dohdns_atomic_symlink() {
    local target="$1" link="$2" temporary
    temporary="${link}.new.$$"
    rm -f -- "$temporary"
    ln -s -- "$target" "$temporary"
    # GNU mv can replace the symlink atomically. BSD mv (used by local macOS
    # tests) has no -T and follows an existing destination symlink, so use a
    # safe two-step fallback there.
    if mv -Tf -- "$temporary" "$link" 2>/dev/null; then
        return 0
    fi
    rm -f -- "$link"
    mv -f -- "$temporary" "$link"
}

dohdns_lock_acquire() {
    local lock="$1"
    dohdns_mkdir "$(dirname -- "$lock")"
    if ! mkdir -- "$lock" 2>/dev/null; then
        dohdns_die "another DoHDNS operation holds lock $lock"
    fi
    DOHDNS_LOCK_DIR="$lock"
    trap 'rmdir -- "$DOHDNS_LOCK_DIR" 2>/dev/null || true' EXIT
}

dohdns_sha256() {
    sha256sum -- "$1" | awk '{print $1}'
}

dohdns_require_generation_name() {
    local value="${1:-}"
    [[ "$value" =~ ^gen-[0-9a-f]{16}(-[1-9][0-9]*)?$ ]] || \
        dohdns_die "invalid generation name in state: $value"
}

dohdns_require_root_for_host() {
    local root="$1"
    if [[ "$root" == "/" && "${EUID:-$(id -u)}" -ne 0 ]]; then
        dohdns_die "real installation requires root; use --root PATH for a sandbox"
    fi
}

dohdns_copy_mode() {
    local source="$1" destination="$2" mode="$3"
    dohdns_mkdir "$(dirname -- "$destination")"
    install -m "$mode" -- "$source" "$destination"
}
