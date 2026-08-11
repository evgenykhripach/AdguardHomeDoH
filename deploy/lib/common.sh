#!/usr/bin/env bash
set -euo pipefail

pressroll_die() { printf 'error: %s\n' "$*" >&2; exit 1; }

pressroll_require_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || pressroll_die "run as root (or use --root for dry-run tests)"
}

pressroll_validate_hostname() {
    [[ "$1" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$ ]] || \
        pressroll_die "invalid hostname: $1"
}

pressroll_validate_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    if ipaddress.ip_address(sys.argv[1]).version != 4:
        raise ValueError
except ValueError:
    raise SystemExit("invalid IPv4")
PY
}

pressroll_abs_root() {
    local value="${1:-/}"
    [[ "$value" == /* ]] || pressroll_die "root must be absolute"
    [[ "$value" != *"/../"* && "$value" != */.. && "$value" != *"/./"* ]] || \
        pressroll_die "root contains traversal"
    value="${value%/}"
    [[ -n "$value" ]] || value=/
    printf '%s\n' "$value"
}

pressroll_under_root() {
    local root="$1" path="$2"
    [[ "$root" == "/" ]] && printf '%s\n' "$path" || printf '%s\n' "$root/${path#/}"
}

pressroll_arch() {
    case "$(dpkg --print-architecture 2>/dev/null || uname -m)" in
        amd64|x86_64) printf 'amd64\n' ;;
        arm64|aarch64) printf 'arm64\n' ;;
        armhf|armv7l) printf 'armv7\n' ;;
        i386|i686) printf '386\n' ;;
        *) pressroll_die "unsupported CPU architecture" ;;
    esac
}

pressroll_backup() {
    local source="$1" destination="$2"
    if [[ -e "$source" || -L "$source" ]]; then
        install -d -m 700 "$(dirname "$destination")"
        cp -a -- "$source" "$destination"
    fi
}
