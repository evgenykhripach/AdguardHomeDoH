#!/usr/bin/env bash
set -eEuo pipefail

REPOSITORY="${ADGUARDHOME_DOH_REPOSITORY:-evgenykhripach/AdguardHomeDoH}"
REF="${ADGUARDHOME_DOH_REF:-main}"
CACHE_BUSTER="${ADGUARDHOME_DOH_CACHE_BUSTER:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT

[[ "$CACHE_BUSTER" =~ ^[A-Za-z0-9._-]+$ ]] || {
    printf 'error: invalid cache buster\n' >&2
    exit 1
}

command -v curl >/dev/null 2>&1 || { printf 'error: curl is required\n' >&2; exit 1; }
command -v tar >/dev/null 2>&1 || { printf 'error: tar is required\n' >&2; exit 1; }

archive="$WORK_DIR/source.tar.gz"
curl --fail --silent --show-error --location \
    "https://codeload.github.com/${REPOSITORY}/tar.gz/${REF}?cache=${CACHE_BUSTER}" \
    -o "$archive"
tar -xzf "$archive" -C "$WORK_DIR"
source_dir="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d -print -quit)"
[[ -n "$source_dir" && -x "$source_dir/deploy/install.sh" ]] || {
    printf 'error: downloaded repository has no deploy/install.sh\n' >&2
    exit 1
}
exec "$source_dir/deploy/install.sh" "$@"
