#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ROOT=/
VERSION=v2.3.0
COMMIT=5be8145042cb3a87b76993d43187b07daa254dff
SOURCE_URL=https://codeload.github.com/mosajjal/sniproxy/tar.gz/5be8145042cb3a87b76993d43187b07daa254dff
SOURCE_SHA256=3197a443f29e1e4de992d2a78283ce504090d3a35242afa343e3cddbaf938c1a
GO_VERSION=1.26.0
GO_URL=https://go.dev/dl/go1.26.0.linux-amd64.tar.gz
GO_SHA256=aac1b08a0fb0c4e0a7c1555beb7b59180b05dfc5a3d62e40e9de90cd42f88235
PREBUILT_BINARY=
PREBUILT_SHA256=

usage() {
    printf 'usage: %s [--root PATH] [--prebuilt-binary PATH --prebuilt-sha256 HEX] [--source-url URL] [--source-sha256 HEX] [--go-url URL] [--go-sha256 HEX]\n' "$0"
}

while (($#)); do
    case "$1" in
        --root) ROOT="$2"; shift 2 ;;
        --source-url) SOURCE_URL="$2"; shift 2 ;;
        --source-sha256) SOURCE_SHA256="$2"; shift 2 ;;
        --go-url) GO_URL="$2"; shift 2 ;;
        --go-sha256) GO_SHA256="$2"; shift 2 ;;
        --prebuilt-binary) PREBUILT_BINARY="$2"; shift 2 ;;
        --prebuilt-sha256) PREBUILT_SHA256="$2"; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; dohdns_die "unknown argument: $1" ;;
    esac
done

ROOT="$(dohdns_abs_root "$ROOT")"
dohdns_require_root_for_host "$ROOT"
BUILD_DIR="$(dohdns_under_root "$ROOT" /var/lib/dohdns/build)"
OUTPUT_DIR="$(dohdns_under_root "$ROOT" /usr/local/libexec/sniproxy/$VERSION)"
dohdns_mkdir "$BUILD_DIR" 0700
dohdns_mkdir "$OUTPUT_DIR" 0755

if [[ -n "$PREBUILT_BINARY" || -n "$PREBUILT_SHA256" ]]; then
    [[ -n "$PREBUILT_BINARY" && -n "$PREBUILT_SHA256" ]] || \
        dohdns_die "--prebuilt-binary and --prebuilt-sha256 must be provided together"
    [[ -f "$PREBUILT_BINARY" ]] || dohdns_die "prebuilt binary missing: $PREBUILT_BINARY"
    [[ "$PREBUILT_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || dohdns_die "prebuilt SHA256 is invalid"
    actual_prebuilt_sha256="$(dohdns_sha256 "$PREBUILT_BINARY")"
    actual_prebuilt_sha256="$(printf '%s' "$actual_prebuilt_sha256" | tr '[:upper:]' '[:lower:]')"
    expected_prebuilt_sha256="$(printf '%s' "$PREBUILT_SHA256" | tr '[:upper:]' '[:lower:]')"
    [[ "$actual_prebuilt_sha256" == "$expected_prebuilt_sha256" ]] || \
        dohdns_die "prebuilt sniproxy SHA256 mismatch"
    install -m 0755 -- "$PREBUILT_BINARY" "$OUTPUT_DIR/sniproxy"
    if ! dohdns_is_sandbox "$ROOT"; then
        expected_version="sniproxy version $VERSION, commit $COMMIT"
        actual_version="$($OUTPUT_DIR/sniproxy --version)"
        [[ "$actual_version" == "$expected_version" ]] || \
            dohdns_die "prebuilt sniproxy version/commit mismatch: $actual_version"
    fi
elif dohdns_is_sandbox "$ROOT"; then
    # Sandbox builds cannot and must not reach the network. The deterministic
    # stand-in is only for layout/rollback tests; real / always builds source.
    binary="$OUTPUT_DIR/sniproxy"
    printf '#!/bin/sh\n# sandbox placeholder for %s (%s)\nexit 0\n' "$VERSION" "$COMMIT" >"$binary"
    chmod 0755 "$binary"
else
    command -v curl >/dev/null 2>&1 || dohdns_die "curl is required for source download"
    command -v sha256sum >/dev/null 2>&1 || dohdns_die "sha256sum is required"
    source_archive="$BUILD_DIR/sniproxy-$COMMIT.tar.gz"
    go_archive="$BUILD_DIR/go${GO_VERSION}.linux-amd64.tar.gz"
    curl --fail --location --silent --show-error --output "$source_archive" "$SOURCE_URL"
    [[ "$(dohdns_sha256 "$source_archive")" == "$SOURCE_SHA256" ]] || dohdns_die "sniproxy source SHA256 mismatch"
    curl --fail --location --silent --show-error --output "$go_archive" "$GO_URL"
    [[ "$(dohdns_sha256 "$go_archive")" == "$GO_SHA256" ]] || dohdns_die "Go archive SHA256 mismatch"
    source_dir="$BUILD_DIR/source-$COMMIT"
    rm -rf -- "$source_dir"
    mkdir -- "$source_dir"
    tar -xzf "$source_archive" --strip-components=1 -C "$source_dir"
    go_root="$BUILD_DIR/go-$GO_VERSION"
    rm -rf -- "$go_root"
    mkdir -- "$go_root"
    tar -xzf "$go_archive" -C "$go_root"
    [[ -x "$go_root/go/bin/go" ]] || dohdns_die "pinned Go archive has unexpected layout"
    go_cmd="$go_root/go/bin/go"
    (cd "$source_dir" && "$go_cmd" build -trimpath \
        -ldflags "-X main.version=$VERSION -X main.commit=$COMMIT" \
        -o "$OUTPUT_DIR/sniproxy" ./cmd/sniproxy)
    chmod 0755 "$OUTPUT_DIR/sniproxy"
fi

binary_sha256="$(dohdns_sha256 "$OUTPUT_DIR/sniproxy")"
printf '%s  %s\n' "$binary_sha256" "sniproxy-$VERSION" >"$BUILD_DIR/sniproxy-$VERSION.sha256"
printf 'built %s (%s)\n' "$OUTPUT_DIR/sniproxy" "$binary_sha256"
