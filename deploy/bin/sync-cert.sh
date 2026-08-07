#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ROOT=/
CERT=
KEY=
CHECK_ONLY=0

while (($#)); do
    case "$1" in
        --root) ROOT="$2"; shift 2 ;;
        --cert) CERT="$2"; shift 2 ;;
        --key) KEY="$2"; shift 2 ;;
        --check) CHECK_ONLY=1; shift ;;
        --help|-h)
            printf 'usage: %s [--root PATH] [--cert CERT] [--key KEY] [--check]\n' "$0"
            exit 0
            ;;
        *) dohdns_die "unknown argument: $1" ;;
    esac
done
ROOT="$(dohdns_abs_root "$ROOT")"
DEST_DIR="$(dohdns_under_root "$ROOT" /etc/sniproxy/tls)"
DEST_CERT="$DEST_DIR/fullchain.pem"
DEST_KEY="$DEST_DIR/privkey.pem"

command -v openssl >/dev/null 2>&1 || dohdns_die "openssl is required for certificate/key matching"

# ExecStartPre runs as User=sniproxy. It must inspect only the installed pair;
# certbot's live directory is root-only and is intentionally not touched here.
if ((CHECK_ONLY)); then
    [[ -r "$DEST_CERT" ]] || dohdns_die "installed certificate is not readable: $DEST_CERT"
    [[ -r "$DEST_KEY" ]] || dohdns_die "installed private key is not readable: $DEST_KEY"
    installed_cert_pub="$(openssl x509 -in "$DEST_CERT" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | dohdns_sha256 /dev/stdin)" || dohdns_die "invalid installed certificate"
    installed_key_pub="$(openssl pkey -in "$DEST_KEY" -pubout -outform DER 2>/dev/null | dohdns_sha256 /dev/stdin)" || dohdns_die "invalid installed private key"
    [[ "$installed_cert_pub" == "$installed_key_pub" ]] || dohdns_die "installed certificate and key do not match"
    printf 'certificate/key match: %s\n' "$DEST_DIR"
    exit 0
fi

dohdns_require_root_for_host "$ROOT"
if [[ -z "$CERT" || -z "$KEY" ]]; then
    CERT="$(dohdns_under_root "$ROOT" /etc/letsencrypt/live/dns.pressroll.ru/fullchain.pem)"
    KEY="$(dohdns_under_root "$ROOT" /etc/letsencrypt/live/dns.pressroll.ru/privkey.pem)"
fi
[[ -r "$CERT" ]] || dohdns_die "certificate is not readable: $CERT"
[[ -r "$KEY" ]] || dohdns_die "private key is not readable: $KEY"

cert_pub="$(openssl x509 -in "$CERT" -pubkey -noout | openssl pkey -pubin -outform DER 2>/dev/null | dohdns_sha256 /dev/stdin)" || dohdns_die "invalid certificate: $CERT"
key_pub="$(openssl pkey -in "$KEY" -pubout -outform DER 2>/dev/null | dohdns_sha256 /dev/stdin)" || dohdns_die "invalid private key: $KEY"
[[ "$cert_pub" == "$key_pub" ]] || dohdns_die "certificate and private key do not match"

dohdns_mkdir "$DEST_DIR" 0750
chmod 0750 "$DEST_DIR"
if [[ "$ROOT" == "/" ]] && id sniproxy >/dev/null 2>&1; then
    chown root:sniproxy -- "$DEST_DIR"
fi
temporary_cert="$(mktemp "$DEST_DIR/.fullchain.pem.XXXXXX")"
temporary_key="$(mktemp "$DEST_DIR/.privkey.pem.XXXXXX")"
cleanup() { rm -f -- "$temporary_cert" "$temporary_key"; }
trap cleanup EXIT
install -m 0640 -- "$CERT" "$temporary_cert"
install -m 0640 -- "$KEY" "$temporary_key"
if [[ "$ROOT" == "/" ]] && id sniproxy >/dev/null 2>&1; then
    chown root:sniproxy -- "$temporary_cert" "$temporary_key"
fi
mv -f -- "$temporary_cert" "$DEST_CERT"
mv -f -- "$temporary_key" "$DEST_KEY"
trap - EXIT
printf 'synchronized TLS certificate and key into %s\n' "$DEST_DIR"
