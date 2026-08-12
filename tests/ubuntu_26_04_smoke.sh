#!/usr/bin/env bash
set -eEuo pipefail

PROJECT_ROOT="${1:-/repo}"
DOMAIN=dns.example.com
PUBLIC_IP=203.0.113.10
MOCK_BIN=/tmp/pressroll-smoke-bin

[[ "${EUID:-$(id -u)}" -eq 0 ]] || { printf 'run as root\n' >&2; exit 1; }
mkdir -p "$MOCK_BIN"

cat > /usr/sbin/policy-rc.d <<'EOF'
#!/bin/sh
exit 101
EOF
chmod 755 /usr/sbin/policy-rc.d

cat > "$MOCK_BIN/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> /tmp/pressroll-systemctl.log
if [[ "$*" == "start pressroll-smart-dns-health.service" ]]; then
    if [[ -e /tmp/pressroll-force-health-failure ]]; then
        exit 1
    fi
    grep -Fq 'restart AdGuardHome' /tmp/pressroll-systemctl.log || exit 1
    touch /tmp/pressroll-health-started
fi
exit 0
EOF
chmod 755 "$MOCK_BIN/systemctl"

cat > "$MOCK_BIN/certbot" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
domain=
standalone=0
pre_hook=
post_hook=
while (($#)); do
    case "$1" in
        -d) domain="$2"; shift 2 ;;
        --standalone) standalone=1; shift ;;
        --pre-hook) pre_hook="$2"; shift 2 ;;
        --post-hook) post_hook="$2"; shift 2 ;;
        *) shift ;;
    esac
done
[[ -n "$domain" ]]
[[ "$standalone" -eq 1 ]]
[[ "$pre_hook" == "systemctl stop nginx" ]]
[[ "$post_hook" == "systemctl start nginx" ]]
bash -c "$pre_hook"
certificate_root="/etc/letsencrypt/live/$domain"
mkdir -p "$certificate_root"
/usr/bin/openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -subj "/CN=$domain" \
    -keyout "$certificate_root/privkey.pem" \
    -out "$certificate_root/fullchain.pem" >/dev/null 2>&1
bash -c "$post_hook"
EOF
chmod 755 "$MOCK_BIN/certbot"

export PATH="$MOCK_BIN:$PATH"
cd /root

# Existing servers may have a private default webroot.  The installer must not
# depend on or relax its permissions to serve the generated profile.
mkdir -p /var/www/html
chmod 700 /var/www/html

install_once() {
    "$PROJECT_ROOT/deploy/install.sh" \
        --domain "$DOMAIN" \
        --public-ip "$PUBLIC_IP" \
        --email admin@example.com
}

active_token() {
    grep -oE 'location = /doh/[a-f0-9]{32,64}' \
        /etc/nginx/sites-enabled/pressroll-smart-dns |
        sed 's#location = /doh/##'
}

install_once | tee /tmp/pressroll-first-install.out
test -e /tmp/pressroll-health-started
nginx -t
/opt/AdGuardHome/AdGuardHome --check-config \
    -c /opt/AdGuardHome/AdGuardHome.yaml \
    -w /var/lib/AdGuardHome
test "$(grep -Fxc 'include /etc/nginx/stream.d/*.conf;' /etc/nginx/nginx.conf)" -eq 1
test -s /var/lib/pressroll-smart-dns/admin-credentials
test -f /var/lib/pressroll-smart-dns/install-complete
test "$(stat -c '%a' /var/www/pressroll-smart-dns)" = 755
first_token="$(active_token)"
test -n "$first_token"
test -s "/var/www/pressroll-smart-dns/$first_token.mobileconfig"
grep -Fq 'AdGuard Home admin credentials' /tmp/pressroll-first-install.out

rm /var/lib/pressroll-smart-dns/install-complete
install_once | tee /tmp/pressroll-recovered-install.out
nginx -t
second_token="$(active_token)"
test "$second_token" = "$first_token"
test "$(grep -Fxc 'include /etc/nginx/stream.d/*.conf;' /etc/nginx/nginx.conf)" -eq 1
test -f /var/lib/pressroll-smart-dns/install-complete
grep -Fq 'AdGuard Home admin credentials' /tmp/pressroll-recovered-install.out
grep -Fq "DoH URL: https://$DOMAIN/doh/$second_token" /tmp/pressroll-recovered-install.out
grep -Fq "mobileconfig: https://$DOMAIN/$second_token.mobileconfig" /tmp/pressroll-recovered-install.out

nginx
trap 'nginx -s quit >/dev/null 2>&1 || true' EXIT
curl --fail --silent --show-error --insecure \
    --resolve "$DOMAIN:443:127.0.0.1" \
    "https://$DOMAIN/$second_token.mobileconfig" \
    -o /tmp/pressroll.mobileconfig
grep -Fq "https://$DOMAIN/doh/$second_token" /tmp/pressroll.mobileconfig

touch /tmp/pressroll-force-health-failure
if install_once >/tmp/pressroll-failed-health.out 2>&1; then
    printf 'installer ignored a failed health-check\n' >&2
    exit 1
fi
printf 'ubuntu 26.04 install smoke: ok\n'
