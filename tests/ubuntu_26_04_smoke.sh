#!/usr/bin/env bash
set -eEuo pipefail

PROJECT_ROOT="${1:-/repo}"
DOMAIN=dns.example.com
PUBLIC_IP=203.0.113.10
MOCK_BIN=/tmp/adguardhome-doh-smoke-bin

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
printf '%s\n' "$*" >> /tmp/adguardhome-doh-systemctl.log
if [[ "$*" == "start adguardhome-doh-health.service" ]]; then
    if [[ -e /tmp/adguardhome-doh-force-health-failure ]]; then
        exit 1
    fi
    grep -Fq 'restart adguardhome-doh' /tmp/adguardhome-doh-systemctl.log || exit 1
    touch /tmp/adguardhome-doh-health-started
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
        --email admin@example.com \
        --yes
}

active_token() {
    grep -oE 'location = /doh/[a-f0-9]{32,64}' \
        /etc/nginx/sites-enabled/adguardhome-doh |
        sed 's#location = /doh/##'
}

install_once | tee /tmp/adguardhome-doh-first-install.out
test -e /tmp/adguardhome-doh-health-started
nginx -t
/opt/AdGuardHome/AdGuardHome --check-config \
    -c /opt/AdGuardHome/AdGuardHome.yaml \
    -w /var/lib/AdGuardHome
test "$(grep -Fxc 'include /etc/nginx/stream.d/*.conf;' /etc/nginx/nginx.conf)" -eq 1
test -s /var/lib/adguardhome-doh/admin-credentials.json
test -f /var/lib/adguardhome-doh/install-complete
test "$(stat -c '%a' /var/www/adguardhome-doh)" = 755
first_token="$(active_token)"
test -n "$first_token"
test -s "/var/www/adguardhome-doh/$DOMAIN.mobileconfig"
grep -Fq 'Admin URL:' /tmp/adguardhome-doh-first-install.out

rm /var/lib/adguardhome-doh/install-complete
install_once | tee /tmp/adguardhome-doh-recovered-install.out
nginx -t
second_token="$(active_token)"
test "$second_token" = "$first_token"
test "$(grep -Fxc 'include /etc/nginx/stream.d/*.conf;' /etc/nginx/nginx.conf)" -eq 1
test -f /var/lib/adguardhome-doh/install-complete
grep -Fq 'Admin URL:' /tmp/adguardhome-doh-recovered-install.out
grep -Fq "DoH URL: https://$DOMAIN/doh/$second_token" /tmp/adguardhome-doh-recovered-install.out
grep -Fq "mobileconfig URL: https://$DOMAIN/$second_token.mobileconfig" /tmp/adguardhome-doh-recovered-install.out

nginx
trap 'nginx -s quit >/dev/null 2>&1 || true' EXIT
curl --fail --silent --show-error --insecure \
    --resolve "$DOMAIN:443:127.0.0.1" \
    --dump-header /tmp/adguardhome-doh-mobileconfig.headers \
    "https://$DOMAIN/$second_token.mobileconfig" \
    -o /tmp/adguardhome-doh.mobileconfig
grep -Fiq "Content-Disposition: attachment; filename=$DOMAIN.mobileconfig" \
    /tmp/adguardhome-doh-mobileconfig.headers
grep -Fq "https://$DOMAIN/doh/$second_token" /tmp/adguardhome-doh.mobileconfig
test "$(grep -Foc "<key>PayloadDisplayName</key><string>$DOMAIN</string>" \
    /tmp/adguardhome-doh.mobileconfig)" -eq 2
touch /tmp/adguardhome-doh-force-health-failure
if install_once >/tmp/adguardhome-doh-failed-health.out 2>&1; then
    printf 'installer ignored a failed health-check\n' >&2
    exit 1
fi
printf 'ubuntu 26.04 install smoke: ok\n'
