#!/usr/bin/env bash
# Client-side stall probe.  Run it on the network where the stalls happen,
# for example a laptop tethered to the phone's hotspot with every VPN off, and
# compare the timestamps with `adguardhome-doh-diag` on the server.
#
# usage: tools/client-probe.sh HOST [ROUTED_SITE] [INTERVAL_SECONDS]
#   DOH_URL=https://HOST/doh/<token>   optional: adds a real DoH query;
#                                      the URL is used but never printed
#   CONTROL_HOST=1.1.1.1               optional: a host that must always work
#
# Every cycle prints one CSV line and appends it to client-probe-<time>.csv.
# rc is curl's exit code: 28 with connect=0 means the SYN was never answered,
# 28 with connect>0 and tls=0 means the TLS handshake was swallowed on the
# path, 35 means the handshake was reset, 0 means the request succeeded.
set -u
HOST="${1:?usage: client-probe.sh HOST [ROUTED_SITE] [INTERVAL_SECONDS]}"
SITE="${2:-chatgpt.com}"
INTERVAL="${3:-10}"
CONTROL="${CONTROL_HOST:-1.1.1.1}"
DOH_URL="${DOH_URL:-}"
QUERY=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB
OUT="client-probe-$(date +%Y%m%d-%H%M%S).csv"
case "$(uname -s)" in
    Darwin) PING_ARGS="-c 1 -t 2" ;;
    *) PING_ARGS="-c 1 -W 2" ;;
esac

ping_ms() {
    # shellcheck disable=SC2086
    ping $PING_ARGS "$1" 2>/dev/null | sed -n 's/.*time=\([0-9.]*\) ms.*/\1/p' | head -1
}

# Prints: rc,connect,tls,total,http_code,remote_ip
http_probe() {
    local out rc connect tls total code ip
    out="$(curl --silent --output /dev/null --max-time 10 --connect-timeout 5 \
        --write-out '%{time_connect}|%{time_appconnect}|%{time_total}|%{http_code}|%{remote_ip}' \
        "$@" 2>/dev/null)"
    rc=$?
    IFS='|' read -r connect tls total code ip <<< "${out:-0|0|0|000|-}"
    printf '%s,%s,%s,%s,%s,%s\n' "$rc" "${connect:-0}" "${tls:-0}" "${total:-0}" "${code:-000}" "${ip:--}"
}

header='time,ping_ms,host_rc,host_connect,host_tls,host_total,host_http,host_ip,site_rc,site_connect,site_tls,site_total,site_http,site_ip,doh_rc,doh_connect,doh_tls,doh_total,doh_http,doh_ip,ctl_rc,ctl_connect,ctl_tls,ctl_total,ctl_http,ctl_ip'
printf '%s\n' "$header" | tee "$OUT"
printf 'probing %s, routed site %s, control %s every %ss; DoH probe %s; log %s\n' \
    "$HOST" "$SITE" "$CONTROL" "$INTERVAL" "$([ -n "$DOH_URL" ] && echo on || echo off)" "$OUT" >&2
while :; do
    stamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    rtt="$(ping_ms "$HOST")"
    host_line="$(http_probe "https://$HOST/")"
    site_line="$(http_probe "https://$SITE/")"
    if [ -n "$DOH_URL" ]; then
        doh_line="$(http_probe --header 'accept: application/dns-message' "$DOH_URL?dns=$QUERY")"
    else
        doh_line="-,-,-,-,-,-"
    fi
    ctl_line="$(http_probe "https://$CONTROL/")"
    printf '%s,%s,%s,%s,%s,%s\n' "$stamp" "${rtt:--}" "$host_line" "$site_line" "$doh_line" "$ctl_line" | tee -a "$OUT"
    sleep "$INTERVAL"
done
