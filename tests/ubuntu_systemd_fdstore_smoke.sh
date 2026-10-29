#!/usr/bin/env bash
# Disposable runner only: unique transient units, private temporary lock file.
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
probe="$project_root/tests/fixtures/recovery/fdstore_probe.py"
[[ "$EUID" == 0 ]] || { printf 'Run this isolated systemd test as root.\n' >&2; exit 1; }
[[ -r /proc/1/comm && "$(cat /proc/1/comm)" == systemd ]] || {
    printf 'This experiment requires systemd as PID 1.\n' >&2; exit 1;
}
version="$(systemctl --version | awk 'NR == 1 { print $2 }')"
[[ "$version" == 255 ]] || {
    printf 'This experiment requires systemd 255; found %s.\n' "$version" >&2; exit 1;
}
[[ -f "$probe" ]] || { printf 'FDSTORE probe is missing.\n' >&2; exit 1; }
command -v flock >/dev/null 2>&1 || { printf 'flock is required for safe cleanup.\n' >&2; exit 1; }

suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
[[ "$suffix" =~ ^[a-f0-9]{32}$ ]] || exit 1
owner="doh-fdstore-owner-${suffix}.service"
waiter="doh-fdstore-waiter-${suffix}.service"
owner_description="DoHDNS FDSTORE owner ${suffix}"
waiter_description="DoHDNS FDSTORE waiter ${suffix}"
for unit in "$owner" "$waiter"; do
    state="$(systemctl show "$unit" --property=LoadState --value 2>/dev/null || true)"
    [[ "$state" == not-found ]] || { printf 'Temporary unit name already exists or is ambiguous.\n' >&2; exit 1; }
done
scratch="$(mktemp -d /tmp/doh-fdstore-smoke.XXXXXXXX)"
[[ "$scratch" =~ ^/tmp/doh-fdstore-smoke\.[a-zA-Z0-9]+$ ]] || exit 1
chmod 700 "$scratch"
test_completed=0

owned_unit() {
    local unit="$1" expected="$2" description transient
    description="$(systemctl show "$unit" --property=Description --value 2>/dev/null)" || return 1
    transient="$(systemctl show "$unit" --property=Transient --value 2>/dev/null)" || return 1
    [[ "$description" == "$expected" && "$transient" == yes ]]
}

cleanup() {
    local original=$? failed=0 unit state
    trap - EXIT INT TERM
    set +e
    # Stop the independent test contender first; it is expected to acquire the
    # lock when the FDSTORE is deliberately cleared during cleanup.
    for unit in "$waiter" "$owner"; do
        state="$(systemctl show "$unit" --property=LoadState --value 2>/dev/null)"
        if [[ "$state" == not-found ]]; then
            continue
        fi
        if [[ "$unit" == "$waiter" ]]; then
            owned_unit "$unit" "$waiter_description" || { failed=1; continue; }
        else
            owned_unit "$unit" "$owner_description" || { failed=1; continue; }
        fi
        systemctl stop "$unit" >/dev/null 2>&1 || failed=1
        if [[ "$unit" == "$owner" ]]; then
            state="$(systemctl show "$unit" --property=LoadState --value 2>/dev/null)"
            if [[ "$state" != not-found ]]; then
                systemctl clean --what=fdstore "$unit" >/dev/null 2>&1 || failed=1
            fi
        fi
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
    if [[ -f "$scratch/lock" ]]; then
        flock -n "$scratch/lock" /bin/true || failed=1
    fi
    if ((failed)); then
        printf 'Cleanup could not safely release the temporary unit or lock; retained %s\n' "$scratch" >&2
        ((original != 0)) || original=1
    else
        rm -rf -- "$scratch" || original=1
    fi
    if ((original == 0 && test_completed == 1)); then
        printf 'PASS: named FDSTORE descriptor and flock survived restart and supervisor SIGKILL.\n'
        printf 'Not tested: reboot, writer-job barrier, or application recovery.\n'
    fi
    exit "$original"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

unit_identity() {
    local unit="$1" pid invocation
    systemctl is-active --quiet "$unit" || return 1
    pid="$(systemctl show "$unit" --property=MainPID --value)" || return 1
    invocation="$(systemctl show "$unit" --property=InvocationID --value)" || return 1
    [[ "$pid" =~ ^[1-9][0-9]*$ && "$invocation" =~ ^[a-f0-9]{32}$ ]] || return 1
    printf '%s %s\n' "$pid" "$invocation"
}

wait_for_waiter() {
    local attempt pid invocation identity
    for ((attempt = 0; attempt < 300; attempt++)); do
        [[ ! -e "$scratch/breach.json" ]] || { printf 'Contender acquired the lock.\n' >&2; return 1; }
        if identity="$(unit_identity "$waiter")"; then
            read -r pid invocation <<< "$identity"
            if /usr/bin/python3 "$probe" validate-waiter "$scratch" "$pid" "$invocation" >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.1
    done
    printf 'Independent contender did not block in flock.\n' >&2
    return 1
}

wait_for_phase() {
    local phase="$1" require_waiter="$2" attempt pid invocation identity waiter_identity waiter_pid waiter_invocation
    for ((attempt = 0; attempt < 300; attempt++)); do
        [[ ! -e "$scratch/breach.json" ]] || { printf 'Contender acquired the lock.\n' >&2; return 1; }
        if ((require_waiter)); then
            waiter_identity="$(unit_identity "$waiter")" || { printf 'Contender exited unexpectedly.\n' >&2; return 1; }
            read -r waiter_pid waiter_invocation <<< "$waiter_identity"
            /usr/bin/python3 "$probe" validate-waiter "$scratch" "$waiter_pid" "$waiter_invocation" >/dev/null 2>&1 || {
                printf 'Contender is no longer blocked on the expected lock.\n' >&2; return 1;
            }
        fi
        if identity="$(unit_identity "$owner")"; then
            read -r pid invocation <<< "$identity"
            if /usr/bin/python3 "$probe" validate-phase "$scratch" "$phase" "$pid" "$invocation" >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.1
    done
    printf 'Supervisor did not provide a valid FDSTORE round-trip for phase %s.\n' "$phase" >&2
    systemctl status "$owner" --no-pager >&2 || true
    return 1
}

systemd-run --quiet --unit="$owner" --description="$owner_description" \
    --property=Type=notify --property=NotifyAccess=main \
    --property=FileDescriptorStoreMax=1 --property=FileDescriptorStorePreserve=yes \
    --property=Restart=on-failure --property=RestartSec=1s --property=TimeoutStartSec=20s \
    /usr/bin/python3 "$probe" supervisor "$scratch" "lock-${suffix}"
[[ "$(systemctl show "$owner" --property=FileDescriptorStoreMax --value)" == 1 ]]
[[ "$(systemctl show "$owner" --property=FileDescriptorStorePreserve --value)" == yes ]]
wait_for_phase 0 0

systemd-run --quiet --unit="$waiter" --description="$waiter_description" \
    --property=Type=notify --property=NotifyAccess=main --property=Restart=no \
    --property=TimeoutStartSec=20s /usr/bin/python3 "$probe" contender "$scratch"
wait_for_waiter
/usr/bin/python3 "$probe" check-lock "$scratch"

# This restart proves an actual named descriptor round-trip, not merely that
# PID 1 processed the asynchronous FDSTORE notification.
systemctl restart "$owner"
wait_for_phase 1 1

# Kill only the supervisor; the independent contender must remain blocked
# while PID 1 restarts the supervisor and returns the same locked descriptor.
systemctl kill --kill-who=main --signal=SIGKILL "$owner"
wait_for_phase 2 1
/usr/bin/python3 "$probe" check-lock "$scratch"
test_completed=1
