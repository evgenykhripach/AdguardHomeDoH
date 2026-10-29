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
roles=(operation health front)
operation_waiter="doh-fdstore-waiter-operation-${suffix}.service"
health_waiter="doh-fdstore-waiter-health-${suffix}.service"
front_waiter="doh-fdstore-waiter-front-${suffix}.service"
waiters=("$operation_waiter" "$health_waiter" "$front_waiter")
owner_description="DoHDNS FDSTORE owner ${suffix}"
for unit in "$owner" "${waiters[@]}"; do
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
    local original=$? failed=0 unit state expected role
    trap - EXIT INT TERM
    set +e
    # Stop the independent test contender first; it is expected to acquire the
    # lock when the FDSTORE is deliberately cleared during cleanup.
    for unit in "${waiters[@]}" "$owner"; do
        state="$(systemctl show "$unit" --property=LoadState --value 2>/dev/null)"
        if [[ "$state" == not-found ]]; then
            continue
        fi
        case "$unit" in
            "$operation_waiter") expected="DoHDNS FDSTORE waiter operation ${suffix}" ;;
            "$health_waiter") expected="DoHDNS FDSTORE waiter health ${suffix}" ;;
            "$front_waiter") expected="DoHDNS FDSTORE waiter front ${suffix}" ;;
            "$owner") expected="$owner_description" ;;
            *) failed=1; continue ;;
        esac
        owned_unit "$unit" "$expected" || { failed=1; continue; }
        systemctl stop "$unit" >/dev/null 2>&1 || failed=1
        if [[ "$unit" == "$owner" ]]; then
            state="$(systemctl show "$unit" --property=LoadState --value 2>/dev/null)"
            if [[ "$state" != not-found ]]; then
                systemctl clean --what=fdstore "$unit" >/dev/null 2>&1 || failed=1
            fi
        fi
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    done
    for role in "${roles[@]}"; do
        if [[ -f "$scratch/$role.lock" ]]; then
            flock -n "$scratch/$role.lock" /bin/true || failed=1
        fi
    done
    if ((failed)); then
        printf 'Cleanup could not safely release the temporary unit or lock; retained %s\n' "$scratch" >&2
        ((original != 0)) || original=1
    else
        rm -rf -- "$scratch" || original=1
    fi
    if ((original == 0 && test_completed == 1)); then
        printf 'PASS: all three named FDSTORE descriptors and flocks survived restart and supervisor SIGKILL.\n'
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
    local role="$1" waiter="$2" mode="${3:-validate-waiter}" attempt pid invocation identity
    for ((attempt = 0; attempt < 300; attempt++)); do
        [[ ! -e "$scratch/breach-$role.json" ]] || { printf 'Contender acquired %s lock.\n' "$role" >&2; return 1; }
        if identity="$(unit_identity "$waiter")"; then
            read -r pid invocation <<< "$identity"
            if /usr/bin/python3 "$probe" "$mode" "$scratch" "$role" "$pid" "$invocation" >/dev/null 2>&1; then
                return 0
            fi
        fi
        sleep 0.1
    done
    printf 'Independent %s contender did not reach %s.\n' "$role" "$mode" >&2
    return 1
}

wait_for_phase() {
    local phase="$1" require_waiter="$2" attempt pid invocation identity waiter_identity waiter_pid waiter_invocation role waiter
    for ((attempt = 0; attempt < 300; attempt++)); do
        for role in "${roles[@]}"; do
            [[ ! -e "$scratch/breach-$role.json" ]] || { printf 'Contender acquired %s lock.\n' "$role" >&2; return 1; }
            if ((require_waiter)); then
                waiter="doh-fdstore-waiter-${role}-${suffix}.service"
                waiter_identity="$(unit_identity "$waiter")" || { printf 'Contender exited unexpectedly.\n' >&2; return 1; }
                read -r waiter_pid waiter_invocation <<< "$waiter_identity"
                /usr/bin/python3 "$probe" validate-waiter "$scratch" "$role" "$waiter_pid" "$waiter_invocation" >/dev/null 2>&1 || {
                    printf 'Contender is no longer blocked on the expected %s lock.\n' "$role" >&2; return 1;
                }
            fi
        done
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

/usr/bin/python3 "$probe" initialize "$scratch" "$suffix"
for role in "${roles[@]}"; do
    waiter="doh-fdstore-waiter-${role}-${suffix}.service"
    systemd-run --quiet --unit="$waiter" --description="DoHDNS FDSTORE waiter ${role} ${suffix}" \
        --property=Type=notify --property=NotifyAccess=main --property=Restart=no \
        --property=TimeoutStartSec=20s /usr/bin/python3 "$probe" contender "$scratch" "$role"
    wait_for_waiter "$role" "$waiter" validate-preexisting-waiter
done

systemd-run --quiet --unit="$owner" --description="$owner_description" \
    --property=Type=notify --property=NotifyAccess=main \
    --property=FileDescriptorStoreMax=3 --property=FileDescriptorStorePreserve=yes \
    --property=Restart=on-failure --property=RestartSec=1s --property=TimeoutStartSec=20s \
    /usr/bin/python3 "$probe" supervisor "$scratch" "$suffix"
[[ "$(systemctl show "$owner" --property=FileDescriptorStoreMax --value)" == 3 ]]
[[ "$(systemctl show "$owner" --property=FileDescriptorStorePreserve --value)" == yes ]]
wait_for_phase 0 0

: > "$scratch/waiters-go"
for role in "${roles[@]}"; do
    waiter="doh-fdstore-waiter-${role}-${suffix}.service"
    wait_for_waiter "$role" "$waiter"
    /usr/bin/python3 "$probe" check-lock "$scratch" "$role"
done

# This restart proves an actual named descriptor round-trip, not merely that
# PID 1 processed the asynchronous FDSTORE notification.
systemctl restart "$owner"
wait_for_phase 1 1
[[ "$(systemctl show "$owner" --property=NFileDescriptorStore --value)" == 3 ]]

# Kill only the supervisor; the independent contender must remain blocked
# while PID 1 restarts the supervisor and returns the same locked descriptor.
systemctl kill --kill-who=main --signal=SIGKILL "$owner"
wait_for_phase 2 1
[[ "$(systemctl show "$owner" --property=NFileDescriptorStore --value)" == 3 ]]
for role in "${roles[@]}"; do
    /usr/bin/python3 "$probe" check-lock "$scratch" "$role"
done
test_completed=1
