#!/usr/bin/env bash
# Disposable real-PID1 experiment. No application services are involved.
# Locks, job barrier and runtime are fakes; this does not prove OOM/boot.
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
fixture="$project_root/tests/fixtures/recovery/systemd_probe.py"
recovery="$project_root/deploy/lib/recovery.py"

[[ "$(ps -p 1 -o comm= | tr -d ' ')" == systemd ]] || {
    printf 'This experiment requires a disposable Ubuntu runner with systemd as PID 1.\n' >&2
    exit 1
}
[[ -r /sys/fs/cgroup/cgroup.controllers ]] || {
    printf 'This experiment requires cgroup v2.\n' >&2
    exit 1
}
sudo -n true
suffix="$(tr -d '-' </proc/sys/kernel/random/uuid)"
[[ "$suffix" =~ ^[a-f0-9]{32}$ ]] || exit 1
unit="adguardhome-doh-writer-${suffix}.service"
scratch="$(sudo -n mktemp -d /tmp/adguardhome-doh-recovery-smoke.XXXXXXXX)"
[[ "$scratch" =~ ^/tmp/adguardhome-doh-recovery-smoke\.[a-zA-Z0-9]+$ ]] || exit 1

cleanup() {
    sudo -n systemctl stop "$unit" >/dev/null 2>&1 || true
    sudo -n systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    sudo -n rm -rf -- "$scratch"
}
trap cleanup EXIT
sudo -n mkdir -m 700 "$scratch/journal" "$scratch/snapshots"

probe() {
    sudo -n /usr/bin/python3 "$fixture" "$1" "$scratch" "$unit" "$recovery" "${@:2}"
}

wait_gone() {
    local count
    for ((count = 0; count < 300; count++)); do
        if probe gone >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.1
    done
    sudo -n systemctl status "$unit" --no-pager >&2 || true
    printf 'Writer, child, cgroup or pending job did not clear.\n' >&2
    return 1
}

sudo -n systemd-run --quiet --unit="$unit" \
    --property=Type=exec --property=KillMode=control-group --property=OOMPolicy=kill \
    --property=Restart=no --property=TimeoutStopSec=5s \
    /usr/bin/python3 "$fixture" writer "$scratch" "$unit" "$recovery"

[[ "$(sudo -n systemctl show "$unit" --property=KillMode --value)" == control-group ]]
[[ "$(sudo -n systemctl show "$unit" --property=OOMPolicy --value)" == kill ]]
read -r main_pid child_pid invocation < <(probe wait)
[[ "$main_pid" =~ ^[0-9]+$ && "$child_pid" =~ ^[0-9]+$ && "$main_pid" != "$child_pid" ]]
probe reject-live
probe reject-stale

# Kill only MainPID. PID1 must terminate the child and drain this cgroup.
sudo -n systemctl kill --kill-who=main --signal=SIGKILL "$unit"
wait_gone

# A restarted unit may reuse its cgroup. The old intent must not authorize
# recovery while the new incarnation is active.
sudo -n systemctl start "$unit"
read -r next_pid next_child next_invocation < <(probe wait "$invocation")
[[ "$next_pid" =~ ^[0-9]+$ && "$next_child" =~ ^[0-9]+$ && "$next_invocation" != "$invocation" ]]
probe reject-live
sudo -n systemctl kill --kill-who=main --signal=SIGKILL "$unit"
wait_gone
probe finish

printf 'PASS: real systemd drained both writer cgroups; mock PREPARED runtime was restored and rechecked.\n'
printf 'Locks, job barrier and runtime were fakes; application restore, OOM and boot were not tested.\n'
