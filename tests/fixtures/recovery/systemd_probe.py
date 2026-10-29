#!/usr/bin/env python3
"""Disposable systemd experiment; locks and job barrier are test doubles.

This tests PID1/cgroup cleanup and a PREPARED journal only. It does not test
the application's restore callback, service gate, OOM, or a reboot.
"""

import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch


def proc_stat(raw):
    # comm may contain spaces or parentheses; fields after its final ')' start
    # with field 3. Linux starttime is field 22.
    suffix = raw[raw.rfind(")") + 2:].split()
    if len(suffix) < 20 or raw.rfind(")") < 0:
        raise ValueError("invalid proc stat")
    return suffix[0], int(suffix[19])


def read_stat(pid):
    return proc_stat(Path("/proc/%d/stat" % pid).read_text())


def show(unit):
    result = subprocess.run(
        ["systemctl", "show", unit, "--property=LoadState,ActiveState,SubState,MainPID,ControlGroup,InvocationID"],
        check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    values = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    required = {"LoadState", "ActiveState", "SubState", "MainPID", "ControlGroup", "InvocationID"}
    if not required <= values.keys() or values["LoadState"] != "loaded":
        raise RuntimeError("cannot establish transient unit state")
    return values


def has_job(unit):
    result = subprocess.run(["systemctl", "list-jobs", "--no-legend", "--plain"],
                            check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return any(unit in line.split() for line in result.stdout.splitlines())


def populated(group):
    path = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
    try:
        fields = dict(line.split() for line in path.read_text().splitlines())
    except FileNotFoundError:
        return False
    if fields.get("populated") not in {"0", "1"}:
        raise RuntimeError("cgroup population is unavailable")
    return fields["populated"] == "1"


def unit_identity(unit):
    state = show(unit)
    pid = int(state["MainPID"])
    if pid <= 0 or not state["ControlGroup"] or not state["InvocationID"]:
        raise RuntimeError("writer is not active")
    status, ticks = read_stat(pid)
    if status == "Z":
        raise RuntimeError("writer is a zombie")
    return {"boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
            "unit": unit, "cgroup": state["ControlGroup"], "invocation_id": state["InvocationID"],
            "main_pid": pid, "proc_starttime": ticks}


def identity_matches(recorded):
    try:
        return unit_identity(recorded["unit"]) == recorded
    except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
        return False


def writer_gone(recorded):
    """Observation, not a barrier against a future systemd start job."""
    state = show(recorded["unit"])
    if state["ActiveState"] not in {"inactive", "failed"} or int(state["MainPID"]) != 0:
        return False
    if has_job(recorded["unit"]) or populated(recorded["cgroup"]):
        return False
    if state["ControlGroup"] and populated(state["ControlGroup"]):
        return False
    if recorded["boot_id"] == Path("/proc/sys/kernel/random/boot_id").read_text().strip():
        try:
            status, ticks = read_stat(recorded["main_pid"])
            if ticks == recorded["proc_starttime"] and status != "Z":
                return False
        except FileNotFoundError:
            pass
    return True


def atomic_json(path, value):
    temp = path.with_suffix(".tmp")
    with temp.open("w") as stream:
        json.dump(value, stream)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def module(path):
    spec = importlib.util.spec_from_file_location("recovery_smoke_module", path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def journal(recovery, directory):
    return recovery.Journal(directory / "journal", directory / "snapshots")


def yes(*args):
    return True


def writer(recovery, directory, unit):
    deadline = time.monotonic() + 20
    while True:
        try:
            identity = unit_identity(unit)
            if identity["main_pid"] == os.getpid() and identity["invocation_id"] == os.environ.get("INVOCATION_ID"):
                break
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError):
            pass
        if time.monotonic() > deadline:
            raise RuntimeError("PID1 did not confirm writer identity")
        time.sleep(0.1)
    instance = journal(recovery, directory)
    if not instance.path.exists():
        instance.begin("systemd-smoke", identity, {"test_only": True}, locks_held=yes,
                       writer_confirmed=identity_matches, job_barrier_held=yes, markers_clear=yes)
    child = subprocess.Popen(["/bin/sleep", "300"], close_fds=True)
    _, child_start = read_stat(child.pid)
    atomic_json(directory / "ready.json", {"writer": identity, "child_pid": child.pid,
                                           "child_start": child_start})
    while True:
        signal.pause()


def wait_ready(directory, unit, old_invocation):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            data = json.loads((directory / "ready.json").read_text())
            identity = data["writer"]
            if identity["invocation_id"] != old_invocation and identity_matches(identity):
                print(identity["main_pid"], data["child_pid"], identity["invocation_id"])
                return
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(0.1)
    raise RuntimeError("writer did not become ready")


def assert_rejected(recovery, directory, unit):
    instance = journal(recovery, directory)
    recorded = instance._load()
    if recorded["phase"] != "PREPARED" or recorded["writer"]["unit"] != unit:
        raise AssertionError("unexpected journal state")
    live = unit_identity(unit)
    if live["cgroup"] != recorded["writer"]["cgroup"]:
        raise AssertionError("test did not exercise the recorded cgroup")
    observed = []

    def gone(identity):
        result = writer_gone(identity)
        observed.append(result)
        return result

    try:
        instance.recover(locks_held=yes, job_barrier_held=yes, writer_gone=gone,
                         stopped=yes, markers_clear=yes, validate_snapshot=lambda path: [],
                         restore=lambda *args: (_ for _ in ()).throw(AssertionError("unexpected restore")))
    except recovery.RecoveryError:
        if observed != [False]:
            raise AssertionError("writer guard did not reject the live cgroup")
        return
    raise AssertionError("live writer was accepted")


def assert_stale_rejected(recovery, directory, unit):
    state = directory / "stale-journal"
    state.mkdir(mode=0o700)
    instance = recovery.Journal(state, directory / "snapshots")
    stale = unit_identity(unit)
    stale["invocation_id"] = ("a" if stale["invocation_id"][0] != "a" else "b") + stale["invocation_id"][1:]
    observed = []

    def confirm(identity):
        result = identity_matches(identity)
        observed.append(result)
        return result

    try:
        instance.begin("stale", stale, {}, locks_held=yes, writer_confirmed=confirm,
                       job_barrier_held=yes, markers_clear=yes)
    except recovery.RecoveryError:
        if observed != [False] or instance.path.exists():
            raise AssertionError("stale invocation was not rejected by its identity check")
        return
    raise AssertionError("stale invocation was accepted")


def assert_gone(directory, unit):
    data = json.loads((directory / "ready.json").read_text())
    if not writer_gone(data["writer"]):
        raise RuntimeError("unit, job, writer, or cgroup is still active")
    try:
        status, ticks = read_stat(data["child_pid"])
        if ticks == data["child_start"] and status != "Z":
            raise RuntimeError("writer child is still running")
    except FileNotFoundError:
        pass


def finish(recovery, directory):
    instance = journal(recovery, directory)
    if instance._load()["phase"] != "PREPARED":
        raise AssertionError("expected the original PREPARED journal")
    kwargs = dict(locks_held=yes, job_barrier_held=yes, writer_gone=writer_gone, stopped=yes,
                  markers_clear=yes, validate_snapshot=lambda path: [],
                  restore=lambda *args: (_ for _ in ()).throw(AssertionError("unexpected restore")))
    if instance.recover(**kwargs) != "RESTORED" or instance.recover(**kwargs) != "RESTORED":
        raise AssertionError("PREPARED recovery was not idempotent")


class FixtureTests(unittest.TestCase):
    def test_proc_stat_parses_parentheses_and_starttime(self):
        self.assertEqual(proc_stat("123 (child (test)) S " + " ".join(["0"] * 18 + ["12345"])), ("S", 12345))

    def test_proc_stat_rejects_incomplete_record(self):
        with self.assertRaises(ValueError):
            proc_stat("123 (child) S")

    def test_live_unit_cannot_be_declared_gone(self):
        with patch(__name__ + ".show", return_value={"ActiveState": "active", "MainPID": "22"}):
            self.assertFalse(writer_gone({"unit": "writer"}))

    def test_gone_rejects_queued_job_populated_group_and_live_original_pid(self):
        record = {"unit": "writer", "cgroup": "/writer", "boot_id": "boot",
                  "main_pid": 42, "proc_starttime": 777}
        unit = {"ActiveState": "failed", "MainPID": "0", "ControlGroup": ""}
        with patch(__name__ + ".show", return_value=unit), \
             patch(__name__ + ".has_job", return_value=True):
            self.assertFalse(writer_gone(record))
        with patch(__name__ + ".show", return_value=unit), \
             patch(__name__ + ".has_job", return_value=False), \
             patch(__name__ + ".populated", return_value=True):
            self.assertFalse(writer_gone(record))
        with patch(__name__ + ".show", return_value=unit), \
             patch(__name__ + ".has_job", return_value=False), \
             patch(__name__ + ".populated", return_value=False), \
             patch.object(Path, "read_text", return_value="boot"), \
             patch(__name__ + ".read_stat", return_value=("S", 777)):
            self.assertFalse(writer_gone(record))


def main():
    if sys.argv[1:] == ["self-test"]:
        unittest.main(argv=[sys.argv[0]])
        return
    action, directory, unit, recovery_path, *rest = sys.argv[1:]
    directory = Path(directory)
    recovery = module(recovery_path)
    if action == "writer":
        writer(recovery, directory, unit)
    elif action == "wait":
        wait_ready(directory, unit, rest[0] if rest else "")
    elif action == "reject-live":
        assert_rejected(recovery, directory, unit)
    elif action == "reject-stale":
        assert_stale_rejected(recovery, directory, unit)
    elif action == "gone":
        assert_gone(directory, unit)
    elif action == "finish":
        finish(recovery, directory)
    else:
        raise ValueError("unknown action")


if __name__ == "__main__":
    main()
