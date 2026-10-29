#!/usr/bin/env python3
"""Disposable FDSTORE/flock experiment. No application state is touched."""

import argparse
import ctypes
import errno
import fcntl
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from deploy.lib import mtproxyl_controller as controller

ROLES = ("operation", "health", "front")
MODES = {"operation": 0o644, "health": 0o644, "front": 0o600}


def write_once(path, value):
    """Publish a complete test record without replacing an earlier record."""
    fd, temporary = tempfile.mkstemp(prefix=".fdstore-probe-", dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
        os.link(temporary, path)
    finally:
        os.unlink(temporary)


def initialize(directory, suffix):
    """Create only isolated fixtures, before the supervisor is started."""
    if not re.fullmatch(r"[a-f0-9]{32}", suffix):
        raise RuntimeError("invalid probe suffix")
    locks = {}
    for index, role in enumerate(ROLES):
        path = directory / (role + ".lock")
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, MODES[role])
        try:
            os.fchmod(fd, MODES[role])
            info = os.fstat(fd)
            locks[role] = {"name": "%s-%s" % (role, suffix), "file": path.name,
                           "device": info.st_dev, "inode": info.st_ino,
                           "mode": MODES[role], "offset": int(suffix[:8], 16) * 4 + index + 1}
        finally:
            os.close(fd)
    if len({(item["device"], item["inode"]) for item in locks.values()}) != len(ROLES):
        raise RuntimeError("fixture lock inodes are not distinct")
    write_once(directory / "state.json", {"suffix": suffix, "locks": locks})


def load_state(directory):
    value = json.loads((directory / "state.json").read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != {"suffix", "locks"}:
        raise RuntimeError("invalid probe state")
    suffix, locks = value["suffix"], value["locks"]
    if (not isinstance(suffix, str) or not re.fullmatch(r"[a-f0-9]{32}", suffix)
            or not isinstance(locks, dict) or set(locks) != set(ROLES)):
        raise RuntimeError("invalid probe lock set")
    for role in ROLES:
        item = locks[role]
        if (not isinstance(item, dict) or set(item) != {"name", "file", "device", "inode", "mode", "offset"}
                or item["name"] != "%s-%s" % (role, suffix) or item["file"] != role + ".lock"
                or item["mode"] != MODES[role]
                or not all(type(item.get(key)) is int and item[key] >= 0
                           for key in ("device", "inode", "offset"))):
            raise RuntimeError("invalid probe lock record")
    if len({(item["device"], item["inode"]) for item in locks.values()}) != len(ROLES):
        raise RuntimeError("probe lock identities are not distinct")
    return value


def check_file_identity(fd, directory, state, role):
    item = state["locks"][role]
    current = os.fstat(fd)
    pathname = (directory / item["file"]).lstat()
    expected = (item["device"], item["inode"])
    if (not stat.S_ISREG(current.st_mode) or not stat.S_ISREG(pathname.st_mode)
            or (current.st_dev, current.st_ino) != expected
            or (pathname.st_dev, pathname.st_ino) != expected
            or current.st_uid != os.geteuid() or current.st_nlink != 1
            or stat.S_IMODE(current.st_mode) != item["mode"] or current.st_mode & 0o022
            or role == "front" and current.st_mode & 0o077):
        raise RuntimeError("lock file identity or permissions changed")


def check_received_fd(fd, directory, state, role):
    check_file_identity(fd, directory, state, role)
    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDWR:
        raise RuntimeError("unexpected inherited file access mode")
    if os.lseek(fd, 0, os.SEEK_CUR) != state["locks"][role]["offset"]:
        raise RuntimeError("inherited file description offset changed")


def inherited_fds(state, environment, pid):
    if environment.get("LISTEN_PID") != str(pid) or environment.get("LISTEN_FDS") != str(len(ROLES)):
        raise RuntimeError("expected exactly three FDSTORE descriptors")
    names = environment.get("LISTEN_FDNAMES", "").split(":")
    expected = {state["locks"][role]["name"] for role in ROLES}
    if len(names) != len(ROLES) or len(set(names)) != len(ROLES) or set(names) != expected:
        raise RuntimeError("FDSTORE names are missing, extra, or duplicated")
    return {role: 3 + names.index(state["locks"][role]["name"]) for role in ROLES}


def check_descriptor_set(descriptors, directory, state):
    if set(descriptors) != set(ROLES) or len(set(descriptors.values())) != len(ROLES):
        raise RuntimeError("unexpected descriptor set")
    for role in ROLES:
        check_received_fd(descriptors[role], directory, state, role)


def must_reject(callback):
    try:
        callback()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError):
        return
    raise RuntimeError("injected invalid descriptor set was accepted")


def inject_invalid_receipts(state, directory, descriptors, environment, pid):
    """Exercise failure paths without modifying any locked descriptor."""
    for value in ("0", "2", "4"):
        broken = dict(environment, LISTEN_FDS=value)
        must_reject(lambda: inherited_fds(state, broken, pid))
    broken = dict(environment, LISTEN_PID=str(pid + 1))
    must_reject(lambda: inherited_fds(state, broken, pid))
    broken = dict(environment, LISTEN_FDNAMES=":".join([state["locks"]["operation"]["name"]] * 3))
    must_reject(lambda: inherited_fds(state, broken, pid))
    broken = dict(environment, LISTEN_FDNAMES=environment["LISTEN_FDNAMES"] + ":extra")
    must_reject(lambda: inherited_fds(state, broken, pid))
    broken_set = dict(descriptors, front=descriptors["health"])
    must_reject(lambda: check_descriptor_set(broken_set, directory, state))
    for index, role in enumerate(ROLES):
        other = ROLES[(index + 1) % len(ROLES)]
        must_reject(lambda: check_received_fd(descriptors[other], directory, state, role))


def assert_lock_records(fdinfo, all_locks, item):
    """Use descriptor-specific flock evidence; numeric proc line IDs differ."""
    target = (os.major(item["device"]), os.minor(item["device"]), item["inode"])
    owners = []
    for line in fdinfo.splitlines():
        fields = line.split()
        if len(fields) != 9 or fields[0] != "lock:" or fields[2:5] != ["FLOCK", "ADVISORY", "WRITE"]:
            continue
        try:
            owner = int(fields[5])
            major, minor, inode = fields[6].split(":")
            found = (int(major, 16), int(minor, 16), int(inode))
        except ValueError:
            continue
        if owner >= 0 and found == target and fields[7:] == ["0", "EOF"]:
            owners.append(owner)
    if len(owners) != 1:
        raise RuntimeError("descriptor-specific flock is unavailable")
    for line in all_locks.splitlines():
        fields = line.split()
        if len(fields) < 8 or fields[1:4] != ["FLOCK", "ADVISORY", "WRITE"]:
            continue  # Also excludes waiting entries marked ->.
        try:
            owner = int(fields[4])
            major, minor, inode = fields[5].split(":")
            found = (int(major, 16), int(minor, 16), int(inode))
        except ValueError:
            continue
        if owner == owners[0] and found == target and fields[6:8] == ["0", "EOF"]:
            return
    raise RuntimeError("descriptor lock is absent from /proc/locks")


def verify_locked_descriptor(fd, directory, state, role):
    check_received_fd(fd, directory, state, role)
    fdinfo = Path("/proc/self/fdinfo/%d" % fd).read_text(encoding="ascii")
    global_locks = Path("/proc/locks").read_text(encoding="ascii")
    assert_lock_records(fdinfo, global_locks, state["locks"][role])
    if role == "front":
        controller._assert_lock_held(fd, directory / state["locks"][role]["file"])


def notify(message, descriptor=None):
    """Use systemd's implementation, including its real notify barrier."""
    library = ctypes.CDLL("libsystemd.so.0")
    if descriptor is None:
        call = library.sd_notify
        call.argtypes = [ctypes.c_int, ctypes.c_char_p]
        call.restype = ctypes.c_int
        result = call(0, message.encode("ascii"))
    else:
        call = library.sd_pid_notify_with_fds
        call.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p,
                         ctypes.POINTER(ctypes.c_int), ctypes.c_uint]
        call.restype = ctypes.c_int
        fds = (ctypes.c_int * 1)(descriptor)
        result = call(0, 0, message.encode("ascii"), fds, 1)
    if result <= 0:
        raise RuntimeError("systemd did not accept the notify submission: %s" % result)


def barrier():
    library = ctypes.CDLL("libsystemd.so.0")
    call = library.sd_notify_barrier
    call.argtypes = [ctypes.c_int, ctypes.c_uint64]
    call.restype = ctypes.c_int
    result = call(0, 10_000_000)
    if result <= 0:
        raise RuntimeError("systemd notify barrier failed: %s" % result)
    # A barrier is only processing acknowledgement, not FDSTORE acceptance.


def proc_starttime(pid):
    value = Path("/proc/%d/stat" % pid).read_text(encoding="utf-8")
    right = value.rfind(")")
    fields = value[right + 2:].split()
    if right < 0 or len(fields) < 20:
        raise RuntimeError("invalid proc stat")
    return int(fields[19])


def invocation():
    value = os.environ.get("INVOCATION_ID", "")
    if not re.fullmatch(r"[a-f0-9]{32}", value):
        raise RuntimeError("systemd invocation identity is missing")
    return value


def acquire_existing_locks(directory, state):
    """Initial acquisition only, in the common lock order."""
    descriptors = {}
    try:
        for role in ROLES:
            fd = os.open(directory / state["locks"][role]["file"], os.O_RDWR | os.O_NOFOLLOW)
            descriptors[role] = fd
            check_file_identity(fd, directory, state, role)
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.lseek(fd, state["locks"][role]["offset"], os.SEEK_SET)
        return descriptors
    except BaseException:
        for fd in descriptors.values():
            os.close(fd)
        raise


def supervisor(directory, suffix):
    state = load_state(directory)
    if suffix != state["suffix"]:
        raise RuntimeError("probe identity changed")
    if not (directory / "started.json").exists():
        if os.environ.get("LISTEN_FDS", "0") != "0":
            raise RuntimeError("unexpected inherited descriptors on initial start")
        # A crash at any point after this marker must never reacquire locks.
        write_once(directory / "started.json", {"suffix": suffix})
        descriptors = acquire_existing_locks(directory, state)
        for role in ROLES:
            notify("FDSTORE=1\nFDNAME=%s\nFDPOLL=0" % state["locks"][role]["name"], descriptors[role])
        barrier()
        phase = 0
    else:
        if not (directory / "phase-0.json").exists():
            raise RuntimeError("initial supervisor did not complete; no lock reacquisition")
        # A stored OFD must never be relocked or explicitly unlocked. Exercise
        # missing/extra/wrong-inode paths while flock calls are forbidden.
        with mock.patch.object(fcntl, "flock", side_effect=AssertionError("unexpected reacquisition")):
            descriptors = inherited_fds(state, os.environ, os.getpid())
            check_descriptor_set(descriptors, directory, state)
            inject_invalid_receipts(state, directory, descriptors, os.environ, os.getpid())
            for role in ROLES:
                verify_locked_descriptor(descriptors[role], directory, state, role)
        phase = 1 if not (directory / "phase-1.json").exists() else 2
        if (directory / ("phase-%d.json" % phase)).exists():
            raise RuntimeError("unexpected extra supervisor restart")
    if phase == 0:
        for role in ROLES:
            verify_locked_descriptor(descriptors[role], directory, state, role)
    write_once(directory / ("phase-%d.json" % phase), {
        "phase": phase, "pid": os.getpid(), "starttime": proc_starttime(os.getpid()),
        "invocation": invocation(), "acquired_order": list(ROLES) if phase == 0 else [],
        "descriptors": {role: {"fd": descriptors[role], **state["locks"][role]} for role in ROLES},
        "received_from_fdstore": phase > 0,
    })
    notify("READY=1")
    while True:
        signal.pause()


def check_lock(directory, role):
    state = load_state(directory)
    fd = os.open(directory / state["locks"][role]["file"], os.O_RDWR | os.O_NOFOLLOW)
    try:
        check_file_identity(fd, directory, state, role)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return
            raise
        raise RuntimeError("independent process acquired the supposedly held lock")
    finally:
        os.close(fd)


def contender(directory, role):
    state = load_state(directory)
    item = state["locks"][role]
    fd = os.open(directory / item["file"], os.O_RDWR | os.O_NOFOLLOW)
    check_file_identity(fd, directory, state, role)
    identity = {"pid": os.getpid(), "invocation": invocation(), "starttime": proc_starttime(os.getpid()),
                "fd": fd, "device": item["device"], "inode": item["inode"]}
    write_once(directory / ("started-" + role + ".json"), identity)
    notify("READY=1")
    # Start the legacy-style independent process before the new supervisor.
    # Its first lock attempt is released only after the supervisor owns all
    # three existing inodes; this gate does not represent a production API.
    deadline = time.monotonic() + 120
    while not (directory / "waiters-go").exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("contender start gate timed out")
        time.sleep(0.05)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno not in (errno.EACCES, errno.EAGAIN):
            raise
    else:
        write_once(directory / ("breach-" + role + ".json"), {"reason": "initially unlocked"})
        while True:
            signal.pause()
    write_once(directory / ("waiting-" + role + ".json"), identity)
    # Blocking until the lock is released catches a release during the restart
    # window without sampling. If acquired, hold it until the test stops us.
    fcntl.flock(fd, fcntl.LOCK_EX)
    write_once(directory / ("breach-" + role + ".json"), {"reason": "lock released while waiting"})
    while True:
        signal.pause()


def validate_preexisting_waiter(directory, role, expected_pid, expected_invocation):
    state = load_state(directory)
    item = state["locks"][role]
    waiting = json.loads((directory / ("started-" + role + ".json")).read_text(encoding="utf-8"))
    if (waiting.get("pid") != expected_pid or waiting.get("invocation") != expected_invocation
            or waiting.get("starttime") != proc_starttime(expected_pid)
            or waiting.get("device") != item["device"] or waiting.get("inode") != item["inode"]
            or (directory / "waiters-go").exists()
            or (directory / ("breach-" + role + ".json")).exists()
            or (directory / ("waiting-" + role + ".json")).exists()):
        raise RuntimeError("pre-existing contender identity changed")
    info = os.stat("/proc/%d/fd/%d" % (expected_pid, waiting["fd"]))
    if (info.st_dev, info.st_ino) != (item["device"], item["inode"]):
        raise RuntimeError("pre-existing contender opened a different inode")


def validate_waiter(directory, role, expected_pid, expected_invocation):
    state = load_state(directory)
    item = state["locks"][role]
    waiting = json.loads((directory / ("waiting-" + role + ".json")).read_text(encoding="utf-8"))
    started = json.loads((directory / ("started-" + role + ".json")).read_text(encoding="utf-8"))
    if (waiting.get("pid") != expected_pid or waiting.get("invocation") != expected_invocation
            or waiting.get("starttime") != proc_starttime(expected_pid)
            or waiting.get("device") != item["device"] or waiting.get("inode") != item["inode"]
            or waiting != started
            or (directory / ("breach-" + role + ".json")).exists()):
        raise RuntimeError("independent waiter identity changed or acquired the lock")
    fd = waiting["fd"]
    info = os.stat("/proc/%d/fd/%d" % (expected_pid, fd))
    if (info.st_dev, info.st_ino) != (item["device"], item["inode"]):
        raise RuntimeError("independent waiter opened a different file")
    # Confirm the contender is already blocked inside flock, not just between
    # its nonblocking check and the blocking call. Unknown architectures fail.
    numbers = {"x86_64": 73, "aarch64": 32}
    number = numbers.get(os.uname().machine)
    if number is None:
        raise RuntimeError("unsupported syscall architecture")
    fields = Path("/proc/%d/syscall" % expected_pid).read_text(encoding="utf-8").split()
    if (len(fields) < 3 or fields[0] != str(number)
            or int(fields[1], 0) != fd or int(fields[2], 0) != fcntl.LOCK_EX):
        raise RuntimeError("independent waiter is not blocked in flock")


def validate_phase(directory, phase, expected_pid, expected_invocation):
    state = load_state(directory)
    previous = []
    for index in range(phase + 1):
        event = json.loads((directory / ("phase-%d.json" % index)).read_text(encoding="utf-8"))
        if (event.get("phase") != index or not isinstance(event.get("descriptors"), dict)
                or set(event["descriptors"]) != set(ROLES)
                or event.get("acquired_order") != (list(ROLES) if index == 0 else [])
                or event.get("received_from_fdstore") is not (index > 0)
                or not re.fullmatch(r"[a-f0-9]{32}", event.get("invocation", ""))):
            raise RuntimeError("invalid phase record")
        fds = []
        for role in ROLES:
            descriptor = event["descriptors"][role]
            if (not isinstance(descriptor, dict) or set(descriptor) != set(state["locks"][role]) | {"fd"}
                    or any(descriptor.get(key) != value for key, value in state["locks"][role].items())
                    or type(descriptor["fd"]) is not int or descriptor["fd"] < 0):
                raise RuntimeError("phase descriptor identity changed")
            fds.append(descriptor["fd"])
        if len(set(fds)) != len(ROLES) or index > 0 and set(fds) != {3, 4, 5}:
            raise RuntimeError("unexpected descriptor numbers")
        if index == 0:
            for role in ROLES:
                started = json.loads((directory / ("started-" + role + ".json")).read_text(encoding="utf-8"))
                if (type(started.get("starttime")) is not int or type(event.get("starttime")) is not int
                        or started["starttime"] > event["starttime"] or started.get("pid") == event.get("pid")):
                    raise RuntimeError("contender did not predate the supervisor")
        previous.append(event)
    if len({event["invocation"] for event in previous}) != len(previous):
        raise RuntimeError("supervisor invocation did not change")
    current = previous[-1]
    if (current["pid"] != expected_pid or current["invocation"] != expected_invocation
            or proc_starttime(expected_pid) != current["starttime"]):
        raise RuntimeError("running supervisor identity changed")
    global_locks = Path("/proc/locks").read_text(encoding="ascii")
    for role in ROLES:
        item = state["locks"][role]
        descriptor = current["descriptors"][role]["fd"]
        file_info = os.stat("/proc/%d/fd/%d" % (expected_pid, descriptor))
        pathname = (directory / item["file"]).lstat()
        if (file_info.st_dev, file_info.st_ino) != (item["device"], item["inode"]) or (
                pathname.st_dev, pathname.st_ino) != (item["device"], item["inode"]):
            raise RuntimeError("supervisor descriptor identity changed")
        info = Path("/proc/%d/fdinfo/%d" % (expected_pid, descriptor)).read_text(encoding="ascii")
        fields = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
        if int(fields.get("pos", "-1").strip()) != item["offset"]:
            raise RuntimeError("supervisor descriptor offset changed")
        assert_lock_records(info, global_locks, item)
        check_lock(directory, role)
        if (directory / ("breach-" + role + ".json")).exists():
            raise RuntimeError("independent waiter acquired the lock")


def selftest():
    with tempfile.TemporaryDirectory(prefix="fdstore-probe-selftest-") as location:
        directory = Path(location)
        suffix = "a" * 32
        initialize(directory, suffix)
        state = load_state(directory)
        descriptors, copies = {}, {}
        try:
            order = []
            real_flock = fcntl.flock

            def capture_order(fd, operation):
                info = os.fstat(fd)
                matches = [role for role in ROLES if (info.st_dev, info.st_ino)
                           == (state["locks"][role]["device"], state["locks"][role]["inode"])]
                if len(matches) != 1 or operation != (fcntl.LOCK_EX | fcntl.LOCK_NB):
                    raise RuntimeError("unexpected initial flock call")
                order.append(matches[0])
                return real_flock(fd, operation)

            with mock.patch.object(fcntl, "flock", side_effect=capture_order):
                descriptors = acquire_existing_locks(directory, state)
            if order != list(ROLES):
                raise RuntimeError("incorrect initial lock order")
            for role in ROLES:
                copies[role] = os.dup(descriptors[role])
            environment = {"LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "3",
                           "LISTEN_FDNAMES": ":".join(state["locks"][role]["name"] for role in ROLES)}
            if inherited_fds(state, environment, os.getpid()) != dict(zip(ROLES, (3, 4, 5))):
                raise RuntimeError("valid descriptor names were mapped incorrectly")
            reversed_environment = dict(environment, LISTEN_FDNAMES=":".join(
                state["locks"][role]["name"] for role in reversed(ROLES)))
            if inherited_fds(state, reversed_environment, os.getpid()) != dict(zip(ROLES, (5, 4, 3))):
                raise RuntimeError("reordered descriptor names were mapped incorrectly")
            with mock.patch.object(fcntl, "flock", side_effect=AssertionError("unexpected reacquisition")):
                check_descriptor_set(copies, directory, state)
                inject_invalid_receipts(state, directory, copies, environment, os.getpid())
                missing_fd = os.dup(descriptors["front"])
                os.close(missing_fd)
                must_reject(lambda: check_descriptor_set(dict(copies, front=missing_fd), directory, state))
                path = directory / state["locks"]["health"]["file"]
                original = directory / "health.saved"
                path.rename(original)
                try:
                    path.write_text("replacement", encoding="utf-8")
                    must_reject(lambda: check_descriptor_set(copies, directory, state))
                finally:
                    path.unlink(missing_ok=True)
                    original.rename(path)
                for role, unsafe_mode in (("health", 0o664), ("front", 0o644)):
                    path = directory / state["locks"][role]["file"]
                    os.chmod(path, unsafe_mode)
                    try:
                        must_reject(lambda: check_descriptor_set(copies, directory, state))
                    finally:
                        os.chmod(path, MODES[role])
                # A crashed initial start cannot acquire the files again.
                write_once(directory / "started.json", {"suffix": suffix})
                with mock.patch.dict(os.environ, environment):
                    must_reject(lambda: supervisor(directory, suffix))
                # An incomplete or extra receipt after a completed initial
                # start must also fail before any flock call.
                write_once(directory / "phase-0.json", {})
                for count in ("2", "4"):
                    with mock.patch.dict(os.environ, dict(environment, LISTEN_FDS=count)):
                        must_reject(lambda: supervisor(directory, suffix))
                foreign = os.open(directory / state["locks"]["health"]["file"], os.O_RDWR | os.O_NOFOLLOW)
                try:
                    missing_fd = os.dup(descriptors["front"])
                    os.close(missing_fd)
                    for invalid in (missing_fd, foreign):
                        bad = dict(copies, operation=invalid)
                        with mock.patch.dict(os.environ, environment), mock.patch.object(
                                sys.modules[__name__], "inherited_fds", return_value=bad):
                            must_reject(lambda: supervisor(directory, suffix))
                finally:
                    os.close(foreign)
                # Exercise both successful receipt branches locally with
                # systemd/proc checks mocked and flock still prohibited.
                class StopProbe(Exception):
                    pass

                current = sys.modules[__name__]
                original_inherited_fds = inherited_fds

                def simulated_receipt(record, variables, pid):
                    original_inherited_fds(record, variables, pid)
                    return copies

                with mock.patch.dict(os.environ, environment), \
                        mock.patch.object(current, "inherited_fds", side_effect=simulated_receipt), \
                        mock.patch.object(current, "verify_locked_descriptor"), \
                        mock.patch.object(current, "proc_starttime", return_value=123), \
                        mock.patch.object(current, "invocation", side_effect=["1" * 32, "2" * 32]), \
                        mock.patch.object(current, "notify"), \
                        mock.patch.object(signal, "pause", side_effect=StopProbe):
                    for phase in (1, 2):
                        try:
                            supervisor(directory, suffix)
                        except StopProbe:
                            pass
                        else:
                            raise RuntimeError("supervisor unexpectedly returned")
                        event = json.loads((directory / ("phase-%d.json" % phase)).read_text(encoding="utf-8"))
                        if (event.get("received_from_fdstore") is not True or event.get("acquired_order")
                                or {role: event["descriptors"][role]["fd"] for role in ROLES} != copies):
                            raise RuntimeError("restored descriptor receipt was not recorded")
            for role in ROLES:
                item = state["locks"][role]
                dev = "%x:%x:%d" % (os.major(item["device"]), os.minor(item["device"]), item["inode"])
                scoped = "lock:\t1: FLOCK ADVISORY WRITE 73 %s 0 EOF\n" % dev
                global_entry = "42: FLOCK ADVISORY WRITE 73 %s 0 EOF\n" % dev
                assert_lock_records(scoped, global_entry, item)
                must_reject(lambda: assert_lock_records(scoped, "", item))
                must_reject(lambda: assert_lock_records(scoped, global_entry.replace("WRITE 73", "WRITE 74"), item))
                command = [sys.executable, __file__, "check-lock", str(directory), role]
                if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                    raise RuntimeError("held lock was not detected")
            os.close(copies.pop("operation"))
            os.close(descriptors.pop("operation"))
            command = [sys.executable, __file__, "check-lock", str(directory), "operation"]
            if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                raise RuntimeError("unlocked file was incorrectly accepted")
        finally:
            for fd in (*copies.values(), *descriptors.values()):
                os.close(fd)
    print("PASS: three existing lock identities, invalid receipts, no reacquisition, and independent observers")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("initialize", "supervisor", "contender", "check-lock", "validate-phase",
                                           "validate-preexisting-waiter", "validate-waiter", "selftest"))
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("arguments", nargs="*")
    args = parser.parse_args()
    if args.action == "selftest":
        if args.directory or args.arguments:
            parser.error("selftest takes no arguments")
        selftest()
        return
    if args.directory is None or not args.directory.is_dir():
        parser.error("test directory is required")
    if args.action == "initialize" and len(args.arguments) == 1:
        initialize(args.directory, args.arguments[0])
    elif args.action == "supervisor" and len(args.arguments) == 1:
        supervisor(args.directory, args.arguments[0])
    elif args.action == "contender" and len(args.arguments) == 1 and args.arguments[0] in ROLES:
        contender(args.directory, args.arguments[0])
    elif args.action == "check-lock" and len(args.arguments) == 1 and args.arguments[0] in ROLES:
        check_lock(args.directory, args.arguments[0])
    elif args.action == "validate-phase" and len(args.arguments) == 3:
        phase, pid, unit_invocation = args.arguments
        if phase not in ("0", "1", "2") or not re.fullmatch(r"[1-9][0-9]*", pid):
            parser.error("invalid phase or supervisor PID")
        validate_phase(args.directory, int(phase), int(pid), unit_invocation)
    elif args.action in ("validate-preexisting-waiter", "validate-waiter") and len(args.arguments) == 3:
        role, pid, unit_invocation = args.arguments
        if role not in ROLES or not re.fullmatch(r"[1-9][0-9]*", pid):
            parser.error("invalid contender PID")
        if args.action == "validate-preexisting-waiter":
            validate_preexisting_waiter(args.directory, role, int(pid), unit_invocation)
        else:
            validate_waiter(args.directory, role, int(pid), unit_invocation)
    else:
        parser.error("invalid action arguments")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print("fdstore probe: %s" % exc, file=sys.stderr)
        raise SystemExit(1)
