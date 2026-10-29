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
from pathlib import Path


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


def load_state(directory):
    value = json.loads((directory / "state.json").read_text(encoding="utf-8"))
    if (not isinstance(value, dict) or not re.fullmatch(r"lock-[a-f0-9]{32}", value.get("name", ""))
            or not all(type(value.get(key)) is int and value[key] >= 0
                       for key in ("device", "inode", "offset"))):
        raise RuntimeError("invalid probe state")
    return value


def check_file_identity(fd, directory, state):
    current = os.fstat(fd)
    pathname = (directory / "lock").lstat()
    expected = (state["device"], state["inode"])
    if (not stat.S_ISREG(current.st_mode) or not stat.S_ISREG(pathname.st_mode)
            or (current.st_dev, current.st_ino) != expected
            or (pathname.st_dev, pathname.st_ino) != expected
            or current.st_uid != os.geteuid() or current.st_mode & 0o077):
        raise RuntimeError("lock file identity or permissions changed")


def check_received_fd(fd, directory, state):
    check_file_identity(fd, directory, state)
    if fcntl.fcntl(fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDWR:
        raise RuntimeError("unexpected inherited file access mode")
    if os.lseek(fd, 0, os.SEEK_CUR) != state["offset"]:
        raise RuntimeError("inherited file description offset changed")


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


def supervisor(directory, name):
    if not re.fullmatch(r"lock-[a-f0-9]{32}", name):
        raise RuntimeError("invalid FD name")
    state_path = directory / "state.json"
    if not state_path.exists():
        if os.environ.get("LISTEN_FDS", "0") != "0":
            raise RuntimeError("unexpected inherited descriptors on initial start")
        fd = os.open(directory / "lock", os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        info = os.fstat(fd)
        offset = int.from_bytes(os.urandom(4), "big") + 1
        os.lseek(fd, offset, os.SEEK_SET)
        state = {"device": info.st_dev, "inode": info.st_ino, "offset": offset, "name": name}
        write_once(state_path, state)
        notify("FDSTORE=1\nFDNAME=%s\nFDPOLL=0" % name, fd)
        barrier()
        phase = 0
    else:
        state = load_state(directory)
        if state["name"] != name:
            raise RuntimeError("FD name changed")
        if (os.environ.get("LISTEN_PID") != str(os.getpid())
                or os.environ.get("LISTEN_FDS") != "1"
                or os.environ.get("LISTEN_FDNAMES") != name):
            raise RuntimeError("expected exactly one named FDSTORE descriptor")
        fd = 3  # SD_LISTEN_FDS_START
        check_received_fd(fd, directory, state)
        phase = 1 if not (directory / "phase-1.json").exists() else 2
        if (directory / ("phase-%d.json" % phase)).exists():
            raise RuntimeError("unexpected extra supervisor restart")
    write_once(directory / ("phase-%d.json" % phase), {
        "phase": phase, "pid": os.getpid(), "starttime": proc_starttime(os.getpid()),
        "invocation": invocation(), "fd": fd, "name": state["name"],
        "device": state["device"], "inode": state["inode"],
        "offset": os.lseek(fd, 0, os.SEEK_CUR),
        "received_from_fdstore": phase > 0,
    })
    notify("READY=1")
    while True:
        signal.pause()


def check_lock(directory):
    state = load_state(directory)
    fd = os.open(directory / "lock", os.O_RDWR | os.O_NOFOLLOW)
    try:
        check_file_identity(fd, directory, state)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return
            raise
        raise RuntimeError("independent process acquired the supposedly held lock")
    finally:
        os.close(fd)


def contender(directory):
    state = load_state(directory)
    fd = os.open(directory / "lock", os.O_RDWR | os.O_NOFOLLOW)
    check_file_identity(fd, directory, state)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        if exc.errno not in (errno.EACCES, errno.EAGAIN):
            raise
    else:
        write_once(directory / "breach.json", {"reason": "initially unlocked"})
        notify("READY=1")
        while True:
            signal.pause()
    write_once(directory / "waiting.json", {
        "pid": os.getpid(), "invocation": invocation(), "starttime": proc_starttime(os.getpid()),
        "fd": fd, "device": state["device"], "inode": state["inode"],
    })
    notify("READY=1")
    # Blocking until the lock is released catches a release during the restart
    # window without sampling. If acquired, hold it until the test stops us.
    fcntl.flock(fd, fcntl.LOCK_EX)
    write_once(directory / "breach.json", {"reason": "lock released while waiting"})
    while True:
        signal.pause()


def validate_waiter(directory, expected_pid, expected_invocation):
    state = load_state(directory)
    waiting = json.loads((directory / "waiting.json").read_text(encoding="utf-8"))
    if (waiting.get("pid") != expected_pid or waiting.get("invocation") != expected_invocation
            or waiting.get("starttime") != proc_starttime(expected_pid)
            or waiting.get("device") != state["device"] or waiting.get("inode") != state["inode"]
            or (directory / "breach.json").exists()):
        raise RuntimeError("independent waiter identity changed or acquired the lock")
    fd = waiting["fd"]
    info = os.stat("/proc/%d/fd/%d" % (expected_pid, fd))
    if (info.st_dev, info.st_ino) != (state["device"], state["inode"]):
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
        if (event.get("phase") != index or event.get("name") != state["name"]
                or event.get("device") != state["device"] or event.get("inode") != state["inode"]
                or event.get("offset") != state["offset"]
                or event.get("received_from_fdstore") is not (index > 0)
                or not re.fullmatch(r"[a-f0-9]{32}", event.get("invocation", ""))):
            raise RuntimeError("invalid phase record")
        previous.append(event)
    if len({event["invocation"] for event in previous}) != len(previous):
        raise RuntimeError("supervisor invocation did not change")
    current = previous[-1]
    if (current["pid"] != expected_pid or current["invocation"] != expected_invocation
            or proc_starttime(expected_pid) != current["starttime"]):
        raise RuntimeError("running supervisor identity changed")
    descriptor = current["fd"]
    if phase > 0 and descriptor != 3:
        raise RuntimeError("unexpected inherited descriptor number")
    file_info = os.stat("/proc/%d/fd/%d" % (expected_pid, descriptor))
    if (file_info.st_dev, file_info.st_ino) != (state["device"], state["inode"]):
        raise RuntimeError("supervisor descriptor identity changed")
    info = Path("/proc/%d/fdinfo/%d" % (expected_pid, descriptor)).read_text(encoding="utf-8")
    fields = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
    if int(fields.get("pos", "-1").strip()) != state["offset"]:
        raise RuntimeError("supervisor descriptor offset changed")
    locked = False
    for line in info.splitlines():
        fields = line.split()
        if len(fields) < 9 or fields[0] != "lock:" or fields[2:5] != ["FLOCK", "ADVISORY", "WRITE"]:
            continue
        device_inode = fields[6].split(":")
        if (len(device_inode) == 3
                and int(device_inode[0], 16) == os.major(state["device"])
                and int(device_inode[1], 16) == os.minor(state["device"])
                and int(device_inode[2]) == state["inode"] and fields[7:9] == ["0", "EOF"]):
            locked = True
    if not locked:
        raise RuntimeError("inherited descriptor does not carry the expected flock")
    check_lock(directory)
    if (directory / "breach.json").exists():
        raise RuntimeError("independent waiter acquired the lock")


def selftest():
    with tempfile.TemporaryDirectory(prefix="fdstore-probe-selftest-") as location:
        directory = Path(location)
        fd = os.open(directory / "lock", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            info = os.fstat(fd)
            os.lseek(fd, 12345, os.SEEK_SET)
            state = {"device": info.st_dev, "inode": info.st_ino,
                     "offset": 12345, "name": "lock-" + "a" * 32}
            write_once(directory / "state.json", state)
            copy = os.dup(fd)
            try:
                check_received_fd(copy, directory, state)
            finally:
                os.close(copy)
            other = os.open(directory / "lock", os.O_RDWR)
            try:
                try:
                    check_received_fd(other, directory, state)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError("different open file description was accepted")
            finally:
                os.close(other)
            command = [sys.executable, __file__, "check-lock", str(directory)]
            if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
                raise RuntimeError("held lock was not detected")
            fcntl.flock(fd, fcntl.LOCK_UN)
            if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                raise RuntimeError("unlocked file was incorrectly accepted")
        finally:
            os.close(fd)
    print("PASS: independent lock observer and file-description offset controls")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("supervisor", "contender", "check-lock", "validate-phase",
                                           "validate-waiter", "selftest"))
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
    if args.action == "supervisor" and len(args.arguments) == 1:
        supervisor(args.directory, args.arguments[0])
    elif args.action == "contender" and not args.arguments:
        contender(args.directory)
    elif args.action == "check-lock" and not args.arguments:
        check_lock(args.directory)
    elif args.action == "validate-phase" and len(args.arguments) == 3:
        phase, pid, unit_invocation = args.arguments
        if phase not in ("0", "1", "2") or not re.fullmatch(r"[1-9][0-9]*", pid):
            parser.error("invalid phase or supervisor PID")
        validate_phase(args.directory, int(phase), int(pid), unit_invocation)
    elif args.action == "validate-waiter" and len(args.arguments) == 2:
        pid, unit_invocation = args.arguments
        if not re.fullmatch(r"[1-9][0-9]*", pid):
            parser.error("invalid contender PID")
        validate_waiter(args.directory, int(pid), unit_invocation)
    else:
        parser.error("invalid action arguments")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, TypeError) as exc:
        print("fdstore probe: %s" % exc, file=sys.stderr)
        raise SystemExit(1)
