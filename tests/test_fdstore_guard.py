import errno
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from deploy.lib import fdstore_guard


ROLES = ("operation", "health", "front")


class FDStoreGuardTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.paths = {role: self.root / (role + ".lock") for role in ROLES}
        self.names = {role: role + "-fixture" for role in ROLES}
        self.actual = {}
        for role in ROLES:
            fd = os.open(self.paths[role], os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            self.addCleanup(os.close, fd)
            os.fchmod(fd, 0o600 if role == "front" else 0o644)
            self.actual[role] = fd
        self.fd_map = {number: self.actual[role] for number, role in enumerate(ROLES, 3)}
        self.environment = {
            "LISTEN_PID": str(os.getpid()),
            "LISTEN_FDS": "3",
            "LISTEN_FDNAMES": ":".join(self.names[role] for role in ROLES),
        }
        self.proc = {}
        global_lines = []
        for number, role in enumerate(ROLES, 3):
            info = os.fstat(self.actual[role])
            device = "%x:%x:%d" % (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino)
            # The acquiring process can have a different PID after restart.
            self.proc["/proc/self/fdinfo/%d" % number] = (
                "pos:\t0\nflags:\t0100002\nlock:\t1: FLOCK ADVISORY WRITE 4321 %s 0 EOF\n" % device
            ).encode("ascii")
            global_lines.append("%d: FLOCK ADVISORY WRITE 4321 %s 0 EOF\n" % (number + 20, device))
        self.proc["/proc/locks"] = "".join(global_lines).encode("ascii")

        def fstat_received(fd):
            if fd not in self.fd_map:
                raise OSError(errno.EBADF, "bad descriptor")
            return os.fstat(self.fd_map[fd])

        def read_proc(path, limit=65536):
            path = str(path)
            if path not in self.proc:
                raise AssertionError("unexpected proc path: " + path)
            value = self.proc[path]
            if isinstance(value, Exception):
                raise value
            return value

        self.environment_patch = mock.patch.dict(os.environ, self.environment, clear=True)
        self.environment_patch.start()
        self.addCleanup(self.environment_patch.stop)
        self.stat_patch = mock.patch.object(fdstore_guard, "_fstat", side_effect=fstat_received)
        self.stat_patch.start()
        self.addCleanup(self.stat_patch.stop)
        self.proc_patch = mock.patch.object(fdstore_guard, "_read_bounded", side_effect=read_proc)
        self.proc_reader = self.proc_patch.start()
        self.addCleanup(self.proc_patch.stop)
        self.flock_patch = mock.patch.object(fcntl, "flock", side_effect=AssertionError("flock called"))
        self.flock = self.flock_patch.start()
        self.addCleanup(self.flock_patch.stop)
        self.addCleanup(self.flock.assert_not_called)

    def receive(self):
        return fdstore_guard.receive_inherited_locks(self.paths, self.names)

    def test_complete_receipt_accepts_old_owner_and_different_proc_record_ids(self):
        self.assertEqual(self.receive(), {"operation": 3, "health": 4, "front": 5})
        self.assertNotEqual(os.getpid(), 4321)

    def test_names_are_mapped_in_any_delivery_order(self):
        os.environ["LISTEN_FDNAMES"] = ":".join(self.names[role] for role in reversed(ROLES))
        self.fd_map = {3: self.actual["front"], 4: self.actual["health"], 5: self.actual["operation"]}
        self.proc["/proc/self/fdinfo/3"], self.proc["/proc/self/fdinfo/5"] = (
            self.proc["/proc/self/fdinfo/5"], self.proc["/proc/self/fdinfo/3"]
        )
        self.assertEqual(self.receive(), {"operation": 5, "health": 4, "front": 3})

    def test_missing_extra_duplicate_or_wrong_systemd_names_and_counts_fail(self):
        cases = [
            ("LISTEN_PID", None), ("LISTEN_PID", str(os.getpid() + 1)),
            ("LISTEN_PID", "0" + str(os.getpid())),
            ("LISTEN_FDS", None), ("LISTEN_FDS", "0"), ("LISTEN_FDS", "2"),
            ("LISTEN_FDS", "4"), ("LISTEN_FDS", "03"),
            ("LISTEN_FDNAMES", None), ("LISTEN_FDNAMES", "operation-fixture:health-fixture"),
            ("LISTEN_FDNAMES", "operation-fixture:health-fixture:front-fixture:extra"),
            ("LISTEN_FDNAMES", "operation-fixture:operation-fixture:front-fixture"),
            ("LISTEN_FDNAMES", "operation-fixture:health-fixture:unexpected"),
        ]
        for key, value in cases:
            with self.subTest(key=key, value=value):
                with mock.patch.dict(os.environ, self.environment, clear=True):
                    if value is None:
                        os.environ.pop(key)
                    else:
                        os.environ[key] = value
                    with self.assertRaises(fdstore_guard.FDStoreGuardError):
                        self.receive()

    def test_invalid_caller_names_and_paths_fail(self):
        for invalid in ({"operation": "one", "health": "one", "front": "two"},
                        {"operation": "", "health": "two", "front": "three"},
                        {"operation": "one:two", "health": "two", "front": "three"},
                        {"operation": "one", "health": "two"}):
            with self.subTest(names=invalid), self.assertRaises(fdstore_guard.FDStoreGuardError):
                fdstore_guard.receive_inherited_locks(self.paths, invalid)
        for invalid in ("relative/operation.lock", str(self.root / ".." / "operation.lock"),
                        "", "/", b"/tmp/operation.lock"):
            with self.subTest(path=invalid), self.assertRaises(fdstore_guard.FDStoreGuardError):
                fdstore_guard.receive_inherited_locks(dict(self.paths, operation=invalid), self.names)
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            fdstore_guard.receive_inherited_locks({"operation": self.paths["operation"]}, self.names)

    def test_missing_descriptor_is_rejected(self):
        del self.fd_map[4]
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()

    def test_duplicate_descriptors_and_duplicate_open_file_descriptions_rejected(self):
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            fdstore_guard._verify_lock_set(self.paths, {"operation": 3, "health": 3, "front": 5})
        duplicate = os.dup(self.actual["operation"])
        self.addCleanup(os.close, duplicate)
        self.assertNotEqual(duplicate, self.actual["operation"])
        self.fd_map[4] = duplicate
        self.paths["health"] = self.paths["operation"]
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()

    def test_same_inode_from_separate_opens_is_rejected(self):
        other = os.open(self.paths["operation"], os.O_RDWR)
        self.addCleanup(os.close, other)
        self.fd_map[4] = other
        self.paths["health"] = self.paths["operation"]
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()

    def test_wrong_path_symlink_or_hardlink_is_rejected(self):
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            fdstore_guard.receive_inherited_locks(dict(self.paths, operation=self.paths["health"]), self.names)
        alias = self.root / "alias.lock"
        alias.symlink_to(self.paths["operation"])
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            fdstore_guard.receive_inherited_locks(dict(self.paths, operation=alias), self.names)
        alias.unlink()
        os.link(self.paths["operation"], alias)
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()

    def test_symlink_in_parent_or_untrusted_parent_is_rejected(self):
        real = self.root / "locks"
        real.mkdir(mode=0o700)
        original = self.paths["operation"]
        target = real / "operation.lock"
        original.rename(target)
        alias = self.root / "link"
        alias.symlink_to(real, target_is_directory=True)
        self.paths["operation"] = alias / target.name
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()
        self.paths["operation"] = target
        real.chmod(0o777)
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()

    def test_file_permissions_and_root_ownership_are_checked(self):
        for role, mode in (("operation", 0o664), ("health", 0o646),
                           ("front", 0o644), ("front", 0o400), ("front", 0o1600)):
            with self.subTest(role=role, mode=oct(mode)):
                original = os.fstat(self.actual[role]).st_mode & 0o7777
                os.fchmod(self.actual[role], mode)
                try:
                    with self.assertRaises(fdstore_guard.FDStoreGuardError):
                        self.receive()
                finally:
                    os.fchmod(self.actual[role], original)
        # Simulate root receiving a file belonging to the test user.
        if os.geteuid() != 0:
            with mock.patch.object(fdstore_guard, "_secure_directory", return_value=()), \
                    mock.patch.object(fdstore_guard.os, "geteuid", return_value=0):
                with self.assertRaises(fdstore_guard.FDStoreGuardError):
                    self.receive()

    def test_unrelated_open_file_description_does_not_inherit_another_flock(self):
        # /proc/locks still reports the lock, but this descriptor has no lock.
        other = os.open(self.paths["health"], os.O_RDWR)
        self.addCleanup(os.close, other)
        self.fd_map[4] = other
        self.proc["/proc/self/fdinfo/4"] = b"pos:\t0\nflags:\t0100002\n"
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()

    def test_fdinfo_requires_one_exact_flock_record(self):
        key = "/proc/self/fdinfo/4"
        good = self.proc[key]
        corrupt = [b"", b"random data\n", b"\xff", good.replace(b"FLOCK", b"POSIX"),
                   good.replace(b"ADVISORY", b"MANDATORY"), good.replace(b"WRITE", b"READ"),
                   good.replace(b" 0 EOF", b" 1 EOF"), good.replace(b" 0 EOF", b" 0 5"),
                   good.replace(b" 4321 ", b" -1 "), good.replace(b" 4321 ", b" xyz "),
                   good.replace(b"lock:\t1:", b"lock:\tbad:"), good + good,
                   good + b"lock: malformed\n"]
        lock_line = good.splitlines()[-1]
        device = lock_line.split()[6]
        major, minor, inode = device.split(b":")
        for changed in (b"ff:" + minor + b":" + inode, major + b":ff:" + inode,
                        major + b":" + minor + b":" + str(int(inode) + 1).encode()):
            corrupt.append(good.replace(device, changed))
        for value in corrupt:
            with self.subTest(value=value):
                self.proc[key] = value
                with self.assertRaises(fdstore_guard.FDStoreGuardError):
                    self.receive()

    def test_global_records_must_match_owner_device_inode_and_range(self):
        key = "/proc/locks"
        good = self.proc[key]
        line = good.splitlines(keepends=True)[1]
        mutations = [b"", b"junk\n", b"\xff", good.replace(line, b""),
                     good.replace(line, line.replace(b"FLOCK", b"POSIX")),
                     good.replace(line, line.replace(b"ADVISORY", b"MANDATORY")),
                     good.replace(line, line.replace(b"WRITE", b"READ")),
                     good.replace(line, line.replace(b" 4321 ", b" 4322 ")),
                     good.replace(line, line.replace(b" 0 EOF", b" 1 EOF")),
                     good.replace(line, line.replace(b" 0 EOF", b" 0 5")),
                     good.replace(line, line.replace(b" FLOCK", b" -> FLOCK")),
                     good + line]
        fields = line.split()
        major, minor, inode = fields[5].split(b":")
        for new_device in (b"ff:" + minor + b":" + inode,
                           major + b":ff:" + inode,
                           major + b":" + minor + b":" + str(int(inode) + 1).encode()):
            mutations.append(good.replace(line, line.replace(fields[5], new_device)))
        for value in mutations:
            with self.subTest(value=value):
                self.proc[key] = value
                with self.assertRaises(fdstore_guard.FDStoreGuardError):
                    self.receive()

    def test_unreadable_proc_fails_and_environment_cannot_redirect_it(self):
        os.environ["PROC_ROOT"] = str(self.root)
        os.environ["FDSTORE_PROC_ROOT"] = str(self.root)
        self.assertEqual(self.receive(), {"operation": 3, "health": 4, "front": 5})
        for key in ("/proc/self/fdinfo/3", "/proc/locks"):
            with self.subTest(key=key):
                original = self.proc[key]
                self.proc[key] = OSError(errno.EACCES, "unreadable")
                try:
                    with self.assertRaises(fdstore_guard.FDStoreGuardError):
                        self.receive()
                finally:
                    self.proc[key] = original

    def test_rechecks_file_identity_after_proc_reads(self):
        original_reader = self.proc_reader.side_effect
        path = self.paths["operation"]

        def replace_file(path_arg, limit=65536):
            result = original_reader(path_arg, limit)
            if str(path_arg) == "/proc/locks":
                path.rename(self.root / "old-operation.lock")
                path.write_text("replacement")
                path.chmod(0o644)
            return result

        self.proc_reader.side_effect = replace_file
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()

    def test_rechecks_parent_identity_after_proc_reads(self):
        original_reader = self.proc_reader.side_effect
        parent = self.root / "locks"
        parent.mkdir(mode=0o700)
        for role in ROLES:
            self.paths[role].rename(parent / self.paths[role].name)
            self.paths[role] = parent / self.paths[role].name

        def replace_parent(path_arg, limit=65536):
            result = original_reader(path_arg, limit)
            if str(path_arg) == "/proc/locks":
                parent.rename(self.root / "old-locks")
                parent.symlink_to(self.root / "old-locks", target_is_directory=True)
            return result

        self.proc_reader.side_effect = replace_parent
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()

    def test_rechecks_descriptor_identity_after_proc_reads(self):
        original_reader = self.proc_reader.side_effect

        def replace_descriptor(path_arg, limit=65536):
            result = original_reader(path_arg, limit)
            if str(path_arg) == "/proc/locks":
                self.fd_map[3] = self.actual["health"]
            return result

        self.proc_reader.side_effect = replace_descriptor
        with self.assertRaises(fdstore_guard.FDStoreGuardError):
            self.receive()


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux /proc flock records")
class RealLinuxFDStoreGuardTest(unittest.TestCase):
    def test_real_inherited_and_independent_open_file_descriptions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            paths = {role: root / (role + ".lock") for role in ROLES}
            fds = {}
            try:
                for role in ROLES:
                    fd = os.open(paths[role], os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                    fds[role] = fd
                    os.fchmod(fd, 0o600 if role == "front" else 0o644)
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                foreign = os.open(paths["health"], os.O_RDWR)
                try:
                    with mock.patch.object(fcntl, "flock", side_effect=AssertionError("flock called")) as forbidden:
                        fdstore_guard._verify_lock_set(paths, fds)
                        with self.assertRaises(fdstore_guard.FDStoreGuardError):
                            fdstore_guard._verify_lock_set(paths, dict(fds, health=foreign))
                        forbidden.assert_not_called()
                    read_fd, write_fd = os.pipe()
                    pid = os.fork()
                    if pid == 0:
                        os.close(read_fd)
                        try:
                            with mock.patch.object(fcntl, "flock", side_effect=AssertionError("flock called")):
                                fdstore_guard._verify_lock_set(paths, fds)
                            os.write(write_fd, b"ok")
                        except BaseException as exc:
                            os.write(write_fd, (type(exc).__name__ + ": " + str(exc)).encode())
                        finally:
                            os.close(write_fd)
                            os._exit(0)
                    os.close(write_fd)
                    try:
                        message = os.read(read_fd, 4096)
                        _, status = os.waitpid(pid, 0)
                        self.assertEqual(status, 0)
                        self.assertEqual(message, b"ok")
                    finally:
                        os.close(read_fd)
                finally:
                    os.close(foreign)
            finally:
                for fd in fds.values():
                    os.close(fd)


if __name__ == "__main__":
    unittest.main()
