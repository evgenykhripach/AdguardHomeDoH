"""Unit tests use fake orchestration; they do not prove systemd behavior."""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


recovery = load("recovery_test_module", ROOT / "deploy/lib/recovery.py")
manager = load("recovery_test_manager", ROOT / "deploy/manage.py")


def yes(*args):
    return True


def strict_validator(path):
    entries = manager._validated_backup_manifest(path)
    manifest = json.loads((path / "manifest.json").read_text())
    if manifest["version"] != manager.BACKUP_VERSION:
        raise RuntimeError("not a current snapshot")
    if {entry[0] for entry in entries} != set(manager._managed_paths(manifest["domain"])):
        raise RuntimeError("snapshot missing current paths")
    return entries


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name).resolve()
        self.state = base / "state"
        self.state.mkdir()
        self.backups = base / "backups"
        self.backups.mkdir()
        self.root = base / "root"
        self.root.mkdir()
        source = self.root / "opt/AdGuardHome/AdGuardHome.yaml"
        source.parent.mkdir(parents=True)
        source.write_text("saved state\n")
        self.snapshot = manager.create_backup(self.root, self.backups / "snapshot", operation="recovery")
        self.journal = recovery.Journal(self.state, self.backups)
        unit = "adguardhome-doh-writer-" + "a" * 32 + ".service"
        self.writer = {"boot_id": "12345678-1234-1234-1234-123456789abc", "unit": unit,
                       "cgroup": "/system.slice/" + unit, "invocation_id": "b" * 32,
                       "main_pid": 1234, "proc_starttime": 5678}

    def phase(self):
        return json.loads((self.state / "intent.json").read_text())["phase"]

    def begin(self, **override):
        options = {"locks_held": yes, "writer_confirmed": yes, "markers_clear": yes,
                   "job_barrier_held": yes}
        options.update(override)
        self.journal.begin("service-change", self.writer, {"adguard_active": True}, **options)

    def seal(self, **override):
        options = {"locks_held": yes, "writer_confirmed": yes, "stopped": yes, "markers_clear": yes,
                   "job_barrier_held": yes,
                   "validate_snapshot": strict_validator}
        options.update(override)
        self.journal.seal(self.snapshot, **options)

    def recover(self, **override):
        options = {"locks_held": yes, "writer_gone": yes, "stopped": yes, "job_barrier_held": yes,
                   "markers_clear": yes, "validate_snapshot": strict_validator,
                   "restore": lambda path, data: None}
        options.update(override)
        return self.journal.recover(**options)

    def test_begin_requires_locks_writer_and_clear_legacy_markers(self):
        for key in ("locks_held", "writer_confirmed", "markers_clear", "job_barrier_held"):
            with self.subTest(key=key), self.assertRaises(recovery.RecoveryError):
                self.begin(**{key: lambda *args: False})
            self.assertFalse((self.state / "intent.json").exists())
        self.begin()
        self.assertEqual(self.phase(), "PREPARED")
        with self.assertRaises(recovery.RecoveryError):
            self.begin()

    def test_seal_requires_stopped_and_full_verified_manager_snapshot(self):
        self.begin()
        with self.assertRaises(recovery.RecoveryError):
            self.seal(stopped=lambda: False)
        self.assertEqual(self.phase(), "PREPARED")
        self.seal()
        self.assertEqual(self.phase(), "SNAPSHOT_READY")
        with self.assertRaises(recovery.RecoveryError):
            self.seal()

    def test_tampered_missing_and_legacy_manifest_fail_before_seal(self):
        self.begin()
        manifest_path = self.snapshot / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        entry = next(item for item in manifest["files"] if item["present"])
        file_path = self.snapshot / entry["backup"]
        original = file_path.read_bytes()
        file_path.write_bytes(b"tampered")
        with self.assertRaises(RuntimeError):
            self.seal()
        file_path.unlink()
        with self.assertRaises(RuntimeError):
            self.seal()
        file_path.write_bytes(original)
        manifest["version"] = 2
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaises(recovery.RecoveryError):
            self.seal()
        self.assertEqual(self.phase(), "PREPARED")

    def test_fsync_failure_prevents_publish_and_retains_prepared(self):
        self.begin()
        with patch.object(recovery.os, "fsync", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                self.seal()
        self.assertEqual(self.phase(), "PREPARED")

    def test_failure_syncing_journal_directory_after_replace_is_not_success(self):
        self.begin()
        original_sync = recovery._sync_directory

        def sync(path):
            if path == self.state:
                raise OSError("directory fsync failed")
            return original_sync(path)

        with patch.object(recovery, "_sync_directory", side_effect=sync):
            with self.assertRaises(OSError):
                self.seal()
        # rename may already be visible, but the caller must not proceed after
        # an exception; recovery handles either durable phase after reboot.
        self.assertEqual(self.phase(), "SNAPSHOT_READY")
        self.assertEqual(self.recover(), "RESTORED")

    def test_unknown_journal_and_unknown_marker_are_fail_closed(self):
        (self.state / "intent.json").write_text('{"version": 99}')
        with self.assertRaises(recovery.RecoveryError):
            self.recover()
        (self.state / "intent.json").unlink()
        self.begin()
        with self.assertRaises(recovery.RecoveryError):
            self.recover(markers_clear=lambda: False)
        self.assertEqual(self.phase(), "PREPARED")

    def test_writer_alive_blocks_recovery_without_touching_snapshot(self):
        self.begin()
        self.seal()
        with self.assertRaises(recovery.RecoveryError):
            self.recover(writer_gone=lambda writer: False,
                         restore=lambda *args: self.fail("restore must not run"))
        self.assertEqual(self.phase(), "SNAPSHOT_READY")

    def test_writer_becomes_live_during_recovery_blocks_restore(self):
        self.begin()
        self.seal()
        checks = iter([True, False])
        with self.assertRaises(recovery.RecoveryError):
            self.recover(writer_gone=lambda writer: next(checks),
                         restore=lambda *args: self.fail("restore must not run"))
        self.assertEqual(self.phase(), "RESTORING")

    def test_identity_requires_writer_incarnation_and_dedicated_unit(self):
        originals = dict(self.writer)
        invalid = {
            "invocation_id": "0" * 32,
            "main_pid": True,
            "proc_starttime": 0,
            "boot_id": "boot",
            "unit": "mtproxyl.service",
            "cgroup": "/system.slice/mtproxyl.service",
        }
        for field, value in invalid.items():
            with self.subTest(field=field):
                self.writer = {**originals, field: value}
                with self.assertRaises(recovery.RecoveryError):
                    self.begin()
        self.writer = {**originals, "unit": "mtproxyl.service", "cgroup": "/system.slice/mtproxyl.service"}
        with self.assertRaises(recovery.RecoveryError):
            self.begin()
        self.writer = originals
        self.begin()
        document = json.loads((self.state / "intent.json").read_text())
        self.assertEqual(document["version"], 2)
        self.assertEqual(document["writer"], originals)

    def test_old_writer_identity_schema_fails_closed(self):
        self.begin()
        intent = self.state / "intent.json"
        document = json.loads(intent.read_text())
        document["version"] = 1
        document["writer"] = {key: document["writer"][key] for key in ("boot_id", "unit", "cgroup")}
        intent.write_text(json.dumps(document))
        with self.assertRaises(recovery.RecoveryError):
            self.recover()

    def test_reused_cgroup_with_new_invocation_is_not_treated_as_gone(self):
        self.begin()
        self.seal()
        running = {**self.writer, "invocation_id": "c" * 32, "proc_starttime": 9999}

        def no_writers(recorded):
            self.assertEqual(recorded, self.writer)
            # Fake systemd check: any competing writer blocks recovery even if
            # the prior incarnation died and the cgroup path was reused.
            return running is None

        with self.assertRaises(recovery.RecoveryError):
            self.recover(writer_gone=no_writers,
                         restore=lambda *args: self.fail("live writer"))
        self.assertEqual(self.phase(), "SNAPSHOT_READY")

    def test_queued_writer_job_barrier_required_and_rechecked(self):
        self.begin()
        self.seal()
        calls = iter([True, False])
        with self.assertRaises(recovery.RecoveryError):
            self.recover(job_barrier_held=lambda: next(calls),
                         restore=lambda *args: self.fail("job barrier lost"))
        self.assertEqual(self.phase(), "RESTORING")

    def test_compatibility_manifest_missing_current_path_is_rejected(self):
        self.begin()
        path = self.snapshot / "manifest.json"
        manifest = json.loads(path.read_text())
        path_to_omit = manager.FRONT_SITE_FILES[0]
        manifest["files"] = [item for item in manifest["files"] if item["path"] != path_to_omit]
        path.write_text(json.dumps(manifest))
        with self.assertRaises(RuntimeError):
            self.seal()
        self.assertEqual(self.phase(), "PREPARED")

    def test_post_seal_tampered_backup_is_rejected(self):
        self.begin()
        self.seal()
        manifest = json.loads((self.snapshot / "manifest.json").read_text())
        entry = next(item for item in manifest["files"] if item["present"])
        (self.snapshot / entry["backup"]).write_text("tampered")
        with self.assertRaises(RuntimeError):
            self.recover(restore=lambda *args: self.fail("restore must not run"))
        self.assertEqual(self.phase(), "SNAPSHOT_READY")

    def test_restore_failure_is_retryable_and_repeat_recovery_is_idempotent(self):
        self.begin()
        self.seal()
        calls = []

        def restore(path, data):
            calls.append(path)
            if len(calls) == 1:
                raise OSError("interrupted restore")

        with self.assertRaises(OSError):
            self.recover(restore=restore)
        self.assertEqual(self.phase(), "RESTORING")
        self.assertEqual(self.recover(restore=restore), "RESTORED")
        self.assertEqual(self.recover(restore=restore), "RESTORED")
        self.assertEqual(len(calls), 2)
        self.journal.retire(locks_held=yes, writer_gone=yes, job_barrier_held=yes, markers_clear=yes)
        self.assertFalse((self.state / "intent.json").exists())

    def test_prepared_recovery_does_not_restore_files(self):
        self.begin()
        self.assertEqual(self.recover(restore=lambda *args: self.fail("no snapshot")), "RESTORED")

    def test_snapshot_checked_again_at_recovery_and_commit(self):
        self.begin()
        self.seal()
        manifest = self.snapshot / "manifest.json"
        manifest.write_text(manifest.read_text() + " ")
        with self.assertRaises(recovery.RecoveryError):
            self.recover()
        with self.assertRaises(recovery.RecoveryError):
            self.journal.commit(locks_held=yes, writer_confirmed=yes, job_barrier_held=yes, markers_clear=yes, validated=yes,
                                validate_snapshot=strict_validator)
        self.assertEqual(self.phase(), "SNAPSHOT_READY")

    def test_commit_requires_external_validation_and_cannot_recover_afterwards(self):
        self.begin()
        self.seal()
        with self.assertRaises(recovery.RecoveryError):
            self.journal.commit(locks_held=yes, writer_confirmed=yes, job_barrier_held=yes, markers_clear=yes, validated=lambda: False,
                                validate_snapshot=strict_validator)
        self.journal.commit(locks_held=yes, writer_confirmed=yes, job_barrier_held=yes, markers_clear=yes, validated=yes,
                            validate_snapshot=strict_validator)
        self.assertEqual(self.recover(restore=lambda *args: self.fail("committed")), "COMMITTED")

    def test_revalidates_full_snapshot_after_fsync_and_detects_data_replacement(self):
        self.begin()
        calls = []
        original_sync = recovery._sync_directory
        manifest = json.loads((self.snapshot / "manifest.json").read_text())
        entry = next(item for item in manifest["files"] if item["present"])
        target = self.snapshot / entry["backup"]

        def change(path):
            original_sync(path)
            if path == self.snapshot:
                target.write_text("changed after first validation")

        def validator(path):
            calls.append(path)
            return strict_validator(path)

        with patch.object(recovery, "_sync_directory", side_effect=change):
            with self.assertRaises(RuntimeError):
                self.seal(validate_snapshot=validator)
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.phase(), "PREPARED")

    def test_same_content_new_inode_is_detected(self):
        self.begin()
        original_sync = recovery._sync_directory
        manifest = json.loads((self.snapshot / "manifest.json").read_text())
        entry = next(item for item in manifest["files"] if item["present"])
        target = self.snapshot / entry["backup"]

        def change(path):
            original_sync(path)
            if path == self.snapshot:
                replacement = self.snapshot / "replacement"
                replacement.write_bytes(target.read_bytes())
                replacement.chmod(target.stat().st_mode & 0o7777)
                os.replace(replacement, target)

        with patch.object(recovery, "_sync_directory", side_effect=change):
            with self.assertRaises(recovery.RecoveryError):
                self.seal()
        self.assertEqual(self.phase(), "PREPARED")

    def test_rejects_insecure_roots_snapshot_and_ancestor(self):
        for path in (self.state, self.backups, self.snapshot):
            with self.subTest(path=path):
                old_mode = path.stat().st_mode & 0o7777
                path.chmod(0o777)
                try:
                    with self.assertRaises(recovery.RecoveryError):
                        if path == self.snapshot:
                            self.begin()
                            self.seal()
                        else:
                            recovery.Journal(self.state, self.backups)
                finally:
                    path.chmod(old_mode)
                    (self.state / "intent.json").unlink(missing_ok=True)
        ancestor = self.state.parent
        old_mode = ancestor.stat().st_mode & 0o7777
        ancestor.chmod(0o777)
        try:
            with self.assertRaises(recovery.RecoveryError):
                recovery.Journal(self.state, self.backups)
            ancestor.chmod(0o1777)
            recovery.Journal(self.state, self.backups)  # trusted sticky ancestor
        finally:
            ancestor.chmod(old_mode)

    def test_rejects_symlink_directory_components(self):
        link = self.state.parent / "link"
        link.symlink_to(self.state, target_is_directory=True)
        with self.assertRaises(recovery.RecoveryError):
            recovery.Journal(link, self.backups)
        snapshot_link = self.backups / "link"
        snapshot_link.symlink_to(self.snapshot, target_is_directory=True)
        self.begin()
        with self.assertRaises(recovery.RecoveryError):
            self.journal.seal(snapshot_link, locks_held=yes, writer_confirmed=yes,
                              stopped=yes, job_barrier_held=yes, markers_clear=yes, validate_snapshot=strict_validator)

    def test_rejects_unsafe_intent_and_manifest_links_and_modes(self):
        self.begin()
        intent = self.state / "intent.json"
        intent.chmod(0o666)
        with self.assertRaises(recovery.RecoveryError):
            self.seal()
        intent.chmod(0o600)
        alias = self.state / "intent-hardlink"
        os.link(intent, alias)
        with self.assertRaises(recovery.RecoveryError):
            self.seal()
        alias.unlink()
        data = intent.read_bytes()
        intent.unlink()
        external = self.state / "external"
        external.write_bytes(data)
        external.chmod(0o600)
        intent.symlink_to(external)
        with self.assertRaises(recovery.RecoveryError):
            self.seal()
        intent.unlink()
        intent.write_bytes(data)
        intent.chmod(0o600)
        manifest = self.snapshot / "manifest.json"
        manifest.chmod(0o666)
        with self.assertRaises(recovery.RecoveryError):
            self.seal()
        manifest.chmod(0o600)
        alias = self.snapshot / "manifest-hardlink"
        os.link(manifest, alias)
        with self.assertRaises(recovery.RecoveryError):
            self.seal()
        alias.unlink()
        data = manifest.read_bytes()
        manifest.unlink()
        external = self.snapshot / "manifest-original"
        external.write_bytes(data)
        external.chmod(0o600)
        manifest.symlink_to(external)
        with self.assertRaises(recovery.RecoveryError):
            self.seal()

    def test_rejects_hardlinked_or_other_writable_snapshot_data(self):
        self.begin()
        manifest = json.loads((self.snapshot / "manifest.json").read_text())
        entry = next(item for item in manifest["files"] if item["present"])
        target = self.snapshot / entry["backup"]
        old_mode = target.stat().st_mode & 0o7777
        target.chmod(old_mode | 0o020)
        with self.assertRaises(RuntimeError):
            self.seal()
        target.chmod(old_mode)
        alias = self.snapshot / "backup-hardlink"
        os.link(target, alias)
        with self.assertRaises(recovery.RecoveryError):
            self.seal()

    def test_detects_replaced_root_after_initialization(self):
        old = self.state.with_name("old-state")
        self.state.rename(old)
        self.state.mkdir()
        with self.assertRaises(recovery.RecoveryError):
            self.begin()

    def test_rejects_untrusted_owner(self):
        original = Path.lstat

        def foreign_owner(path, *args, **kwargs):
            info = original(path, *args, **kwargs)
            if path == self.state:
                fields = list(info)
                fields[4] = 987654
                return os.stat_result(fields)
            return info

        with patch.object(Path, "lstat", foreign_owner):
            with self.assertRaises(recovery.RecoveryError):
                recovery.Journal(self.state, self.backups)


if __name__ == "__main__":
    unittest.main()
