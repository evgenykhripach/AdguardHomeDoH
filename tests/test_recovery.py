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


def valid_runtime(runtime):
    return (isinstance(runtime, dict) and set(runtime) == {"adguard_active"}
            and type(runtime["adguard_active"]) is bool)


def committed_confirmed(data):
    return data["phase"] == "COMMITTED"


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

    def begin(self, runtime_before=None, **override):
        options = {"locks_held": yes, "writer_confirmed": yes, "markers_clear": yes,
                   "job_barrier_held": yes, "validate_runtime": valid_runtime}
        options.update(override)
        if runtime_before is None:
            runtime_before = {"adguard_active": True}
        self.journal.begin("service-change", self.writer, runtime_before, **options)

    def seal(self, **override):
        options = {"locks_held": yes, "writer_confirmed": yes, "stopped": yes, "markers_clear": yes,
                   "job_barrier_held": yes,
                   "validate_snapshot": strict_validator, "validate_runtime": valid_runtime}
        options.update(override)
        self.journal.seal(self.snapshot, **options)

    def recover(self, **override):
        options = {"locks_held": yes, "writer_gone": yes, "stopped": yes, "job_barrier_held": yes,
                   "markers_clear": yes, "validate_snapshot": strict_validator,
                   "validate_runtime": valid_runtime, "restore": lambda path, data: None,
                   "restore_runtime": yes, "runtime_restored": yes,
                   "committed_confirmed": committed_confirmed}
        options.update(override)
        return self.journal.recover(**options)

    def retire(self, **override):
        options = {"locks_held": yes, "writer_gone": yes, "job_barrier_held": yes,
                   "markers_clear": yes, "validate_runtime": valid_runtime,
                   "runtime_restored": yes, "committed_confirmed": committed_confirmed}
        options.update(override)
        return self.journal.retire(**options)

    def test_begin_requires_locks_writer_and_clear_legacy_markers(self):
        for key in ("locks_held", "writer_confirmed", "markers_clear", "job_barrier_held"):
            with self.subTest(key=key), self.assertRaises(recovery.RecoveryError):
                self.begin(**{key: lambda *args: False})
            self.assertFalse((self.state / "intent.json").exists())
        self.begin()
        self.assertEqual(self.phase(), "PREPARED")
        with self.assertRaises(recovery.RecoveryError):
            self.begin()

    def test_runtime_callbacks_cannot_be_omitted(self):
        with self.assertRaises(TypeError):
            self.journal.begin("service-change", self.writer, {"adguard_active": True},
                               locks_held=yes, writer_confirmed=yes, job_barrier_held=yes, markers_clear=yes)
        self.assertFalse((self.state / "intent.json").exists())
        self.begin()
        options = {"locks_held": yes, "writer_gone": yes, "stopped": yes, "job_barrier_held": yes,
                   "markers_clear": yes, "validate_snapshot": strict_validator, "validate_runtime": valid_runtime,
                   "restore": lambda *args: None, "restore_runtime": yes, "runtime_restored": yes,
                   "committed_confirmed": committed_confirmed}
        for missing in ("validate_runtime", "restore_runtime", "runtime_restored", "committed_confirmed"):
            with self.subTest(missing=missing), self.assertRaises(TypeError):
                self.journal.recover(**{key: value for key, value in options.items() if key != missing})
        self.assertEqual(self.phase(), "PREPARED")
        self.recover()
        options.pop("stopped")
        options.pop("validate_snapshot")
        options.pop("restore")
        options.pop("restore_runtime")
        for missing in ("validate_runtime", "runtime_restored", "committed_confirmed"):
            with self.subTest(missing=missing), self.assertRaises(TypeError):
                self.journal.retire(**{key: value for key, value in options.items() if key != missing})
        self.assertEqual(self.phase(), "RESTORED")

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
        self.assertEqual(self.phase(), "SNAPSHOT_READY")

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
        self.assertEqual(self.phase(), "SNAPSHOT_READY")

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
        self.retire()
        self.assertFalse((self.state / "intent.json").exists())

    def test_prepared_recovery_restores_and_confirms_runtime_without_snapshot(self):
        self.begin()
        runtime = {"adguard_active": False}
        calls = []

        def restore_runtime(recorded):
            calls.append(("restore", dict(recorded)))
            runtime.update(recorded)
            return True

        def confirm_runtime(recorded):
            calls.append(("confirm", dict(recorded)))
            return runtime == recorded

        self.assertEqual(self.recover(
            stopped=lambda: not runtime["adguard_active"],
            restore=lambda *args: self.fail("no snapshot"),
            restore_runtime=restore_runtime, runtime_restored=confirm_runtime), "RESTORED")
        self.assertEqual(runtime, {"adguard_active": True})
        self.assertEqual(calls, [("restore", {"adguard_active": True}),
                                 ("confirm", {"adguard_active": True})])

    def test_prepared_with_already_active_runtime_still_runs_callback_and_guards(self):
        self.begin()
        calls = []

        def restore_runtime(expected):
            calls.append(dict(expected))
            return True

        self.assertEqual(self.recover(stopped=lambda: False, restore_runtime=restore_runtime,
                                      restore=lambda *args: self.fail("no snapshot")), "RESTORED")
        self.assertEqual(calls, [{"adguard_active": True}])

    def test_crash_after_runtime_restore_retries_exact_callback_without_restoring_files_again(self):
        self.begin()
        self.seal()
        runtime = {"adguard_active": False}
        calls = []

        def restore(path, data):
            self.assertEqual(path, self.snapshot)
            self.assertEqual(data["snapshot"]["path"], str(self.snapshot))
            self.assertFalse(runtime["adguard_active"])
            calls.append("files")

        def restore_runtime(recorded):
            calls.append("runtime")
            runtime.update(recorded)
            return True

        def runtime_restored(recorded):
            calls.append("confirm")
            return runtime == recorded

        original_write = self.journal._write

        def crash_before_restored(data):
            if data["phase"] == "RESTORED":
                raise OSError("simulated crash before RESTORED")
            return original_write(data)

        options = dict(stopped=lambda: not runtime["adguard_active"], restore=restore,
                       restore_runtime=restore_runtime, runtime_restored=runtime_restored)
        with patch.object(self.journal, "_write", side_effect=crash_before_restored):
            with self.assertRaisesRegex(OSError, "simulated crash"):
                self.recover(**options)
        self.assertEqual(self.phase(), "RUNTIME_RESTORING")
        self.assertTrue(runtime["adguard_active"])

        self.journal = recovery.Journal(self.state, self.backups)
        self.assertEqual(self.recover(**options), "RESTORED")
        self.assertEqual(calls, ["files", "runtime", "confirm", "runtime", "confirm"])
        self.assertEqual(self.recover(**options), "RESTORED")
        self.assertEqual(calls, ["files", "runtime", "confirm", "runtime", "confirm", "confirm"])

    def test_runtime_failure_or_failed_confirmation_retains_retryable_journal(self):
        self.begin()
        calls = []

        def restore_runtime(recorded):
            calls.append(dict(recorded))
            return True

        with self.assertRaises(recovery.RecoveryError):
            self.recover(restore_runtime=lambda expected: False)
        self.assertEqual(self.phase(), "RUNTIME_RESTORING")
        with self.assertRaises(recovery.RecoveryError):
            self.recover(restore_runtime=lambda expected: None)
        with self.assertRaises(recovery.RecoveryError):
            self.recover(restore_runtime=restore_runtime, runtime_restored=lambda expected: False)
        self.assertEqual(self.phase(), "RUNTIME_RESTORING")
        self.assertEqual(self.recover(restore_runtime=restore_runtime), "RESTORED")
        self.assertEqual(calls, [{"adguard_active": True}, {"adguard_active": True}])
        with self.assertRaises(recovery.RecoveryError):
            self.recover(runtime_restored=lambda expected: False)
        self.assertEqual(self.phase(), "RESTORED")

    def test_crash_during_runtime_restore_is_retried_for_prepared_without_snapshot(self):
        self.begin()
        runtime = {"adguard_active": False}
        calls = []

        def restore_runtime(expected):
            calls.append(dict(expected))
            runtime.update(expected)
            if len(calls) == 1:
                raise OSError("runtime callback interrupted")
            return True

        options = dict(stopped=lambda: not runtime["adguard_active"],
                       restore=lambda *args: self.fail("no snapshot"),
                       restore_runtime=restore_runtime,
                       runtime_restored=lambda expected: runtime == expected)
        with self.assertRaisesRegex(OSError, "runtime callback interrupted"):
            self.recover(**options)
        self.assertEqual(self.phase(), "RUNTIME_RESTORING")
        self.assertTrue(runtime["adguard_active"])
        self.journal = recovery.Journal(self.state, self.backups)
        self.assertEqual(self.recover(**options), "RESTORED")
        self.assertEqual(calls, [{"adguard_active": True}, {"adguard_active": True}])

    def test_existing_restoring_snapshot_with_live_service_is_not_assumed_restored(self):
        self.begin()
        self.seal()
        with self.assertRaises(OSError):
            self.recover(restore=lambda *args: (_ for _ in ()).throw(OSError("interrupted")))
        self.assertEqual(self.phase(), "RESTORING")
        with self.assertRaises(recovery.RecoveryError):
            self.recover(stopped=lambda: False,
                         restore_runtime=lambda *args: self.fail("files may not have been restored"))
        self.assertEqual(self.phase(), "RESTORING")

    def test_runtime_validator_is_required_and_invalid_runtime_is_fail_closed(self):
        with self.assertRaises(recovery.RecoveryError):
            self.begin(runtime_before={"adguard_active": "yes"})
        self.assertFalse((self.state / "intent.json").exists())
        self.begin()
        intent = self.state / "intent.json"
        document = json.loads(intent.read_text())
        document["runtime_before"] = {"unexpected": True}
        intent.write_text(json.dumps(document))
        with self.assertRaises(recovery.RecoveryError):
            self.seal()
        with self.assertRaises(recovery.RecoveryError):
            self.recover()
        self.assertEqual(self.phase(), "PREPARED")

    def test_runtime_state_requires_exact_json_types_even_with_permissive_validator(self):
        for invalid in ({"items": (True,)}, {"items": {1: True}}, {"items": float("nan")}):
            with self.subTest(invalid=invalid), self.assertRaises(recovery.RecoveryError):
                self.begin(runtime_before=invalid, validate_runtime=yes)
            self.assertFalse((self.state / "intent.json").exists())
        self.begin()
        intent = self.state / "intent.json"
        document = json.loads(intent.read_text())
        document["runtime_before"] = {"invalid": float("inf")}
        intent.write_text(json.dumps(document))
        with self.assertRaises(recovery.RecoveryError):
            self.recover(validate_runtime=yes)
        self.assertEqual(self.phase(), "PREPARED")

    def test_invalid_runtime_cannot_retire_restored_or_committed_intent(self):
        for terminal in ("RESTORED", "COMMITTED"):
            with self.subTest(terminal=terminal):
                self.begin()
                if terminal == "RESTORED":
                    self.recover()
                else:
                    self.seal()
                    self.journal.commit(locks_held=yes, writer_confirmed=yes, job_barrier_held=yes,
                                        markers_clear=yes, validated=yes, validate_snapshot=strict_validator,
                                        validate_runtime=valid_runtime)
                intent = self.state / "intent.json"
                document = json.loads(intent.read_text())
                document["runtime_before"] = {"adguard_active": "invalid"}
                intent.write_text(json.dumps(document))
                with self.assertRaises(recovery.RecoveryError):
                    self.retire()
                self.assertEqual(self.phase(), terminal)
                intent.unlink()

    def test_callbacks_cannot_change_the_recorded_writer_or_runtime(self):
        self.begin()
        self.seal()
        received = []

        def restore(path, data):
            data["writer"]["unit"] = "tampered"
            data["runtime_before"]["adguard_active"] = False

        def restore_runtime(expected):
            received.append(dict(expected))
            expected["adguard_active"] = False
            return True

        def confirm(expected):
            received.append(dict(expected))
            return expected == {"adguard_active": True}

        self.assertEqual(self.recover(restore=restore, restore_runtime=restore_runtime,
                                      runtime_restored=confirm,
                                      writer_gone=lambda writer: writer == self.writer), "RESTORED")
        self.assertEqual(received, [{"adguard_active": True}, {"adguard_active": True}])
        document = json.loads((self.state / "intent.json").read_text())
        self.assertEqual(document["writer"], self.writer)
        self.assertEqual(document["runtime_before"], {"adguard_active": True})

    def test_recovery_rechecks_guards_after_runtime_and_confirmation_callbacks(self):
        for callback in ("restore_runtime", "runtime_restored"):
            for guard in ("locks_held", "job_barrier_held", "writer_gone", "markers_clear"):
                with self.subTest(callback=callback, guard=guard):
                    self.begin()
                    current = {"safe": True}

                    def lose_guard(*args):
                        current["safe"] = False
                        return True

                    options = {guard: lambda *args: current["safe"], callback: lose_guard}
                    with self.assertRaises(recovery.RecoveryError):
                        self.recover(**options)
                    self.assertEqual(self.phase(), "RUNTIME_RESTORING")
                    (self.state / "intent.json").unlink()

    def test_recovery_rechecks_guards_after_file_restore_before_starting_runtime(self):
        self.begin()
        self.seal()
        current = {"safe": True}

        def restore(*args):
            current["safe"] = False

        with self.assertRaises(recovery.RecoveryError):
            self.recover(restore=restore, markers_clear=lambda: current["safe"],
                         restore_runtime=lambda *args: self.fail("unsafe to start runtime"))
        self.assertEqual(self.phase(), "RESTORING")

    def test_file_restore_requires_service_to_remain_stopped(self):
        self.begin()
        self.seal()
        runtime = {"stopped": True}
        with self.assertRaises(recovery.RecoveryError):
            self.recover(stopped=lambda: runtime["stopped"],
                         restore=lambda *args: runtime.update(stopped=False),
                         restore_runtime=lambda *args: self.fail("service started during file restore"))
        self.assertEqual(self.phase(), "RESTORING")

    def test_retire_requires_fresh_runtime_and_rechecks_guards(self):
        self.begin()
        self.recover()
        with self.assertRaises(recovery.RecoveryError):
            self.retire(runtime_restored=lambda expected: False)
        self.assertEqual(self.phase(), "RESTORED")
        current = {"safe": True}

        def confirm_runtime(expected):
            self.assertEqual(expected, {"adguard_active": True})
            current["safe"] = False
            return True

        with self.assertRaises(recovery.RecoveryError):
            self.retire(runtime_restored=confirm_runtime, job_barrier_held=lambda: current["safe"])
        self.assertEqual(self.phase(), "RESTORED")
        self.retire()
        with self.assertRaises(recovery.RecoveryError):
            self.retire()
        self.assertFalse((self.state / "intent.json").exists())

    def test_retire_rechecks_all_guards_after_terminal_callback(self):
        for guard in ("locks_held", "job_barrier_held", "writer_gone", "markers_clear"):
            with self.subTest(guard=guard):
                self.begin()
                self.recover()
                current = {"safe": True}

                def confirm(expected):
                    current["safe"] = False
                    return True

                with self.assertRaises(recovery.RecoveryError):
                    self.retire(runtime_restored=confirm, **{guard: lambda *args: current["safe"]})
                self.assertEqual(self.phase(), "RESTORED")
                (self.state / "intent.json").unlink()

    def test_snapshot_checked_again_at_recovery_and_commit(self):
        self.begin()
        self.seal()
        manifest = self.snapshot / "manifest.json"
        manifest.write_text(manifest.read_text() + " ")
        with self.assertRaises(recovery.RecoveryError):
            self.recover()
        with self.assertRaises(recovery.RecoveryError):
            self.journal.commit(locks_held=yes, writer_confirmed=yes, job_barrier_held=yes, markers_clear=yes, validated=yes,
                                validate_snapshot=strict_validator, validate_runtime=valid_runtime)
        self.assertEqual(self.phase(), "SNAPSHOT_READY")

    def test_commit_requires_external_validation_and_cannot_recover_afterwards(self):
        self.begin()
        self.seal()
        with self.assertRaises(recovery.RecoveryError):
            self.journal.commit(locks_held=yes, writer_confirmed=yes, job_barrier_held=yes, markers_clear=yes, validated=lambda: False,
                                validate_snapshot=strict_validator, validate_runtime=valid_runtime)
        self.journal.commit(locks_held=yes, writer_confirmed=yes, job_barrier_held=yes, markers_clear=yes, validated=yes,
                            validate_snapshot=strict_validator, validate_runtime=valid_runtime)
        calls = []

        def confirm_commit(data):
            calls.append(data["phase"])
            return data["phase"] == "COMMITTED"

        def no_rollback(*args):
            self.fail("committed state must not be rolled back")

        with self.assertRaises(recovery.RecoveryError):
            self.recover(restore=no_rollback, restore_runtime=no_rollback,
                         committed_confirmed=lambda data: False)
        self.assertEqual(self.recover(restore=no_rollback, restore_runtime=no_rollback,
                                      committed_confirmed=confirm_commit), "COMMITTED")
        with self.assertRaises(recovery.RecoveryError):
            self.retire(committed_confirmed=lambda data: False, runtime_restored=no_rollback)
        self.assertEqual(self.phase(), "COMMITTED")
        current = {"safe": True}

        def lose_guard(data):
            current["safe"] = False
            return True

        with self.assertRaises(recovery.RecoveryError):
            self.retire(committed_confirmed=lose_guard, runtime_restored=no_rollback,
                        writer_gone=lambda writer: current["safe"])
        self.assertEqual(self.phase(), "COMMITTED")
        self.retire(committed_confirmed=confirm_commit, runtime_restored=no_rollback)
        self.assertEqual(calls, ["COMMITTED", "COMMITTED"])
        with self.assertRaises(recovery.RecoveryError):
            self.retire()

    def test_commit_rechecks_guards_after_final_validation(self):
        self.begin()
        self.seal()
        state = {"safe": True, "checks": 0}

        def validated():
            state["checks"] += 1
            if state["checks"] == 2:
                state["safe"] = False
            return True

        with self.assertRaises(recovery.RecoveryError):
            self.journal.commit(locks_held=lambda: state["safe"], writer_confirmed=yes,
                                job_barrier_held=yes, markers_clear=yes, validated=validated,
                                validate_snapshot=strict_validator, validate_runtime=valid_runtime)
        self.assertEqual(self.phase(), "SNAPSHOT_READY")

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
                              stopped=yes, job_barrier_held=yes, markers_clear=yes,
                              validate_snapshot=strict_validator, validate_runtime=valid_runtime)

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
