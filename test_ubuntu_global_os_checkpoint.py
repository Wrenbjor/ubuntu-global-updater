"""Offline regression test for the legacy PHP-only checkpoint."""

import unittest
import fcntl
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import preflight_recovery
import prelaunch_installer
import ubuntu_global_handoff
import ubuntu_global_os


class LegacyCheckpointTests(unittest.TestCase):
    def test_completed_php_only_checkpoint_allows_jammy_to_noble_plan(self):
        checkpoint = {'php_phase': 'complete', 'error': None}
        snapshot = {
            'release': '22.04', 'ubuntu': True, 'machine_id': 'fixture-machine',
            'boot_id': 'fixture-boot', 'active_package_work': False,
            'dpkg_clean': True, 'holds': [], 'reboot_required': False,
            'old_progress': checkpoint,
        }
        decision = ubuntu_global_os.plan(snapshot)
        self.assertEqual((decision['action'], decision['to_release']), ('upgrade', '24.04'))

        for change in ({'phase': 'release-running'}, {'php_phase': 'installing'},
                       {'error': 'failed'}, {'failed_part': 2}):
            with self.subTest(change=change):
                snapshot['old_progress'] = dict(checkpoint, **change)
                self.assertEqual(
                    ubuntu_global_os.plan(snapshot),
                    {'action': 'hold', 'reason': 'prior_failed_or_partial_workflow_preserved'},
                )


class CheckpointRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.base = self.root / 'global'
        self.base.mkdir(mode=0o700)
        self.unit = self.root / 'updater.service'
        self.unit.write_bytes(preflight_recovery.unit_bytes(self.base))
        self.wrapper = self.root / 'wrapper'
        self.wrapper.write_bytes(preflight_recovery.wrapper_bytes(self.base))
        self.wrapper.chmod(0o700)
        self.payload = self.base / 'payload'
        self.payload.mkdir(mode=0o700)
        old_worker = b'# Old worker fixture\n'
        (self.payload / 'ubuntu_global.py').write_bytes(old_worker)
        self.manifest = {'ubuntu_global.py': preflight_recovery.sha(old_worker)}
        manifest_patch = patch.object(
            preflight_recovery, 'CHECKPOINT_HOLD_MANIFEST_SHA',
            preflight_recovery.manifest_digest(self.manifest))
        manifest_patch.start()
        self.addCleanup(manifest_patch.stop)
        (self.root / 'etc').mkdir()
        (self.root / 'etc/machine-id').write_text('a' * 32)
        binding = {'machine_id': 'a' * 32, 'firmware_uuid': None}
        self.state = dict(schema=2, status='failed-needs-review', identity=binding,
                          host_binding=binding, completed=[], operation_running=False,
                          error=preflight_recovery.CHECKPOINT_HOLD)
        self.write_state()
        self.old_checkpoint = self.root / 'var/lib/ubuntu-php-upgrade/progress.json'
        self.old_checkpoint.parent.mkdir(parents=True)
        self.old_checkpoint.write_text('{"error":null,"php_phase":"complete"}')
        (self.base / 'unattended-state.json').touch(mode=0o600)
        (self.base / 'worker.lock').touch(mode=0o600)
        self.fd = os.open(self.base / 'installer.lock', os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, self.fd)
        fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.manager = dict(LoadState='loaded', ActiveState='failed', MainPID='0',
                            UnitFileState='disabled', FragmentPath=str(self.unit))
        process_patch = patch.object(prelaunch_installer, 'no_running_payload')
        process_patch.start()
        self.addCleanup(process_patch.stop)

    def write_state(self):
        state_file = self.base / 'state.json'
        state_file.write_text(json.dumps(self.state))
        state_file.chmod(0o600)

    def prepare(self):
        return preflight_recovery.prepare_recovery(
            self.base, self.wrapper, self.unit, lambda: self.manager, self.fd,
            os.geteuid(), self.root, self.manifest)

    def test_archives_global_hold_and_keeps_legacy_receipt(self):
        plan = self.prepare()
        original = self.old_checkpoint.read_bytes()
        actions = []

        def control(action):
            actions.append(action)
            if action == 'reset-failed':
                self.manager.update(LoadState='not-found', ActiveState='inactive')

        result = preflight_recovery.apply_recovery(
            plan, lambda: self.manager, control, self.fd, os.geteuid(), self.root, self.manifest)
        archive = self.base / result['evidence']
        self.assertEqual(json.loads((archive / 'state.json').read_bytes()), self.state)
        self.assertTrue((archive / 'unit-before').is_file())
        self.assertEqual(self.old_checkpoint.read_bytes(), original)
        self.assertEqual(actions, ['daemon-reload', 'reset-failed'])

    def test_refuses_prior_package_activity_and_incomplete_legacy_receipt(self):
        for key, value in [('completed', ['prepare-Ubuntu-22.04']),
                           ('operation_running', True), ('error', 'unrelated_failure')]:
            with self.subTest(key=key):
                saved = self.state[key]
                self.state[key] = value
                self.write_state()
                with self.assertRaisesRegex(preflight_recovery.RecoveryError, 'checkpoint_not_exact'):
                    self.prepare()
                self.state[key] = saved
        self.write_state()
        self.old_checkpoint.write_text('{"php_phase":"installing"}')
        with self.assertRaisesRegex(preflight_recovery.RecoveryError, 'legacy_checkpoint_not_completed'):
            self.prepare()
        self.assertTrue((self.base / 'state.json').is_file())
        self.assertTrue(self.unit.is_file())

    def test_refuses_drift_between_prepare_and_archive(self):
        plan = self.prepare()
        self.old_checkpoint.write_text('{"error":null,"php_phase":"complete","updated":"changed"}')
        with self.assertRaisesRegex(preflight_recovery.RecoveryError, 'preflight_recovery_plan_drift'):
            preflight_recovery.apply_recovery(
                plan, lambda: self.manager, lambda _: self.fail('unit changed'),
                self.fd, os.geteuid(), self.root, self.manifest)
        self.assertTrue((self.base / 'state.json').is_file())

    def test_installer_opt_in_checks_timers_and_installs_after_archival(self):
        fcntl.flock(self.fd, fcntl.LOCK_UN)
        timers = {name: {'enabled': 'enabled', 'active': True}
                  for name in ubuntu_global_handoff.TIMERS}
        new_payload = {'ubuntu_global.py': b'# New worker fixture\n'}
        options = dict(base=self.base, wrapper=self.wrapper, unit_paths=[self.unit],
                       system_reader=lambda: self.manager, start=False,
                       owner_uid=os.geteuid(), recover_checkpoint_hold=True)

        def control(argv, **_):
            if argv[1] == 'reset-failed':
                self.manager.update(LoadState='not-found', ActiveState='inactive')
            return type('Result', (), {'returncode': 0})()

        with patch.object(prelaunch_installer.layout, 'existing_shared_lock_paths', return_value=[]), \
             patch.object(prelaunch_installer, 'WRAPPER', preflight_recovery.wrapper_bytes(self.base)), \
             patch.object(prelaunch_installer.subprocess, 'run', side_effect=control), \
             patch.object(preflight_recovery.host_identity, 'verify'), \
             patch.object(preflight_recovery, 'php_only_receipt', return_value='fixture-receipt'), \
             patch.object(ubuntu_global_handoff, 'load_state', return_value=timers), \
             patch.object(ubuntu_global_handoff, 'System') as system:
            system.return_value.timer.return_value = {'enabled': 'enabled', 'active': False}
            with self.assertRaisesRegex(prelaunch_installer.InstallError, 'timer_restoration'):
                prelaunch_installer.install_bundle(new_payload, [self.manifest], **options)
            self.assertTrue((self.base / 'state.json').is_file())
            system.return_value.timer.side_effect = timers.__getitem__
            result = prelaunch_installer.install_bundle(new_payload, [self.manifest], **options)
        self.assertEqual((self.payload / 'ubuntu_global.py').read_bytes(), new_payload['ubuntu_global.py'])
        archive = self.base / result['preflight_recovery']['evidence']
        self.assertTrue((archive / 'state.json').is_file())
