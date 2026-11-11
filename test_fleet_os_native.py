import contextlib
import copy
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import fleet_os_native as native
import fleet_os_stage as stage
from test_fleet_os_stage import Backend


class Policy(Backend):
    def __init__(self):
        super().__init__()
        self.events = []
        self.retained = True

    def prepare(self, decision):
        prepared = super().prepare(decision)
        prepared.update(full_native_transaction_preflight_verified=True,
                        php_restore_plan_verified=True, native_reboot_policy_verified=True)
        return prepared

    def retained_worker(self):
        return self.retained

    @contextlib.contextmanager
    def guard(self, prepared):
        self.events.append('guard-on')
        try:
            yield
        finally:
            self.events.append('guard-off')

    def restore_php(self, prepared):
        self.events.append('restore-php')
        self.value['php']['package_suite'] = prepared['target_suite']


class Commands:
    def __init__(self, policy):
        self.policy = policy
        self.offered = '24.04.3 LTS'
        self.fail = False
        self.argv = []

    def check(self, argv):
        self.argv.append(argv)
        return "New release '" + self.offered + "' available.\nRun 'do-release-upgrade' to upgrade."

    def run_upgrade(self, argv):
        self.argv.append(argv)
        self.policy.events.append('native-upgrade')
        if self.fail:
            raise stage.Hold('fixture failure')
        self.policy.value['release'] = '24.04'


class NativeTests(unittest.TestCase):
    def make(self):
        policy = Policy()
        commands = Commands(policy)
        backend = native.SupportedReleaseBackend(policy, commands, verifier=lambda _: None)
        decision = stage.plan(policy.snapshot())
        return policy, commands, backend, decision

    def test_supported_command_guard_and_restore_order(self):
        policy, commands, backend, decision = self.make()
        prepared = backend.prepare(decision)
        backend.upgrade(decision, prepared)
        self.assertEqual(policy.events, ['guard-on', 'native-upgrade', 'restore-php', 'guard-off'])
        self.assertEqual(commands.argv[-1], [native.UPGRADER, '--mode=server',
                                            '--frontend=DistUpgradeViewNonInteractive'])
        self.assertFalse(any('-d' in args or '--devel-release' in args for args in commands.argv))

    def test_wrong_or_unavailable_release(self):
        for offered in ['26.04.1 LTS', '25.10', 'nonsense']:
            policy, commands, backend, decision = self.make()
            commands.offered = offered
            with self.assertRaises(stage.Hold):
                backend.prepare(decision)
            self.assertEqual(policy.events, [])

    def test_requires_retained_worker(self):
        policy, commands, backend, decision = self.make()
        prepared = backend.prepare(decision)
        policy.retained = False
        with self.assertRaises(stage.Hold):
            backend.upgrade(decision, prepared)
        self.assertEqual(policy.events, [])

    def test_native_failure_does_not_restore_or_reboot(self):
        policy, commands, backend, decision = self.make()
        prepared = backend.prepare(decision)
        commands.fail = True
        with self.assertRaises(stage.Hold):
            backend.upgrade(decision, prepared)
        self.assertEqual(policy.events, ['guard-on', 'native-upgrade', 'guard-off'])

    def test_plan_and_baseline_drift_blocked(self):
        for change in ['plan', 'host', 'offering']:
            policy, commands, backend, decision = self.make()
            prepared = backend.prepare(decision)
            if change == 'plan':
                prepared['php_candidates']['php8.5-fpm']['version'] = 'changed'
            elif change == 'host':
                policy.value['boot_id'] = 'new-boot'
            else:
                commands.offered = '26.04.1 LTS'
            with self.subTest(change=change), self.assertRaises(stage.Hold):
                backend.upgrade(decision, prepared)
            self.assertEqual(policy.events, [])

    def test_host_transaction_and_php_restoration_proofs_required(self):
        for key in ['full_native_transaction_preflight_verified', 'php_restore_plan_verified', 'native_reboot_policy_verified']:
            policy, commands, backend, decision = self.make()
            old = policy.prepare
            def prepare(decision):
                value = old(decision)
                value[key] = False
                return value
            policy.prepare = prepare
            with self.subTest(key=key), self.assertRaises(stage.Hold):
                backend.prepare(decision)

    def test_official_version_output_formats(self):
        for value in ['24.04', '24.04 LTS', '24.04.1 LTS']:
            self.assertEqual(native.offered_release("New release '" + value + "' available."), '24.04')
        with self.assertRaises(stage.Hold):
            native.offered_release('No new release found.')


class CommandBoundaryTests(unittest.TestCase):
    def test_private_log_and_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'native.log'
            child = Mock()
            child.wait.return_value = 1
            with patch.object(native.subprocess, 'Popen', return_value=child) as launch:
                with self.assertRaisesRegex(stage.Hold, 'preserve_no_retry'):
                    native.Commands(log).run_upgrade(['fixture-upgrader'])
            self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
            self.assertEqual(launch.call_count, 1)
            child.wait.assert_called_once_with()
            child.kill.assert_not_called()
            child.terminate.assert_not_called()

    def test_wait_interrupt_does_not_terminate_child(self):
        with tempfile.TemporaryDirectory() as directory:
            child = Mock()
            child.wait.side_effect = [KeyboardInterrupt(), 0]
            with patch.object(native.subprocess, 'Popen', return_value=child):
                native.Commands(Path(directory) / 'native.log').run_upgrade(['fixture-upgrader'])
            self.assertEqual(child.wait.call_count, 2)
            child.kill.assert_not_called()
            child.terminate.assert_not_called()

    def test_unsafe_log_parents_and_existing_targets_block_launch(self):
        for case in ['public-parent', 'writable-ancestor', 'symlink-parent',
                     'symlink-target', 'existing-target', 'parent-traversal']:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent = root / 'logs'
                parent.mkdir(mode=0o700)
                log = parent / 'native.log'
                if case == 'public-parent':
                    parent.chmod(0o755)
                elif case == 'writable-ancestor':
                    root.chmod(0o777)
                elif case == 'symlink-parent':
                    link = root / 'linked'
                    link.symlink_to(parent, target_is_directory=True)
                    log = link / 'native.log'
                elif case == 'symlink-target':
                    log.symlink_to(root / 'untouched')
                elif case == 'existing-target':
                    log.write_text('preserve')
                elif case == 'parent-traversal':
                    log = parent / '..' / 'native.log'
                with patch.object(native.subprocess, 'Popen') as launch:
                    with self.assertRaises((stage.Hold, OSError)):
                        native.Commands(log).run_upgrade(['fixture-upgrader'])
                    launch.assert_not_called()
                if case == 'existing-target':
                    self.assertEqual(log.read_text(), 'preserve')
                if case == 'symlink-target':
                    self.assertFalse((root / 'untouched').exists())

    def test_log_parent_untrusted_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            actual = os.fstat
            def untrusted(fd):
                info = actual(fd)
                return SimpleNamespace(st_mode=info.st_mode, st_uid=123456789)
            with patch.object(native.os, 'fstat', side_effect=untrusted), \
                    patch.object(native.subprocess, 'Popen') as launch:
                with self.assertRaisesRegex(stage.Hold, 'parent_owner'):
                    native.Commands(Path(directory) / 'native.log').run_upgrade(['fixture-upgrader'])
                launch.assert_not_called()

    def test_readonly_timeout_and_failure(self):
        commands = native.Commands('/var/log/private/native.log')
        with patch.object(native.subprocess, 'run', side_effect=subprocess.TimeoutExpired('fixture', 120)) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                commands.check(['fixture-readonly'])
            self.assertEqual(run.call_args.kwargs['timeout'], 120)
        with patch.object(native.subprocess, 'run', return_value=SimpleNamespace(returncode=1, stdout=b'failure')):
            with self.assertRaisesRegex(stage.Hold, 'readonly_check_failed'):
                commands.check(['fixture-readonly'])

    def test_installed_upgrader_ownership_and_integrity(self):
        safe = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=0)
        owner = 'ubuntu-release-upgrader-core: ' + native.UPGRADER
        for case in ['safe', 'owner', 'modified', 'symlink', 'writable', 'nonroot']:
            with self.subTest(case=case):
                info = safe
                if case == 'symlink':
                    info = SimpleNamespace(st_mode=stat.S_IFLNK | 0o777, st_uid=0)
                elif case == 'writable':
                    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o775, st_uid=0)
                elif case == 'nonroot':
                    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o755, st_uid=1000)
                commands = Mock()
                commands.check.side_effect = [owner if case != 'owner' else 'unexpected-package: ' + native.UPGRADER,
                                              '??5?????? /modified' if case == 'modified' else '']
                with patch.object(native.Path, 'lstat', return_value=info):
                    if case == 'safe':
                        native.verify_installed_upgrader(commands)
                    else:
                        with self.assertRaises(stage.Hold):
                            native.verify_installed_upgrader(commands)
                if case in ['symlink', 'writable', 'nonroot']:
                    commands.check.assert_not_called()


if __name__ == '__main__':
    unittest.main()
