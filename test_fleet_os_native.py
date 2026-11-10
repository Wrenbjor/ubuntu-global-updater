import contextlib
import copy
import unittest
from unittest.mock import patch

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


if __name__ == '__main__':
    unittest.main()
