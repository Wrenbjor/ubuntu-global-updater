"""Offline lifecycle tests. No apt, nginx, FPM, systemd or reboot commands."""
import copy
import tempfile
import unittest
from pathlib import Path
import fleet_os_stage as stage


def snapshot(release='22.04', boot='boot-one'):
    return dict(ubuntu=True, release=release, machine_id='machine-one', boot_id=boot,
                legacy_workflow_clear=True, dpkg_clean=True, active_package_work=False,
                holds=[], reboot_required=False,
                php=dict(cli_version='8.5.12', active_fpm_versions={'www': '8.5.12'},
                         all_nginx_routes_verified=True, modules_verified=True,
                         package_suite=stage.SUITES[release], packages_authenticated=True,
                         installed_packages=['php8.5-cli', 'php8.5-common', 'php8.5-fpm', 'php8.5-redis']))


class Backend:
    def __init__(self, release='22.04'):
        self.value = snapshot(release)
        self.calls = 0
        self.fail = False
        self.bad_php = False
        self.proof = dict.fromkeys(stage.POSTFLIGHT + ('target_kernel_verified',), True)

    def snapshot(self):
        return copy.deepcopy(self.value)

    def prepare(self, decision):
        result = dict.fromkeys(stage.PREFLIGHT, True)
        result.update(target_suite=decision['target_suite'], snapshot_sha256=stage.digest(self.value),
                      php_candidates={n: dict(version='test-debian-revision', authenticated=True,
                                              suite=decision['target_suite'], core=n != 'php8.5-redis',
                                              upstream_version='6.1.0' if n.endswith('redis') else '8.5.12')
                                      for n in self.value['php']['installed_packages']})
        return result

    def upgrade(self, decision, prepared):
        self.calls += 1
        if self.fail:
            raise RuntimeError('fixture failure')
        self.value['release'] = decision['to_release']
        self.value['php']['package_suite'] = decision['target_suite']
        self.value['php']['installed_package_versions'] = {
            name: item['version'] for name, item in prepared['php_candidates'].items()}
        if self.bad_php:
            self.value['php']['cli_version'] = '8.5.13'

    def verify(self, state):
        return self.proof


class LifecycleTests(unittest.TestCase):
    def test_sequential_plan(self):
        self.assertEqual(stage.plan(snapshot())['to_release'], '24.04')
        self.assertEqual(stage.plan(snapshot('24.04'))['to_release'], '26.04')
        self.assertEqual(stage.plan(snapshot('26.04'))['action'], 'complete')

    def test_php_first_exact_and_provenance(self):
        for key, value in [('cli_version', '8.5.13'), ('active_fpm_versions', {}),
                           ('active_fpm_versions', {'www': '8.2.35'}), ('modules_verified', False),
                           ('all_nginx_routes_verified', False), ('package_suite', 'noble'),
                           ('packages_authenticated', False)]:
            with self.subTest(key=key, value=value):
                snap = snapshot()
                snap['php'][key] = value
                with self.assertRaises(stage.Hold):
                    stage.plan(snap)

    def test_prerequisite_holds(self):
        for key, value in [('holds', ['mysql-server']), ('dpkg_clean', False),
                           ('active_package_work', True), ('legacy_workflow_clear', False),
                           ('release', '20.04'), ('machine_id', '')]:
            with self.subTest(key=key):
                snap = snapshot()
                snap[key] = value
                with self.assertRaises(stage.Hold):
                    stage.plan(snap)

    def test_pending_prerequisite_reboot(self):
        snap = snapshot()
        snap['reboot_required'] = True
        self.assertEqual(stage.plan(snap)['action'], 'reboot-required')

    def test_full_two_hops_require_separate_reboot_acceptance(self):
        with tempfile.TemporaryDirectory() as directory, stage.Store(Path(directory) / 'state') as store:
            backend = Backend()
            stage.advance(backend, store, apply=False)
            self.assertIsNone(store.read())
            self.assertEqual(backend.calls, 0)
            for target in ['24.04', '26.04']:
                result = stage.advance(backend, store, apply=True)
                self.assertEqual(result['action'], 'reboot-required')
                self.assertEqual(store.read()['status'], 'pending-reboot')
                self.assertEqual(stage.advance(backend, store, apply=True)['action'], 'reboot-required')
                backend.value['boot_id'] += '-new'
                self.assertEqual(stage.advance(backend, store, apply=False)['action'], 'verify-boot')
                self.assertEqual(store.read()['status'], 'pending-reboot')
                self.assertEqual(stage.advance(backend, store, apply=True)['action'], 'verify-boot')
                self.assertEqual(store.read()['status'], 'boot-verified')
                self.assertEqual(backend.value['release'], target)
            self.assertEqual(stage.advance(backend, store, apply=True)['action'], 'complete')
            self.assertEqual(backend.calls, 2)

    def test_failure_never_retries(self):
        for bad_php in [False, True]:
            with self.subTest(bad_php=bad_php), tempfile.TemporaryDirectory() as directory:
                with stage.Store(Path(directory) / 'state') as store:
                    backend = Backend()
                    backend.fail = not bad_php
                    backend.bad_php = bad_php
                    with self.assertRaises(RuntimeError):
                        stage.advance(backend, store, apply=True)
                    self.assertEqual(store.read()['status'], 'failed-preserve-no-retry')
                    with self.assertRaises(stage.Hold):
                        stage.advance(backend, store, apply=True)
                    self.assertEqual(backend.calls, 1)

    def test_missing_target_package_or_wrong_version_holds(self):
        backend = Backend()
        snap = backend.snapshot()
        decision = stage.plan(snap)
        for change in ['missing', 'newer', 'foreign', 'untrusted', 'adapter', 'database']:
            prepared = backend.prepare(decision)
            if change == 'missing':
                del prepared['php_candidates']['php8.5-redis']
            elif change == 'newer':
                prepared['php_candidates']['php8.5-fpm']['upstream_version'] = '8.5.13'
            elif change == 'foreign':
                prepared['php_candidates']['php8.5-cli']['suite'] = 'jammy'
            elif change == 'untrusted':
                prepared['php_candidates']['php8.5-cli']['authenticated'] = False
            elif change == 'adapter':
                prepared['native_adapter_verified'] = False
            else:
                prepared['database_majors_preserved'] = False
            with self.subTest(change=change), self.assertRaises(stage.Hold):
                stage.preservation(prepared, snap, decision)

    def test_legacy_and_interrupted_checkpoints_preserved(self):
        with self.assertRaisesRegex(stage.Hold, 'legacy_or_unknown'):
            stage.plan(snapshot('24.04'), {'phase': 'part2-complete'})
        for status in ['installing', 'failed-preserve-no-retry', 'complete']:
            state = dict(schema=2, stage='fleet-os-php-first', machine_id='machine-one',
                         from_release='22.04', to_release='24.04', status=status)
            with self.assertRaisesRegex(stage.Hold, 'interrupted_or_failed'):
                stage.plan(snapshot('24.04'), state)

    def test_postboot_health_failure_does_not_accept(self):
        with tempfile.TemporaryDirectory() as directory, stage.Store(Path(directory) / 'state') as store:
            backend = Backend()
            stage.advance(backend, store, apply=True)
            backend.value['boot_id'] = 'boot-two'
            backend.proof['target_kernel_verified'] = False
            with self.assertRaises(stage.Hold):
                stage.advance(backend, store, apply=True)
            self.assertEqual(store.read()['status'], 'pending-reboot')
            self.assertEqual(backend.calls, 1)

    def test_old_receipt_is_not_adopted(self):
        state = dict(schema=1, stage='fleet-os-php-first', machine_id='machine-one',
                     from_release='22.04', to_release='24.04', status='pending-reboot')
        with self.assertRaisesRegex(stage.Hold, 'legacy_or_unknown'):
            stage.plan(snapshot('24.04'), state)

    def test_exact_package_receipt_after_hop_and_boot(self):
        for phase in ['hop', 'boot']:
            for change in ['missing', 'extra', 'extension-version', 'core-version', 'no-versions']:
                with self.subTest(phase=phase, change=change), tempfile.TemporaryDirectory() as directory:
                    with stage.Store(Path(directory) / 'state') as store:
                        backend = Backend()
                        def corrupt():
                            php = backend.value['php']
                            if change == 'missing':
                                php['installed_packages'].remove('php8.5-redis')
                                del php['installed_package_versions']['php8.5-redis']
                            elif change == 'extra':
                                php['installed_packages'].append('php8.5-mysql')
                                php['installed_package_versions']['php8.5-mysql'] = 'unplanned'
                            elif change == 'no-versions':
                                del php['installed_package_versions']
                            else:
                                name = 'php8.5-redis' if change == 'extension-version' else 'php8.5-fpm'
                                php['installed_package_versions'][name] = 'different-revision'
                        if phase == 'hop':
                            original = backend.upgrade
                            def upgrade(decision, prepared):
                                original(decision, prepared)
                                corrupt()
                            backend.upgrade = upgrade
                        else:
                            stage.advance(backend, store, apply=True)
                            backend.value['boot_id'] = 'boot-two'
                            corrupt()
                        with self.assertRaises(stage.Hold):
                            stage.advance(backend, store, apply=True)
                        self.assertEqual(store.read()['status'],
                                         'failed-preserve-no-retry' if phase == 'hop' else 'pending-reboot')
                        self.assertEqual(backend.calls, 1)

    def test_receipt_missing_or_changed_holds(self):
        for change in ['missing', 'changed']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                with stage.Store(Path(directory) / 'state') as store:
                    backend = Backend()
                    stage.advance(backend, store, apply=True)
                    state = store.read()
                    if change == 'missing':
                        del state['package_plan']
                    else:
                        state['package_plan']['php_candidates']['php8.5-redis']['version'] = 'changed'
                    store.write(state)
                    backend.value['boot_id'] = 'boot-two'
                    with self.assertRaisesRegex(stage.Hold, 'package_plan_receipt'):
                        stage.advance(backend, store, apply=True)
                    self.assertEqual(store.read(), state)

    def test_accepted_boot_fresh_health_and_separate_later_boot(self):
        for initial in ['22.04', '24.04']:
            with self.subTest(initial=initial), tempfile.TemporaryDirectory() as directory:
                with stage.Store(Path(directory) / 'state') as store:
                    backend = Backend(initial)
                    stage.advance(backend, store, apply=True)
                    backend.value['boot_id'] = 'boot-two'
                    stage.advance(backend, store, apply=True)
                    accepted = store.read()
                    for boot in ['boot-two', 'boot-three']:
                        for proof in ['application_health_verified', 'target_kernel_verified']:
                            backend.value['boot_id'] = boot
                            backend.proof[proof] = False
                            with self.assertRaises(stage.Hold):
                                stage.advance(backend, store, apply=True)
                            backend.proof[proof] = True
                            self.assertEqual(store.read(), accepted)
                            self.assertEqual(backend.calls, 1)
                    result = stage.advance(backend, store, apply=False)
                    self.assertEqual(result['action'], 'verify-boot')
                    self.assertEqual(store.read(), accepted)
                    result = stage.advance(backend, store, apply=True)
                    self.assertEqual(result['action'], 'verify-boot')
                    self.assertEqual(store.read()['accepted_boot_id'], 'boot-three')
                    self.assertEqual(backend.calls, 1)

    def test_store_lock_and_interrupted_write(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'state'
            with stage.Store(path) as store:
                with self.assertRaises(BlockingIOError):
                    with stage.Store(path):
                        pass
                (path / 'state.next').write_text('partial')
                with self.assertRaises(FileExistsError):
                    store.write({'new': True})

    def test_store_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'link'
            path.symlink_to(directory)
            with self.assertRaises(stage.Hold):
                with stage.Store(path):
                    pass


if __name__ == '__main__':
    unittest.main()
