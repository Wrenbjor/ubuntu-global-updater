"""Offline regression test for the legacy PHP-only checkpoint."""

import unittest

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
