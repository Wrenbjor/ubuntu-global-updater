"""Dynamic pool fixtures; all commands mocked, never modifies host services."""
import unittest
import test_php85_shell


class FleetConfigurationTests(unittest.TestCase):
    def exercise(self, scenario):
        return test_php85_shell.BashFixtures.exercise(self, scenario)

    def test_migrates_multiple_pools_and_routes_without_merging_identities(self):
        r = self.exercise({'stock': True, 'multipool': True})
        self.assertEqual(r['rc'], 0, r['stderr'])
        self.assertIn('customer.php85.sock', r['site'])
        self.assertNotIn('unix:/run/php/customer.sock;', r['site'])
        self.assertIn('customer.php85.sock', r['extra_target'])
        self.assertIn('php8.5-fpm.sock', r['target'])
        self.assertIn('process.max=99', r['global_config'])
        self.assertIn('php/8.5/fpm/pool.d/*.conf', r['global_config'])
        self.assertIn('/run/php/php8.5-fpm.pid', r['global_config'])
        self.assertNotIn('php/7.4/', r['global_config'])

    def test_completed_multi_pool_migration_is_rerunnable(self):
        r = self.exercise({'stock': True, 'multipool': True, 'rerun': True})
        self.assertEqual(r['rc'], 0, r['stderr'])
        self.assertIn('web PHP 8.5 -> 8.5.12', r['stdout'])
        self.assertIn('customer.php85.sock', r['extra_target'])
        self.assertNotIn('customer.php85.php85.sock', r['site'])

    def test_inline_routes_cannot_be_silently_omitted(self):
        r = self.exercise({'inline_route': True})
        self.assertNotEqual(r['rc'], 0)
        self.assertIn('no partial migration', r['stderr'])
        self.assertFalse(any(c[0] == 'apt-get' for c in r['calls']))
        self.assertEqual(r['site'], r['original'])

    def test_failed_multi_pool_health_restores_source_routes(self):
        r = self.exercise({'stock': True, 'multipool': True, 'bad_health': True})
        self.assertNotEqual(r['rc'], 0)
        self.assertEqual(r['site'], r['original'])
        self.assertNotIn('COMPLETE', r['stdout'])


if __name__ == '__main__':
    unittest.main()
