import unittest
import test_php85_shell
class IniGuardTests(unittest.TestCase):
    def exercise(self,scenario):return test_php85_shell.BashFixtures.exercise(self,scenario)
    def test_custom_unknown_setting_and_loader_block_before_apt(self):
        for setting in ('curl.cainfo=/private/ca.pem\n','extension=custom.so\n','extension_dir=/old/abi\n'):
            r=self.exercise({'custom_ini':setting})
            self.assertNotEqual(r['rc'],0,r['stdout'])
            self.assertFalse(any(c[0]=='apt-get' for c in r['calls']))
    def test_package_default_and_per_sapi_disabled_modules(self):
        r=self.exercise({'module_states':True,'custom_ini':'precision=14\n'})
        self.assertEqual(r['rc'],0,r['stderr'])
        self.assertEqual(r['module_links']['cli'],['20-curl.ini'])
        self.assertEqual(r['module_links']['fpm'],['20-curl.ini','20-mysqli.ini'])
    def test_changed_nonwhitelist_default_blocks(self):
        r=self.exercise({'module_states':True,'custom_ini':'precision=17\n'})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('Unsupported custom INI directive precision',r['stderr'])
    def test_missing_target_module_never_switches_routes(self):
        r=self.exercise({'module_states':True,'missing_target_module':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('Enabled source module has no PHP 8.5',r['stderr'])
        self.assertEqual(r['site'],r['original'])
    def test_missing_runtime_module_never_switches_routes(self):
        r=self.exercise({'module_states':True,'runtime_missing_module':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('did not load source module',r['stderr'])
        self.assertEqual(r['site'],r['original'])
    def test_unknown_pool_override_blocks_before_apt(self):
        for value in ('php_admin_value[extension_dir]=/old/abi\n','php_value[curl.cainfo]=/private/ca.pem\n'):
            r=self.exercise({'pool_override':value})
            self.assertNotEqual(r['rc'],0)
            self.assertIn('Unsupported pool PHP override',r['stderr'])
            self.assertFalse(any(c[0]=='apt-get' for c in r['calls']))
    def test_target_custom_loader_never_cuts_over(self):
        r=self.exercise({'custom_target_ini':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('target INI',r['stderr'])
        self.assertEqual(r['site'],r['original'])
    def test_failed_run_restores_cli_auto_mode(self):
        r=self.exercise({'bad_health':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn(['update-alternatives','--auto','php'],r['calls'])
    def test_new_auto_best_cannot_silently_replace_saved_cli(self):
        r=self.exercise({'bad_health':True,'auto_best_changed':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('CLI path restored manually',r['stderr'])
        self.assertNotIn(['update-alternatives','--auto','php'],r['calls'])
if __name__=='__main__':unittest.main()
