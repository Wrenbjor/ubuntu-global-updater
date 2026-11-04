import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('simple_config_tested',Path(__file__).with_name('php85_config.py'))
C=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(C)


class ConfigFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix='php85-simple-config-')
        self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.root.chmod(0o700);self.uid=os.getuid()
        self.site='/etc/nginx/sites-enabled/site.conf'
        self.source_pool='/etc/php/7.4/fpm/pool.d/www.conf'
        self.target_pool='/etc/php/8.5/fpm/pool.d/www.conf'
        self.pool='[www]\nuser=forge\ngroup=forge\nlisten=/run/php/php7.4-fpm.sock\npm.max_children=8\nenv[FIXTURE_TOKEN]=private-fixture-value\n'
        self.write(self.source_pool,self.pool,0o640)
        self.write(self.target_pool,'[www]\nuser=forge\ngroup=forge\nlisten=/run/php/php8.5-fpm.sock\npm.max_children=99\n',0o644)
        self.text=('server {\n listen 443 ssl;\n server_name example.com www.example.com;\n'
            ' include forge-conf/site/before/*;\n location ~ \\.php$ { include fastcgi_params;\n'
            ' fastcgi_pass unix:/run/php/php7.4-fpm.sock;\n }\n include forge-conf/site/after/*;\n}\n')
        self.write(self.site,self.text)
        for branch in ('7.4','8.5'):
            for sapi in ('cli','fpm'):
                self.write('/etc/php/'+branch+'/'+sapi+'/php.ini','memory_limit=512M\n')
                (self.root/('etc/php/'+branch+'/'+sapi+'/conf.d')).mkdir()
        self.source=dict(version='7.4.33',directory='/usr/lib/php/20190902',modules=['Core','json','mysqli','mysqlnd'],
            ini={'memory_limit':'512M','display_errors':'0','mysqli.default_socket':None,'mysqli.reconnect':'0'})
        self.target=dict(version='8.5.13',directory='/usr/lib/php/20250925',modules=['Core','json','mysqli','mysqlnd'],
            ini={'memory_limit':'512M','display_errors':'0','mysqli.default_socket':'/var/run/mysqld/mysqld.sock'})
        self.backup=self.root/'manual-run/backup'

    def write(self,path,text,mode=0o644):
        file=self.root/path.lstrip('/');file.parent.mkdir(parents=True,exist_ok=True)
        file.write_text(text);file.chmod(mode);return file

    def dump(self,text=None):
        return ('nginx: configuration file /etc/nginx/nginx.conf test is successful\n'
            '# configuration file /etc/nginx/nginx.conf:\ninclude /etc/nginx/modules-enabled/*.conf;\n'
            '# configuration file /usr/share/nginx/modules-available/mod-http-image-filter.conf:\n'
            'load_module modules/ngx_http_image_filter_module.so;\n'
            '# configuration file '+self.site+':\n'+(self.text if text is None else text))

    def plan(self,**kwargs):
        return C.plan_configuration(self.dump(),self.source,self.target,root=self.root,owner_uid=self.uid,**kwargs)

    def apply(self,plan,kinds):
        return C.apply_configuration(plan,self.backup,root=self.root,owner_uid=self.uid,kinds=kinds)

    def test_native_dump_uses_routes_not_vendor_module_or_relative_Forge_include_paths(self):
        parsed=C.parse_nginx_dump(self.dump())
        self.assertEqual(parsed['source_branch'],'7.4')
        self.assertEqual(parsed['routes'],[dict(file=self.site,old_socket='/run/php/php7.4-fpm.sock',new_socket='/run/php/php8.5-fpm.sock')])
        self.assertIn('example.com',parsed['health_candidates'])

    def test_ready_85_reuses_existing_pool_and_INI_and_changes_only_known_route(self):
        pool=(self.root/self.target_pool.lstrip('/')).read_bytes()
        ini=(self.root/'etc/php/8.5/fpm/php.ini').read_bytes()
        plan=self.plan(reuse_target=True)
        self.assertEqual([row['kind'] for row in plan['changes']],['route'])
        self.apply(plan,('route',))
        self.assertIn('php8.5-fpm.sock',(self.root/self.site.lstrip('/')).read_text())
        self.assertEqual((self.root/self.target_pool.lstrip('/')).read_bytes(),pool)
        self.assertEqual((self.root/'etc/php/8.5/fpm/php.ini').read_bytes(),ini)
        backups=list(self.backup.glob('*.before'));self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_text(),self.text);self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode),0o600)

    def test_web85_healthy_configuration_is_a_noop(self):
        self.text=self.text.replace('php7.4-fpm.sock','php8.5-fpm.sock');self.write(self.site,self.text)
        plan=C.plan_configuration(self.dump(),self.target,self.target,root=self.root,owner_uid=self.uid)
        self.assertTrue(plan['reuse_target']);self.assertEqual(plan['changes'],[])

    def test_default_CLI_already85_does_not_change_web_source_selection(self):
        self.source['CLI_version']='8.5.13'
        plan=self.plan(reuse_target=True)
        self.assertEqual(plan['source_branch'],'7.4');self.assertEqual([r['kind'] for r in plan['changes']],['route'])

    def test_fresh_prepare_preserves_pool_settings_privacy_and_safe_INI_before_route_switch(self):
        oldjob=self.write('/var/lib/ubuntu-php85-upgrade/current.json','old failure evidence\n',0o600)
        plan=self.plan();self.apply(plan,('pool','ini'))
        self.assertEqual((self.root/self.site.lstrip('/')).read_text(),self.text)
        pool=self.root/self.target_pool.lstrip('/');new=pool.read_text()
        self.assertIn('pm.max_children=8',new);self.assertIn('env[FIXTURE_TOKEN]=private-fixture-value',new)
        self.assertIn('listen=/run/php/php8.5-fpm.sock',new)
        self.assertFalse(pool.stat().st_mode&0o007,'private source pool must not become world readable')
        overlay=(self.root/'etc/php/8.5/fpm/conf.d/99-php85-updater.ini').read_text()
        self.assertIn('memory_limit="512M"',overlay);self.assertNotIn('mysqli.reconnect',overlay)
        self.assertNotIn('mysqli.default_socket',overlay)
        self.assertEqual(oldjob.read_text(),'old failure evidence\n')
        self.apply(plan,('route',));self.assertIn('php8.5-fpm.sock',(self.root/self.site.lstrip('/')).read_text())

    def test_comments_and_quoted_non_directives_are_not_route_edits(self):
        extra='# fastcgi_pass unix:/run/php/php7.4-fpm.sock;\nset $example "fastcgi_pass unix:/run/php/php7.4-fpm.sock;";\n'
        self.text=extra+self.text;self.write(self.site,self.text)
        plan=self.plan(reuse_target=True);rendered=plan['changes'][0]['content']
        self.assertTrue(rendered.startswith(extra));self.assertEqual(rendered.count('php8.5-fpm.sock'),1)

    def test_mixed_TCP_variable_and_missing_native_dump_routes_are_rejected(self):
        for text in (self.text+'server { server_name other.example; fastcgi_pass unix:/run/php/php8.3-fpm.sock; }\n',
            self.text.replace('unix:/run/php/php7.4-fpm.sock','127.0.0.1:9000'),
            self.text.replace('unix:/run/php/php7.4-fpm.sock','$php_backend'),
            'server { server_name unrelated.example; return 200; }\n'+self.text):
            with self.subTest(text=text):
                with self.assertRaises(C.ConfigError):C.parse_nginx_dump(self.dump(text))
        with self.assertRaises(C.ConfigError):C.parse_nginx_dump(self.text)

    def test_loader_and_unavailable_extension_profiles_hold_without_any_writes(self):
        self.source['ini']['auto_prepend_file']='/private/application/bootstrap.php'
        with self.assertRaises(C.ConfigError):self.plan()
        self.assertFalse(self.backup.exists())
        self.source['ini'].pop('auto_prepend_file');self.target['modules'].remove('mysqli')
        with self.assertRaises(C.ConfigError):self.plan(reuse_target=True)

    def test_existing_target_supported_setting_mismatch_holds_instead_of_overwriting_live_85(self):
        self.target['ini']['memory_limit']='256M'
        with self.assertRaises(C.ConfigError):self.plan(reuse_target=True)
        self.assertFalse(self.backup.exists())

    def test_route_drift_during_backup_is_not_overwritten(self):
        plan=self.plan(reuse_target=True);actual_fsync=C.os.fsync;changed=False
        def fsync(fd):
            nonlocal changed
            actual_fsync(fd)
            if not changed and '/backup/' in os.readlink('/proc/self/fd/'+str(fd)):
                changed=True;self.write(self.site,self.text+'# external drift\n')
        with patch.object(C.os,'fsync',side_effect=fsync):
            with self.assertRaises(C.ConfigError):self.apply(plan,('route',))
        self.assertIn('# external drift',(self.root/self.site.lstrip('/')).read_text())
        self.assertNotIn('php8.5-fpm.sock',(self.root/self.site.lstrip('/')).read_text())

    def test_world_writable_new_INI_parent_is_rejected(self):
        plan=self.plan();(self.root/'etc/php/8.5/fpm/conf.d').chmod(0o777)
        with self.assertRaises(C.ConfigError):self.apply(plan,('ini',))
        self.assertFalse((self.root/'etc/php/8.5/fpm/conf.d/99-php85-updater.ini').exists())

    def test_separate_source_CLI_and_FPM_values_are_not_collapsed_into_one_overlay(self):
        source_cli=dict(self.source,ini=dict(self.source['ini'],memory_limit='-1'))
        target_cli=dict(self.target,ini=dict(self.target['ini'],memory_limit='128M'))
        plan=self.plan(source_CLI_registry=source_cli,target_CLI_registry=target_cli)
        self.apply(plan,('pool','ini'))
        self.assertIn('memory_limit="512M"',(self.root/'etc/php/8.5/fpm/conf.d/99-php85-updater.ini').read_text())
        self.assertIn('memory_limit="-1"',(self.root/'etc/php/8.5/cli/conf.d/99-php85-updater.ini').read_text())

    def test_missing_target_preflight_validates_all_source_inputs_without_target_reads_or_writes(self):
        read=C._read
        def source_only(path,*args,**kwargs):
            self.assertFalse(path.startswith('/etc/php/8.5/'));return read(path,*args,**kwargs)
        with patch.object(C,'_read',side_effect=source_only):
            plan=C.plan_configuration(self.dump(),self.source,None,root=self.root,owner_uid=self.uid)
        self.assertTrue(plan['install_needed']);self.assertEqual(plan['changes'],[])
        self.write('/etc/php/7.4/fpm/php.ini','auto_prepend_file=/private/app.php\n')
        with self.assertRaises(C.ConfigError):C.plan_configuration(self.dump(),self.source,None,root=self.root,owner_uid=self.uid)
        self.write('/etc/php/7.4/fpm/php.ini','extension_dir=/usr/lib/php/20000000\n')
        with self.assertRaises(C.ConfigError):C.validate_source_ini('7.4',root=self.root,owner_uid=self.uid,expected_directory='/usr/lib/php/20190902')
        self.assertFalse(self.backup.exists())

    def test_file_replaced_by_FIFO_between_lstat_and_open_is_rejected_without_read_or_block(self):
        file=self.root/self.site.lstrip('/');real_open=C.os.open;real_fdopen=C.os.fdopen;reads=[]
        def open_file(path,flags,*args,**kwargs):
            if str(path)==str(file):
                self.assertTrue(flags&os.O_NONBLOCK);file.unlink();os.mkfifo(file,0o600)
            return real_open(path,flags,*args,**kwargs)
        class NoRead:
            def __init__(self,stream):self.stream=stream
            def __enter__(self):return self
            def __exit__(self,*args):return self.stream.__exit__(*args)
            def fileno(self):return self.stream.fileno()
            def read(self,*args):reads.append(args);raise AssertionError('changed inode must never be read')
        with patch.object(C.os,'open',side_effect=open_file),patch.object(C.os,'fdopen',side_effect=lambda fd,*a,**k:NoRead(real_fdopen(fd,*a,**k))):
            with self.assertRaises(C.ConfigError):C._read(self.site,self.root,self.uid,'/etc/nginx')
        self.assertEqual(reads,[])

    def test_files_session_path_and_serialization_are_preserved(self):
        self.source['ini'].update({'session.save_handler':'files','session.save_path':'/var/lib/php/custom-sessions','session.serialize_handler':'php_serialize'})
        self.target['ini'].update({'session.save_handler':'files','session.save_path':'/var/lib/php/sessions','session.serialize_handler':'php'})
        plan=self.plan();self.apply(plan,('pool','ini'))
        overlay=(self.root/'etc/php/8.5/fpm/conf.d/99-php85-updater.ini').read_text()
        self.assertIn('session.save_path="/var/lib/php/custom-sessions"',overlay)
        self.assertIn('session.serialize_handler="php_serialize"',overlay)

    def test_nonfiles_session_backend_holds_without_printing_secret_connection_path(self):
        self.source['ini'].update({'session.save_handler':'redis','session.save_path':'tcp://127.0.0.1?auth=fixture-secret'})
        with self.assertRaises(C.ConfigError) as caught:self.plan()
        self.assertNotIn('fixture-secret',str(caught.exception));self.assertNotIn('tcp://',str(caught.exception))
        self.assertFalse(self.backup.exists())

    def test_reused_target_files_session_path_mismatch_holds_without_overwrite(self):
        self.source['ini'].update({'session.save_handler':'files','session.save_path':'/var/lib/php/custom-sessions'})
        self.target['ini'].update({'session.save_handler':'files','session.save_path':'/var/lib/php/sessions'})
        with self.assertRaises(C.ConfigError):self.plan(reuse_target=True)
        self.assertFalse(self.backup.exists())

    def test_target_custom_session_backend_is_not_silently_retyped_using_source_files_path(self):
        self.source['ini'].update({'session.save_handler':'files','session.save_path':'/var/lib/php/sessions'})
        self.target['ini'].update({'session.save_handler':'redis','session.save_path':'tcp://127.0.0.1?auth=fixture-secret'})
        with self.assertRaises(C.ConfigError) as caught:self.plan()
        self.assertNotIn('fixture-secret',str(caught.exception));self.assertFalse(self.backup.exists())


if __name__=='__main__':unittest.main()
