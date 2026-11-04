import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC=importlib.util.spec_from_file_location('simple_updater_tested',Path(__file__).with_name('php85_upgrade.py'))
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)
VERSION='8.5.13-1+ubuntu22.04.1+deb.sury.org+1'


class FlowFixtures(unittest.TestCase):
    def exercise(self,*,ready=True,web='7.4',apply=True,lock_busy=False,baseline_bad=False,
                 final_bad=False,config_bad=False,source_bad=False,protected_change=False,
                 stock_target=False,cli_only=False,incompatible_target=False,timer_bad=False):
        with tempfile.TemporaryDirectory(prefix='php85-simple-flow-') as temporary:
            root=Path(temporary);state=root/'manual-state';state.mkdir();run=state/'run-fixture';run.mkdir()
            facts={}
            for logical,text in (('/etc/os-release','ID=ubuntu\nVERSION_ID="22.04"\n'),
                ('/proc/sys/kernel/osrelease','5.15.0-fixture-generic\n'),('/etc/machine-id','f'*32+'\n'),
                ('/usr/bin/php7.4','fixture CLI not executed\n'),('/usr/bin/php8.5','fixture CLI not executed\n')):
                path=root/('facts-'+str(len(facts)));path.write_text(text);facts[logical]=path
            old=root/'old-current.json';old.write_bytes(b'unchanged old failed checkpoint\n')
            table={'php'+web+'-'+name:VERSION if web=='8.5' else '7.4.33-31+ubuntu22.04.1+deb.sury.org+1'
                for name in ('cli','common','fpm','mysql','json')}
            table.update(nginx='1.20.0',**{'mysql-community-server-core':'8.0.44','redis-server':'6.0.16'})
            if ready:table.update({'php8.5-'+name:VERSION for name in ('cli','common','fpm','mysql')})
            if cli_only:table.update({'php8.5-'+name:VERSION for name in ('cli','common')})
            events=[];health_calls=0;current_table=dict(table)
            active85=ready and not stock_target;default_cli='8.5' if ready or cli_only else '7.4'
            timer_active=True
            dump='# configuration file /etc/nginx/sites-enabled/site.conf:\nserver { server_name example.com; fastcgi_pass unix:/run/php/php'+web+'-fpm.sock; }\n'
            class FakeRunner:
                def run(inner,args,timeout=60,check=True):
                    nonlocal health_calls,current_table,active85,default_cli,timer_active
                    events.append(dict(kind='command',args=args,timeout=timeout,check=check))
                    if args[:2]==['/usr/bin/systemd-detect-virt','--container']:return None
                    if args==['/usr/bin/dpkg','--audit']:return ''
                    if args[0]=='/usr/bin/dpkg-query':
                        return ''.join('ii \t'+name+'\t'+version+'\n' for name,version in sorted(current_table.items()))
                    if args[:2]==['/usr/bin/apt-cache','policy']:
                        return args[2]+':\n  Candidate: '+VERSION+'\n  Version table:\n     '+VERSION+' 500\n        500 https://ppa.launchpadcontent.net/ondrej/php/ubuntu jammy/main amd64 Packages\n'
                    if args[0]=='/usr/bin/apt-get':
                        if '-s' in args:
                            if protected_change:return 'Inst mysql-community-server-core [8.0.44] (9.0.1 fixture)\n'
                            return ''.join('Inst '+name+' ('+VERSION+' fixture)\n' for name in ('php8.5-cli','php8.5-common','php8.5-fpm','php8.5-mysql')
                                if current_table.get(name)!=VERSION)
                        if 'install' in args:
                            self.assertIsNone(timeout,'native package transaction must have no kill timeout')
                            self.assertIn('--no-remove',args);self.assertIn('DPkg::Lock::Timeout=60',args)
                            if lock_busy:raise M.Stop('command_failed_apt-get')
                            for item in args:
                                if item.startswith('php8.5-') and '=' in item:
                                    name,version=item.split('=',1);current_table[name]=version
                            default_cli='8.5'
                        return ''
                    if args[:2]==['/usr/bin/dpkg','--compare-versions']:return ''
                    if args==['/usr/sbin/nginx','-T']:return dump
                    if args[0]=='/usr/sbin/php-fpm8.5' and config_bad:raise M.Stop('command_failed_php-fpm8.5')
                    if args[0] in ('/usr/sbin/nginx','/usr/sbin/php-fpm8.5'):return ''
                    if args[:2]==['/bin/systemctl','is-active']:
                        if args[2]=='nginx':return 'active'
                        if args[2]=='php8.5-fpm':return 'active' if active85 else None
                        return 'active' if args[2]=='apt-daily.timer' and timer_active else None
                    if args[:2]==['/bin/systemctl','stop'] and args[-1]=='apt-daily.timer':timer_active=False;return ''
                    if args[:2]==['/bin/systemctl','start'] and args[-1]=='apt-daily.timer':timer_active=not timer_bad;return ''
                    if args[:2]==['/bin/systemctl','is-enabled']:return 'enabled' if ready else None
                    if args[:2] in (['/bin/systemctl','start'],['/bin/systemctl','restart']) and args[-1]=='php8.5-fpm':active85=True;return ''
                    if args[0]=='/bin/systemctl':return ''
                    if args[:2]==['/usr/bin/update-alternatives','--query']:
                        return 'Name: php\nStatus: auto\nValue: /usr/bin/php'+default_cli+'\n'
                    if args[:2]==['/usr/bin/update-alternatives','--set']:default_cli=args[-1][-3:];return ''
                    if args[0]=='/usr/bin/php':return '8.5.13'
                    if args[0]=='/usr/bin/curl':
                        health_calls+=1
                        return '503' if baseline_bad or final_bad and health_calls>2 else '200'
                    raise AssertionError('native command escaped fixture '+repr(args))
            def registry(runner,branch,sapi='fpm'):
                return dict(version='8.5.13' if branch=='8.5' else '7.4.33',directory='/usr/lib/php/20250925',
                    modules=['Core','json','mysqli'],ini={'memory_limit':'512M'})
            def plan(dump,source,target=None,**kwargs):
                events.append(dict(kind='plan',target=target is not None,reuse=kwargs.get('reuse_target',False)))
                if source_bad:raise M.CFG.ConfigError('source_profile_requires_review')
                if incompatible_target and kwargs.get('reuse_target'):raise M.CFG.ConfigError('existing_target_pool_identity_or_socket_mismatch')
                changes=[]
                if target is not None:
                    if not kwargs.get('reuse_target',False) and web!='8.5':changes += [{'kind':k} for k in ('pool','ini','ini')]
                    if web!='8.5':changes.append({'kind':'route'})
                return dict(schema=1,changes=changes,new_socket='/run/php/php8.5-fpm.sock')
            def configure(plan,backup_dir,**kwargs):events.append(dict(kind='configure',kinds=kwargs['kinds'],changes=plan['changes']))
            def proof(*args):events.append(dict(kind='runtime'));return dict(master_pid=1234,socket='/run/php/php8.5-fpm.sock')
            def paths(value):
                if str(value)=='/usr/bin/php':return facts['/usr/bin/php'+default_cli]
                return facts.get(str(value),Path(value))
            error=None;result=None
            with patch.object(M,'STATE',state),patch.object(M,'Path',side_effect=paths),\
                 patch.object(M,'registry',side_effect=registry),patch.object(M,'native_target',side_effect=proof),\
                 patch.object(M,'stock_target_pool',return_value=stock_target),\
                 patch.object(M.CFG,'plan_configuration',side_effect=plan),patch.object(M.CFG,'apply_configuration',side_effect=configure),\
                 patch.object(M.subprocess,'run',side_effect=AssertionError('real subprocess forbidden')),\
                 contextlib.redirect_stdout(io.StringIO()):
                try:result=M.execute(FakeRunner(),apply,run if apply else None)
                except (M.Stop,M.CFG.ConfigError) as caught:error=str(caught)
            status=json.loads((run/'status.json').read_text()) if (run/'status.json').exists() else None
            return dict(result=result,error=error,events=events,status=status,old=old.read_bytes())

    def commands(self,result):return [e['args'] for e in result['events'] if e['kind']=='command']

    def test_current_installed85_refreshes_once_but_skips_install_and_target_config_rewrite(self):
        r=self.exercise();self.assertIsNone(r['error']);commands=self.commands(r)
        self.assertEqual(sum(c[0]=='/usr/bin/apt-get' and 'update' in c for c in commands),1)
        self.assertFalse(any(c[0]=='/usr/bin/apt-get' and 'install' in c and '-s' not in c for c in commands))
        configurations=[e for e in r['events'] if e['kind']=='configure']
        self.assertTrue(all(row['kind']=='route' for e in configurations for row in e['changes']))
        self.assertEqual(r['status']['phase'],'complete');self.assertEqual(r['old'],b'unchanged old failed checkpoint\n')
        self.assertFalse(any(c[:3]==['/usr/bin/update-alternatives','--set','php'] and c[-1]!='/usr/bin/php8.5' for c in commands))

    def test_already_web85_healthy_has_no_install_restart_or_Nginx_reload(self):
        r=self.exercise(web='8.5');self.assertIsNone(r['error']);commands=self.commands(r)
        self.assertFalse(any(c[0]=='/usr/bin/apt-get' and 'install' in c and '-s' not in c for c in commands))
        self.assertNotIn(['/bin/systemctl','restart','php8.5-fpm'],commands)
        self.assertNotIn(['/bin/systemctl','reload','nginx'],commands)
        self.assertTrue(all(not e['changes'] for e in r['events'] if e['kind']=='configure'))

    def test_missing85_installs_matching_extensions_then_proves_FPM_before_switch(self):
        r=self.exercise(ready=False);self.assertIsNone(r['error']);commands=self.commands(r)
        install=next(c for c in commands if c[0]=='/usr/bin/apt-get' and 'install' in c and '-s' not in c)
        self.assertIn('php8.5-mysql='+VERSION,install);self.assertFalse(any(c.startswith('php8.5-json=') for c in install))
        prepare=next(i for i,e in enumerate(r['events']) if e['kind']=='configure' and e['kinds']==('pool','ini'))
        proof=next(i for i,e in enumerate(r['events']) if e['kind']=='runtime')
        routes=next(i for i,e in enumerate(r['events']) if e['kind']=='configure' and e['kinds']==('route',))
        self.assertLess(prepare,proof);self.assertLess(proof,routes)

    def test_installed_stock_inactive85_is_configured_without_package_replay(self):
        r=self.exercise(stock_target=True);self.assertIsNone(r['error']);commands=self.commands(r)
        self.assertFalse(any(c[0]=='/usr/bin/apt-get' and 'install' in c and '-s' not in c for c in commands))
        self.assertIn(['/bin/systemctl','start','php8.5-fpm'],commands)
        self.assertTrue(any(row['kind']=='pool' for e in r['events'] if e['kind']=='configure' for row in e['changes']))

    def test_CLI_only85_still_installs_FPM_and_unknown_existing_pool_is_not_overwritten(self):
        r=self.exercise(ready=False,cli_only=True);self.assertIsNone(r['error'])
        self.assertTrue(any(c[0]=='/usr/bin/apt-get' and 'install' in c and '-s' not in c for c in self.commands(r)))
        r=self.exercise(incompatible_target=True);self.assertIsNotNone(r['error'])
        self.assertFalse(any(c[0]=='/usr/bin/apt-get' for c in self.commands(r)))
        self.assertFalse(any(e['kind']=='configure' for e in r['events']))

    def test_baseline_failure_or_invalid_source_never_reaches_APT_or_cutover(self):
        for kwargs in ({'baseline_bad':True},{'source_bad':True}):
            with self.subTest(kwargs=kwargs):
                r=self.exercise(**kwargs);self.assertIsNotNone(r['error'])
                self.assertFalse(any(c[0]=='/usr/bin/apt-get' for c in self.commands(r)))
                self.assertFalse(any(e['kind']=='configure' for e in r['events']))

    def test_APT_lock_failure_preserves_jobs_restores_timers_and_never_kills_owner(self):
        r=self.exercise(ready=False,lock_busy=True);self.assertEqual(r['error'],'command_failed_apt-get')
        commands=self.commands(r);self.assertIn(['/bin/systemctl','start','apt-daily.timer'],commands)
        self.assertFalse(any(Path(c[0]).name in ('kill','pkill','killall') for c in commands))
        self.assertFalse(any(e['kind']=='configure' for e in r['events']));self.assertEqual(r['status']['phase'],'failed')

    def test_protected_package_simulation_and_FPM_config_failure_never_switch_routes(self):
        for kwargs in ({'protected_change':True},{'config_bad':True}):
            with self.subTest(kwargs=kwargs):
                r=self.exercise(**kwargs);self.assertIsNotNone(r['error'])
                self.assertFalse(any(e['kind']=='configure' and e['kinds']==('route',) for e in r['events']))

    def test_plan_only_is_cached_and_does_not_write_apply_receipt_or_refresh(self):
        r=self.exercise(apply=False);self.assertIsNone(r['error']);self.assertEqual(r['result']['status'],'plan-only')
        self.assertIsNone(r['status']);self.assertFalse(any('update' in c for c in self.commands(r)))
        self.assertFalse(any(e['kind']=='configure' for e in r['events']))

    def test_failed_post_cutover_health_is_not_reported_complete(self):
        r=self.exercise(final_bad=True);self.assertEqual(r['error'],'application_health_failed')
        self.assertEqual(r['status']['phase'],'failed');self.assertIsNone(r['result'])

    def test_timer_restore_failure_is_not_complete_and_is_attempted_only_once(self):
        r=self.exercise(timer_bad=True);self.assertEqual(r['error'],'APT_timer_restore_failed')
        self.assertEqual(r['status']['phase'],'failed');self.assertIsNone(r['result'])
        self.assertEqual(self.commands(r).count(['/bin/systemctl','start','apt-daily.timer']),1)


class RunnerFixtures(unittest.TestCase):
    def test_generated_registry_query_omits_nonfiles_session_credentials_but_preserves_files_path(self):
        environment=dict(PATH='/usr/bin:/bin',HOME='/nonexistent',LANG='C',LC_ALL='C')
        info=json.loads(M.subprocess.check_output(['/usr/bin/php','-n','-r',
            'echo json_encode(["branch"=>PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION,"directory"=>PHP_EXTENSION_DIR]);'],
            env=environment,timeout=10))
        for handler,path in (('files','/var/lib/php/custom-sessions'),('redis','tcp://127.0.0.1?auth=fixture-secret')):
            facts={'session.save_handler':handler,'session.save_path':path}
            def native_query(args,**kwargs):
                if '-n' in args:return info['directory']
                script=args[-1].replace('$all=ini_get_all(null,false);','$all=json_decode('+json.dumps(json.dumps(facts))+',true);',1)
                return M.subprocess.check_output(['/usr/bin/php','-n','-r',script],env=environment,timeout=10).decode()
            with patch.object(M.CFG,'validate_source_ini',return_value=True):
                result=M.registry(SimpleNamespace(run=native_query),info['branch'])
            if handler=='files':self.assertEqual(result['ini']['session.save_path'],path)
            else:self.assertNotIn('session.save_path',result['ini']);self.assertNotIn('fixture-secret',json.dumps(result))

    def test_archive_is_exact_private_exclusive_and_APT_hook_uses_saved_run_source(self):
        with tempfile.TemporaryDirectory(prefix='php85-simple-source-') as temporary:
            run=Path(temporary);M.archive_source(run)
            for name,original in (('php85_upgrade.py',Path(M.__file__)),('php85_config.py',Path(M.CFG.__file__))):
                self.assertEqual((run/name).read_bytes(),original.read_bytes())
                self.assertEqual((run/name).stat().st_mode&0o777,0o600)
            hook=M.apt_hook(run,{'php8.5-cli':VERSION})
            self.assertIn(str(run/'php85_upgrade.py'),hook.read_text())
            self.assertNotIn(str(Path(M.__file__)),hook.read_text())
            with self.assertRaises(FileExistsError):M.archive_source(run)

    def test_native_deprecation_stderr_with_zero_exit_does_not_fail_FPM_test(self):
        with tempfile.TemporaryDirectory(prefix='php85-simple-command-') as temporary:
            def native(args,**kwargs):
                self.assertEqual(args,['/usr/sbin/php-fpm8.5','-t'])
                kwargs['stderr'].write(b'PHP Deprecated: fixture deprecation\n');return SimpleNamespace(returncode=0)
            with patch.object(M.subprocess,'run',side_effect=native):
                self.assertEqual(M.Runner(temporary).run(['/usr/sbin/php-fpm8.5','-t']),'')
            stderr=list(Path(temporary).glob('*.stderr'));self.assertEqual(len(stderr),1)
            self.assertEqual(stderr[0].stat().st_mode&0o777,0o600)


class MainFixtures(unittest.TestCase):
    def test_status_reads_only_new_manual_receipt_without_locks_or_native_commands(self):
        with tempfile.TemporaryDirectory(prefix='php85-simple-status-') as temporary:
            state=Path(temporary)
            with patch.object(M,'STATE',state),patch.object(M.os,'geteuid',return_value=0),patch.object(M.os,'umask'),\
                 patch.object(M,'maintenance_locks',side_effect=AssertionError('status must not acquire write locks')),\
                 patch.object(M,'Runner',side_effect=AssertionError('status must not run native commands')):
                output=io.StringIO()
                with contextlib.redirect_stdout(output):self.assertEqual(M.main(['--status']),0)
                self.assertEqual(json.loads(output.getvalue()),dict(status='no_simple_updater_run'))
                (state/'current.json').write_text(json.dumps(dict(phase='failed',reason='fixture')))
                output=io.StringIO()
                with contextlib.redirect_stdout(output):M.main(['--status'])
                self.assertEqual(json.loads(output.getvalue()),dict(phase='failed',reason='fixture'))

    def test_explicit_rollback_run_uses_fresh_log_directories_preserving_original_logs(self):
        with tempfile.TemporaryDirectory(prefix='php85-simple-rollback-') as temporary:
            state=Path(temporary);runid='run-20261104T010203Z-0123abcd';run=state/runid;run.mkdir()
            (run/'status.json').write_text(json.dumps(dict(phase='complete',machine_id='fixture')))
            oldlog=run/'001-nginx.stdout';oldlog.write_bytes(b'original evidence\n');logs=[]
            def private(path):path=Path(path);path.mkdir(mode=0o700,exist_ok=True);return path
            def runner(path):logs.append(Path(path));return SimpleNamespace(logs=path)
            with patch.object(M,'STATE',state),patch.object(M.os,'geteuid',return_value=0),patch.object(M.os,'umask'),\
                 patch.object(M,'maintenance_locks',return_value=[]),patch.object(M,'private_directory',side_effect=private),\
                 patch.object(M,'Runner',side_effect=runner),patch.object(M,'rollback',return_value=0) as rollback:
                M.main(['--rollback','--run',runid]);M.main(['--rollback','--run',runid])
                self.assertEqual(rollback.call_count,2)
            self.assertEqual(len(set(logs)),2);self.assertTrue(all(p.parent==run and p.name.startswith('rollback-attempt-') for p in logs))
            self.assertEqual(oldlog.read_bytes(),b'original evidence\n')


if __name__=='__main__':unittest.main()
