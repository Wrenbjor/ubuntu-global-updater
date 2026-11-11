import json
import os
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import unittest

SOURCE=Path(__file__).with_name('php85.sh')
PROXY=r'''#!/usr/bin/python3
import json,os,sys
from pathlib import Path
name=Path(sys.argv[0]).name;args=sys.argv[1:]
root=Path(__file__).resolve().parent.parent
scenario=json.loads((root/'scenario.json').read_text())
with (root/'commands.jsonl').open('a') as log:log.write(json.dumps([name]+args)+'\n')
config=root/'etc';home=root/'home';run=root/'run'
version=scenario.get('package_version','8.5.12')+'-1+ubuntu'+scenario.get('release','22.04')+'.1+deb.sury.org+1'
def done(text='',rc=0):
    if text:print(text,end='' if text.endswith('\n') else '\n')
    raise SystemExit(rc)
if name=='dpkg':done('' if args==['--audit'] else 'amd64')
if name=='dpkg-query':
    if '-L' in args:done(str(root/'usr/share/php8.5-fpm/pool.d/www.conf'))
    status='rc' if scenario.get('source_rc') else 'ii'
    rows=[status+'  php7.4-'+suffix+' 7.4.33\n' for suffix in ('cli','common','fpm','mysql','json')]
    rows+=['ii  php8.5-'+suffix+' '+version+'\n' for suffix in ('cli','common','fpm','mysql')]
    rows+=['ii  nginx 1.20.0\n','ii  mysql-community-server-core 8.0.44\n']
    done(''.join(rows))
if name=='hostname':done('fixture-host')
if name=='nginx':
    if '-T' in args:
        site=config/'nginx/sites-enabled/site.conf'
        main=config/'nginx/nginx.conf'
        extra=config/'nginx/php-shared.conf'
        done('# configuration file '+str(main)+':\nhttp { include '+str(site)+'; }\n'
            +'# configuration file '+str(site)+':\n'+site.read_text()
            +'\n# configuration file '+str(config/'nginx/fastcgi_params')+':\nfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;\n'
            + ('# configuration file '+str(extra)+':\n'+extra.read_text() if extra.exists() else ''),\
            1 if scenario.get('nginx_check_fail') and (root/'apt-done').exists() else 0)
    if '-v' in args:done('nginx version: fixture')
    done('')
if name=='apt-cache':
    if args[0]=='madison':done('' if scenario.get('missing_exact') else args[-1]+' | '+version+' | fixture')
    if len(args)==1:
        suite='noble/main' if scenario.get('wrong_repo') else scenario.get('codename','jammy')+'/main'
        done('500 https://ppa.launchpadcontent.net/ondrej/php/ubuntu '+suite+' amd64 Packages\n' if not scenario.get('missing_repo') else '')
    done(args[-1]+':\n  Candidate: '+scenario.get('candidate_version',version)+'\n')
if name=='apt-get':
    if '-s' in args:
        if scenario.get('remove'):done('Remv mysql-community-server-core [8.0.44]\n')
        if scenario.get('protected_change'):done('Inst nginx [1.20.0] (1.22.0 fixture)\n')
        done('Inst php8.5-fpm ('+version+' fixture)\n')
    if 'install' in args and scenario.get('lock_failure'):done('',100)
    if 'install' in args:(root/'apt-done').touch()
    if 'install' in args and scenario.get('change_source_during_apt'):
        with (config/'php/7.4/fpm/php-fpm.conf').open('a') as f:f.write('include=/unreviewed/pools/*.conf\n')
    if 'install' in args and scenario.get('change_nginx_during_apt'):
        with (config/'nginx/sites-available/site.conf').open('a') as f:f.write('# concurrent Nginx edit\n')
    done('')
if name=='add-apt-repository':
    scenario['missing_repo']=False;(root/'scenario.json').write_text(json.dumps(scenario));done('')
if name=='timeout':
    assert args[1] in ('apt-get','add-apt-repository')
    os.execv(str(root/'bin'/args[1]),args[1:])
if name=='systemctl':
    if args[:2]==['reload-or-restart','nginx'] and scenario.get('terminate_cutover'):
        import signal
        os.kill(os.getppid(),signal.SIGTERM)
    state=root/'service-state.json'
    data=json.loads(state.read_text()) if state.exists() else {'apt-daily.timer':True,'apt-daily-upgrade.timer':False,'php8.5-fpm':True,'nginx':True}
    if args[0]=='show':done('123')
    if args[0]=='is-active':done('',0 if data.get(args[-1],False) else 3)
    if args[0] in ('start','stop','restart','reload-or-restart'):
        for service in args[1:]:data[service]=args[0]!='stop'
        state.write_text(json.dumps(data))
    done('')
if name=='update-alternatives':
    if '--query' in args:done('Name: php\nStatus: auto\nValue: '+str(root/'bin/php8.5')+'\nBest: '+str(root/('bin/php' if scenario.get('auto_best_changed') else 'bin/php8.5'))+'\n')
    done('')
if name in ('php','php8.5'):
    if '-m' in args:done('curl' if not scenario.get('runtime_missing_module') else '')
    done('CLI PHP 8.5.12')
if name=='php-fpm8.5':
    if '-m' in args:done('curl\nmysqli' if not scenario.get('runtime_missing_module') else '')
    if '-t' in args and scenario.get('deprecation'):print('PHP Deprecated: fixture warning',file=sys.stderr)
    if '-t' in args and scenario.get('bad_fpm'):done('',1)
    done('PHP '+scenario.get('runtime_version','8.5.12')+' (fpm-fcgi)' if '-v' in args else '')
if name=='curl':
    count=root/'curl-count'
    n=int(count.read_text())+1 if count.exists() else 1;count.write_text(str(n))
    if scenario.get('concurrent_edit') and n>1:
        site=config/'nginx/sites-available/site.conf'
        site.write_text(site.read_text()+'# external edit\n')
    if scenario.get('concurrent_target_edit') and n>1:
        target=config/'php/8.5/fpm/pool.d/www.conf'
        target.write_text(target.read_text()+'; external target edit\n')
    done('503' if scenario.get('bad_health') else '200')
if name=='chown':done('')
raise SystemExit('Unexpected fixture command '+name+' '+repr(args))
'''


class BashFixtures(unittest.TestCase):
    def exercise(self,scenario=None,args=None,cut=None):
        scenario=scenario or {};args=['--apply'] if args is None else args
        with tempfile.TemporaryDirectory(prefix='php85-bash-') as temporary:
            root=Path(temporary);config=root/'etc';run=root/'run';home=root/'home';bin=root/'bin'
            for path in (config,run,home,bin):path.mkdir()
            (config/'os-release').write_text('ID=ubuntu\nVERSION_ID="'+scenario.get('release','22.04')+'"\nVERSION_CODENAME='+scenario.get('codename','jammy')+'\n')
            proxy=bin/'proxy';proxy.write_text(PROXY);proxy.chmod(0o755)
            for name in ('dpkg','dpkg-query','hostname','nginx','apt-cache','apt-get','add-apt-repository','timeout',
                'systemctl','update-alternatives','php','php8.5','php-fpm8.5','curl','chown'):(bin/name).symlink_to('proxy')
            proc=root/'proc';(proc/'123').mkdir(parents=True);(proc/'123/exe').symlink_to(bin/'php-fpm8.5')
            (root/'scenario.json').write_text(json.dumps(scenario))
            if scenario.get('interrupted_checkpoint'):(home/'php85-active-run').write_text('/root/previous-backup\n')
            site=config/'nginx/sites-available/site.conf';site.parent.mkdir(parents=True)
            branch='8.5' if scenario.get('web85') else '7.4'
            text=('server {\n listen 443 ssl;\n server_name example.com www.example.com;\n include forge-conf/site/before/*;\n'
                ' location ~ \\.php$ {\n  include fastcgi_params;\n  fastcgi_pass unix:/run/php/php'+branch+'-fpm.sock;\n }\n}\n')
            if scenario.get('multipool'):text=text.replace(' }\n}\n',' }\n location /customer {\n  fastcgi_pass unix:/run/php/customer.sock; # customer\n }\n}\n')
            if scenario.get('inline_route'):text=text.replace(' }\n}\n',' }\n location /other { fastcgi_pass unix:/run/php/other.sock; }\n}\n')
            if scenario.get('shared_sites'):
                (config/'nginx/php-shared.conf').write_text('fastcgi_pass unix:/run/php/php'+branch+'-fpm.sock;\n')
                text=('server {\n listen 80;\n server_name first.example.com;\n include php-shared.conf;\n}\n'
                      'server {\n listen 127.0.0.1:8443 ssl;\n server_name second.example.com;\n include php-shared.conf;\n}\n')
            site.write_text(text);site.chmod(0o640)
            if scenario.get('no_hostname'):site.write_text(text.replace('server_name example.com www.example.com;','server_name _;'))
            enabled=config/'nginx/sites-enabled/site.conf';enabled.parent.mkdir();enabled.symlink_to('../sites-available/site.conf')
            source_pool='[www]\nuser=forge\ngroup=forge\nlisten=/run/php/php7.4-fpm.sock\npm.max_children=8\nenv[FIXTURE_TOKEN]=fixture-private\n'
            stock='[www]\nuser=www-data\ngroup=www-data\nlisten=/run/php/php8.5-fpm.sock\n'
            ready='[www]\nuser=forge\ngroup=forge\nlisten=/run/php/php8.5-fpm.sock\npm.max_children=99\n'
            for phpbranch,pool in (('7.4',source_pool),('8.5',ready if scenario.get('custom_target') else stock)):
                if scenario.get('bad_source') and phpbranch=='7.4':pool=pool.replace('php7.4-fpm.sock','other.sock')
                p=config/('php/'+phpbranch+'/fpm/pool.d/www.conf');p.parent.mkdir(parents=True);p.write_text(pool);p.chmod(0o640)
                for sapi in ('cli','fpm'):
                    folder=config/('php/'+phpbranch+'/'+sapi);(folder/'conf.d').mkdir(parents=True,exist_ok=True)
                    (folder/'php.ini').write_text('memory_limit=512M\nsession.sid_length=26\n'+(scenario.get('custom_ini','') if phpbranch=='7.4' else ''))
            import hashlib
            target_payload=root/'usr/lib/php/8.5/php.ini-production';target_payload.parent.mkdir(parents=True)
            target_payload.write_text('memory_limit=512M\nsession.sid_length=26\n')
            target_manifest=root/'var/lib/dpkg/info/php8.5-common.md5sums';target_manifest.parent.mkdir(parents=True,exist_ok=True)
            target_manifest.write_text(hashlib.md5(target_payload.read_bytes()).hexdigest()+'  '+str(target_payload.relative_to(root))+'\n')
            if scenario.get('custom_target_ini'):
                (config/'php/8.5/fpm/conf.d/99-zzz.ini').write_text('extension=custom.so\n')
            if scenario.get('pool_override'):
                with (config/'php/7.4/fpm/pool.d/www.conf').open('a') as f:f.write(scenario['pool_override'])
            if scenario.get('module_states'):
                import hashlib
                manifest=root/'var/lib/dpkg/info/php7.4-common.md5sums';manifest.parent.mkdir(parents=True,exist_ok=True)
                production=root/'usr/lib/php/7.4/php.ini-production';production.parent.mkdir(parents=True)
                production.write_text('precision=14\n')
                entries=[hashlib.md5(production.read_bytes()).hexdigest()+'  '+str(production.relative_to(root))+'\n']
                for module in ('curl','mysqli'):
                    payload=root/('usr/share/php7.4-'+module+'/'+module+'.ini');payload.parent.mkdir(parents=True)
                    payload.write_text('extension='+module+'.so\n')
                    entries.append(hashlib.md5(payload.read_bytes()).hexdigest()+'  '+str(payload.relative_to(root))+'\n')
                    target_module=root/('usr/share/php8.5-'+module+'/'+module+'.ini');target_module.parent.mkdir(parents=True)
                    target_module.write_bytes(payload.read_bytes())
                    with target_manifest.open('a') as f:f.write(hashlib.md5(target_module.read_bytes()).hexdigest()+'  '+str(target_module.relative_to(root))+'\n')
                    for branch in ('7.4','8.5'):
                        available=config/('php/'+branch+'/mods-available');available.mkdir(exist_ok=True)
                        (available/(module+'.ini')).write_bytes(payload.read_bytes())
                        for sapi in ('cli','fpm'):
                            if branch=='7.4' and sapi=='cli' and module=='mysqli':continue
                            if branch=='8.5' and (scenario.get('missing_target_module') or scenario.get('disabled_target_custom_module')) and module=='curl':continue
                            (config/('php/'+branch+'/'+sapi+'/conf.d/20-'+module+'.ini')).symlink_to('../../mods-available/'+module+'.ini')
                    if scenario.get('missing_target_module') and module=='curl':
                        (config/'php/8.5/mods-available/curl.ini').unlink()
                manifest.write_text(''.join(entries))
                if scenario.get('disabled_target_custom_module'):
                    (config/'php/8.5/mods-available/curl.ini').write_text('extension=/private/custom/curl.so\n')
            if scenario.get('multipool'):
                (config/'php/7.4/fpm/pool.d/extra.conf').write_text('[extra]\nuser=forge\ngroup=forge\nlisten=/run/php/customer.sock\n')
            (config/'php/7.4/fpm/php-fpm.conf').write_text('[global]\npid=/run/php/php7.4-fpm.pid\nprocess.max=99\ninclude='+str(config/'php/7.4/fpm/pool.d/*.conf')+'\n')
            if scenario.get('extra_pool'):(config/'php/8.5/fpm/pool.d/extra.conf').write_text('[extra]\nlisten=/run/php/extra.sock\n')
            template=root/'usr/share/php8.5-fpm/pool.d/www.conf';template.parent.mkdir(parents=True);template.write_text(stock)
            old=home/'old-checkpoint.json';old.write_bytes(b'old failed evidence\n')
            (run/'php').mkdir();sockets=[]
            mock_socket=os.environ.get('PHP85_TEST_MOCK_SOCKET')=='1'
            if mock_socket:
                (run/'php/php8.5-fpm.sock').touch()
                if scenario.get('multipool'):(run/'php/customer.php85.sock').touch()
            else:
                names=['php8.5-fpm.sock']+(['customer.php85.sock'] if scenario.get('multipool') else [])
                for name in names:
                    sock=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
                    sockets.append(sock);sock.bind(str(run/'php'/name))
            original=SOURCE.read_text();script=original
            if mock_socket:script=script.replace('[[ -S $run_root/${next#/run/} ]]','[[ -f $run_root/${next#/run/} ]]')
            replacements={'config_root=/etc':'config_root='+str(config),'run_root=/run':'run_root='+str(run),
                'proc_root=/proc':'proc_root='+str(proc),
                'home_root=/root':'home_root='+str(home),'PATH=/usr/sbin:/usr/bin:/sbin:/bin':'PATH='+str(bin)+':/usr/bin:/bin',
                '[[ $EUID -eq 0 ]]':'[[ $EUID -ge 0 ]]'}
            for before,after in replacements.items():
                self.assertIn(before,script);script=script.replace(before,after,1)
            # Only the package-default template prefix is virtualized in this fixture copy.
            script=script.replace(r'^\/usr\/share\/',str(root/'usr/share').replace('/',r'\/')+r'\/')
            path=root/'entry.sh';raw=script.encode();path.write_bytes(raw if cut is None else raw[:cut])
            try:
                result=subprocess.run(['/bin/bash',str(path)]+args,cwd=root,env=dict(PATH='/usr/bin:/bin',HOME=str(home),LANG='C',LC_ALL='C'),
                    stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
                if scenario.get('rerun') and result.returncode==0 and cut is None:
                    result=subprocess.run(['/bin/bash',str(path)]+args,cwd=root,env=dict(PATH='/usr/bin:/bin',HOME=str(home),LANG='C',LC_ALL='C'),
                        stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
            finally:
                for sock in sockets:sock.close()
            calls=[json.loads(line) for line in (root/'commands.jsonl').read_text().splitlines()] if (root/'commands.jsonl').exists() else []
            backups=list(home.glob('php85-backup.*'))
            saved=(backups[0]/str(site).lstrip('/')).read_bytes() if backups and (backups[0]/str(site).lstrip('/')).exists() else None
            target=config/'php/8.5/fpm/pool.d/www.conf'
            overlays={sapi:[p.read_text() for p in (config/('php/8.5/'+sapi+'/conf.d')).glob('99-legacy-*')] for sapi in ('cli','fpm')}
            return dict(rc=result.returncode,stdout=result.stdout.decode(),stderr=result.stderr.decode(),calls=calls,
                shared=(config/'nginx/php-shared.conf').read_text() if (config/'nginx/php-shared.conf').exists() else '',checkpoint=(home/'php85-active-run').exists(),site=site.read_text(),original=text,symlink=enabled.is_symlink(),backup=saved,backup_count=len(backups),
                global_config=(config/'php/8.5/fpm/php-fpm.conf').read_text() if (config/'php/8.5/fpm/php-fpm.conf').exists() else '',extra_target=(config/'php/8.5/fpm/pool.d/extra.conf').read_text() if (config/'php/8.5/fpm/pool.d/extra.conf').exists() else '',module_links={sapi:sorted(p.name for p in (config/('php/8.5/'+sapi+'/conf.d')).glob('*.ini') if p.is_symlink()) for sapi in ('cli','fpm')},target=target.read_text(),target_mode=target.stat().st_mode&0o777,ready=ready,overlays=overlays,old=old.read_bytes())

    def test_source_configuration_drift_during_apt_blocks_before_migration(self):
        r=self.exercise({'change_source_during_apt':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('Source PHP configuration changed after discovery',r['stderr'])
        self.assertEqual(r['site'],r['original'])
        self.assertNotIn('pm.max_children=8',r['target'])
        self.assertFalse(any(c[:2]==['systemctl','restart'] for c in r['calls']))

    def test_nginx_configuration_drift_during_apt_is_preserved(self):
        r=self.exercise({'change_nginx_during_apt':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('Nginx configuration changed after discovery',r['stderr'])
        self.assertEqual(r['site'],r['original']+'# concurrent Nginx edit\n')
        self.assertNotIn('pm.max_children=8',r['target'])
        self.assertFalse(any(c[:2]==['systemctl','restart'] for c in r['calls']))

    def test_failed_nginx_dump_is_rejected_even_when_output_is_unchanged(self):
        r=self.exercise({'nginx_check_fail':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('Nginx configuration verification failed after discovery',r['stderr'])
        self.assertEqual(r['site'],r['original'])
        self.assertNotIn('pm.max_children=8',r['target'])
        self.assertFalse(any(c[:2]==['systemctl','restart'] for c in r['calls']))

    def test_exact_target_is_pinned(self):
        r=self.exercise({'candidate_version':'8.5.13-1+ubuntu22.04.1+deb.sury.org+1'});self.assertEqual(r['rc'],0,r['stderr'])
        install=[c for c in r['calls'] if c[0]=='apt-get' and 'install' in c and '-s' not in c][-1]
        self.assertIn('php8.5-fpm=8.5.12-1+ubuntu22.04.1+deb.sury.org+1',install)

    def test_unavailable_exact_target_stops_before_install(self):
        r=self.exercise({'missing_exact':True});self.assertNotEqual(r['rc'],0)
        self.assertIn('Exact PHP 8.5.12 unavailable',r['stderr'])
        self.assertFalse(any(c[0]=='apt-get' and 'install' in c for c in r['calls']))
        self.assertEqual(r['site'],r['original'])

    def test_newer_FPM_runtime_is_not_success(self):
        r=self.exercise({'runtime_version':'8.5.13'});self.assertNotEqual(r['rc'],0)
        self.assertIn('not exactly PHP 8.5.12',r['stderr'])
        self.assertEqual(r['site'],r['original'])

    def test_generic_sites_do_not_require_WordPress_login(self):
        r=self.exercise();self.assertEqual(r['rc'],0,r['stderr'])
        probes=[c[-1] for c in r['calls'] if c[0]=='curl']
        self.assertTrue(probes)
        self.assertEqual(set(probes),{'https://example.com:443/'})

    def test_shared_snippet_probes_each_server_listener(self):
        r=self.exercise({'shared_sites':True})
        self.assertEqual(r['rc'],0,r)
        probes=[c for c in r['calls'] if c[0]=='curl']
        self.assertIn('php8.5-fpm.sock',r['shared'])
        self.assertNotIn('php7.4-fpm.sock',r['shared'])
        self.assertEqual({c[-1] for c in probes},{'http://first.example.com:80/','https://second.example.com:8443/'})
        self.assertEqual({c[c.index('--resolve')+1] for c in probes},{'first.example.com:80:127.0.0.1','second.example.com:8443:127.0.0.1'})

    def test_default_plan_is_read_only(self):
        r=self.exercise(args=[]);self.assertEqual(r['rc'],0,r['stderr'])
        self.assertEqual(r['site'],r['original']);self.assertEqual(r['backup_count'],0)
        self.assertFalse(any(c[0] in ('apt-get','add-apt-repository','systemctl','update-alternatives') for c in r['calls']))

    def test_custom_target_pool_is_not_silently_reused(self):
        r=self.exercise({'custom_target':True});self.assertNotEqual(r['rc'],0)
        self.assertIn('Existing customized PHP 8.5 pool',r['stderr'])
        self.assertEqual(r['site'],r['original'])
        self.assertFalse(any(c[0]=='apt-get' for c in r['calls']))

    def test_stock_pool_copies_source_settings_permissions_without_old_loaders(self):
        r=self.exercise({'stock':True});self.assertEqual(r['rc'],0,r['stderr'])
        self.assertIn('pm.max_children=8',r['target']);self.assertIn('listen=/run/php/php8.5-fpm.sock',r['target'])
        self.assertEqual(r['target_mode'],0o640)
        for files in r['overlays'].values():
            self.assertTrue(files);self.assertIn('memory_limit=512M',files[0]);self.assertNotIn('extension=',files[0]);self.assertNotIn('session.sid_length',files[0])

    def test_source_removed_configuration_does_not_require_old_PHP_binary(self):
        r=self.exercise({'source_rc':True});self.assertEqual(r['rc'],0,r['stderr'])
        self.assertFalse(any(c[0]=='php7.4' for c in r['calls']));self.assertIn('php8.5-fpm.sock',r['site'])

    def test_Ubuntu24_uses_matching_Noble_packages_without_an_OS_upgrade(self):
        r=self.exercise({'release':'24.04','codename':'noble'});self.assertEqual(r['rc'],0,r['stderr'])
        installs=[c for c in r['calls'] if c[0]=='apt-get' and 'install' in c and '-s' not in c]
        self.assertTrue(installs);self.assertTrue(any('ubuntu24.04.' in word for word in installs[-1]))

    def test_status_has_no_repository_package_or_service_mutation(self):
        r=self.exercise(args=['--status']);self.assertEqual(r['rc'],0,r['stderr'])
        self.assertEqual(r['backup_count'],0);self.assertEqual(r['site'],r['original'])
        self.assertFalse(any(c[0] in ('apt-get','add-apt-repository','update-alternatives') for c in r['calls']))
        self.assertFalse(any(c[0]=='systemctl' and c[1] in ('start','stop','restart','enable','reload-or-restart') for c in r['calls']))

    def test_missing_repository_uses_native_add_command_before_update(self):
        r=self.exercise({'missing_repo':True});self.assertEqual(r['rc'],0,r['stderr'])
        add=next(i for i,c in enumerate(r['calls']) if c[0]=='add-apt-repository')
        update=next(i for i,c in enumerate(r['calls']) if c[0]=='apt-get' and 'update' in c)
        self.assertLess(add,update)

    def test_wrong_release_repository_and_protected_changes_stop_before_install(self):
        for scenario in ({'wrong_repo':True},{'remove':True},{'protected_change':True}):
            with self.subTest(scenario=scenario):
                r=self.exercise(scenario);self.assertNotEqual(r['rc'],0)
                self.assertFalse(any(c[0]=='apt-get' and 'install' in c and '-s' not in c for c in r['calls']))
                self.assertEqual(r['site'],r['original'])

    def test_APT_lock_exit_never_kills_owner_or_switches_routes(self):
        r=self.exercise({'lock_failure':True});self.assertNotEqual(r['rc'],0)
        self.assertEqual(r['site'],r['original']);self.assertFalse(any(c[0] in ('kill','pkill','killall') for c in r['calls']))
        self.assertTrue(any(c[:2]==['systemctl','start'] and 'apt-daily.timer' in c for c in r['calls']))

    def test_deprecation_stderr_is_accepted_but_failed_native_config_is_not(self):
        r=self.exercise({'deprecation':True});self.assertEqual(r['rc'],0,r['stderr'])
        r=self.exercise({'bad_fpm':True});self.assertNotEqual(r['rc'],0);self.assertEqual(r['site'],r['original'])

    def test_unsupported_source_pool_target_extra_pool_or_missing_host_holds_before_APT(self):
        for scenario in ({'bad_source':True},{'extra_pool':True},{'no_hostname':True}):
            with self.subTest(scenario=scenario):
                r=self.exercise(scenario);self.assertNotEqual(r['rc'],0)
                self.assertFalse(any(c[0]=='apt-get' for c in r['calls']))
                self.assertEqual(r['site'],r['original'] if not scenario.get('no_hostname') else r['original'].replace('server_name example.com www.example.com;','server_name _;'))

    def test_already85_web_and_bad_final_health_are_reported_truthfully(self):
        r=self.exercise({'web85':True});self.assertEqual(r['rc'],0,r['stderr']);self.assertEqual(r['site'],r['original'])
        r=self.exercise({'bad_health':True});self.assertNotEqual(r['rc'],0);self.assertNotIn('COMPLETE',r['stdout'])

    def test_failed_health_restores_routes_and_cli_without_package_rollback(self):
        r=self.exercise({'bad_health':True,'stock':True})
        self.assertNotEqual(r['rc'],0)
        self.assertEqual(r['site'],r['original'])
        self.assertFalse(r['checkpoint'])
        self.assertIn('packages were NOT rolled back',r['stderr'])
        self.assertTrue(any(c[:3]==['systemctl','reload','nginx'] for c in r['calls']))
        self.assertTrue(any(c[:3]==['update-alternatives','--set','php'] for c in r['calls']))
        self.assertFalse(any(c[0]=='apt-get' and ('remove' in c or 'purge' in c) for c in r['calls']))

    def test_termination_at_cutover_rolls_back_and_exits_nonzero(self):
        r=self.exercise({'terminate_cutover':True,'stock':True})
        self.assertEqual(r['rc'],143)
        self.assertEqual(r['site'],r['original'])
        self.assertFalse(r['checkpoint'])
        self.assertNotIn('COMPLETE',r['stdout'])

    def test_concurrent_target_edit_is_not_overwritten_during_rollback(self):
        r=self.exercise({'concurrent_target_edit':True,'bad_health':True,'stock':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('; external target edit',r['target'])
        self.assertTrue(r['checkpoint'])
        self.assertEqual(r['site'],r['original'])

    def test_interrupted_run_blocks_apply_before_package_mutation(self):
        r=self.exercise({'interrupted_checkpoint':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('interrupted/failed rollback',r['stderr'])
        self.assertEqual(r['backup_count'],0)
        self.assertFalse(any(c[0]=='apt-get' for c in r['calls']))

    def test_rollback_does_not_discard_concurrent_route_edit(self):
        r=self.exercise({'bad_health':True,'concurrent_edit':True})
        self.assertNotEqual(r['rc'],0)
        self.assertIn('# external edit',r['site'])
        self.assertTrue(r['checkpoint'])
        self.assertIn('ROLLBACK BLOCKED',r['stderr'])

    def test_incomplete_final_invocation_never_runs_package_or_service_commands(self):
        source=SOURCE.read_bytes();self.assertFalse(source.endswith(b'\n'))
        # A prefix missing the full last sentinel cannot enter the operational body.
        length=len(source)-source.rfind(b'\nphp85_main ')-1
        for tail in range(1,length+1):
            r=self.exercise(cut=-tail);self.assertEqual(r['calls'],[]);self.assertNotIn('COMPLETE',r['stdout'])


if __name__=='__main__':unittest.main()
