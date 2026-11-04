import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from test_php85_upgrade import M,VERSION


class PackageGuardFixtures(unittest.TestCase):
    def test_stock_target_pool_requires_unchanged_native_template_or_conffile_proof(self):
        for layout in ('template','conffile'):
            for modified in (False,True):
                with self.subTest(layout=layout,modified=modified),tempfile.TemporaryDirectory(prefix='php85-simple-stock-') as temporary:
                    root=Path(temporary);native=Path;raw=b'[www]\nuser=www-data\ngroup=www-data\nlisten=/run/php/php8.5-fpm.sock\n'
                    target=root/'etc/php/8.5/fpm/pool.d/www.conf';target.parent.mkdir(parents=True);target.write_bytes(raw+(b'; modified\n' if modified else b''))
                    logical='/usr/share/php8.5-fpm/pool.d/www.conf';template=root/logical.lstrip('/');template.parent.mkdir(parents=True);template.write_bytes(raw)
                    inventory=root/'var/lib/dpkg/info/php8.5-fpm.md5sums';inventory.parent.mkdir(parents=True)
                    md5=M.hashlib.md5(raw,usedforsecurity=False).hexdigest()
                    inventory.write_text(md5+'  '+logical.lstrip('/')+'\n' if layout=='template' else '')
                    def paths(path):
                        path=str(path)
                        return root/path.lstrip('/') if path.startswith(('/etc/php/','/usr/share/','/var/lib/dpkg/info/')) else native(path)
                    def command(args,**kwargs):
                        if args[:2]==['/usr/bin/dpkg-query','-L']:return logical if layout=='template' else str(target)
                        self.assertEqual(args,['/usr/bin/dpkg-query','-W','-f=${Conffiles}','php8.5-fpm'])
                        return ' '+str(target)+' '+md5+'\n'
                    with patch.object(M,'Path',side_effect=paths),patch.object(M.CFG,'_read',side_effect=lambda *a:(target.read_bytes(),{})):
                        self.assertEqual(M.stock_target_pool(SimpleNamespace(run=command)),not modified)

    def guard(self,archives):
        expected={'php8.5-cli':VERSION,'libfixture':'1.0'}
        with tempfile.TemporaryDirectory(prefix='php85-simple-archive-') as temporary:
            path=Path(temporary)/'approved.json';path.write_text(json.dumps(expected))
            release=Path(temporary)/'os-release';release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
            files={};lines=[]
            for index,(package,version) in enumerate(archives):
                name='/fixture/archive-'+str(index)+'.deb';files[name]=(package,version);lines.append(name)
            def metadata(args,**kwargs):
                self.assertEqual(args[:2],['/usr/bin/dpkg-deb','-f']);self.assertEqual(kwargs['timeout'],10)
                self.assertIn(args[3],('Package','Version'))
                return files[args[2]][0 if args[3]=='Package' else 1].encode()
            native=Path
            with patch.object(M.subprocess,'check_output',side_effect=metadata),\
                 patch.object(M,'Path',side_effect=lambda p:release if str(p)=='/etc/os-release' else native(p)):
                M.apt_guard(str(path),io.StringIO('\n'.join(lines)+'\n'))

    def test_actual_archive_gate_accepts_exact_set_and_rejects_extra_DB_duplicate_or_version_drift(self):
        exact=[('php8.5-cli',VERSION),('libfixture','1.0')];self.guard(exact)
        for archives in (exact+[('mysql-community-server-core','9.0')],exact+[('libother','1')],
            exact+[('php8.5-cli',VERSION)],[('php8.5-cli','8.5.12'),('libfixture','1.0')],exact[:1]):
            with self.subTest(archives=archives):
                with self.assertRaises(M.Stop):self.guard(archives)

    def test_candidate_origin_must_belong_to_candidate_version_block(self):
        raw=('Candidate: '+VERSION+'\nVersion table:\n '+VERSION+' 500\n'
            '  500 https://foreign.example/ubuntu jammy/main amd64 Packages\n'
            ' 8.5.12-1+ubuntu22.04.1+deb.sury.org+1 500\n'
            '  500 https://ppa.launchpadcontent.net/ondrej/php/ubuntu jammy/main amd64 Packages\n')
        runner=SimpleNamespace(run=lambda *a,**k:raw)
        with self.assertRaises(M.Stop):M.candidates(runner,['php8.5-cli'])

    def test_native_plan_pins_installed_protected_packages_and_refuses_removals_or_downgrade(self):
        calls=[]
        def simulate(args,**kwargs):calls.append(args);return ''
        pins,changes,actions=M.install_plan(SimpleNamespace(run=simulate),{'php8.5-cli':VERSION},
            {'mysql-community-server-core':'8.0.44','php7.4-fpm':'7.4.33','nginx':'1.20.0'})
        for pin in ('mysql-community-server-core=8.0.44','php7.4-fpm=7.4.33','nginx=1.20.0'):self.assertIn(pin,pins)
        self.assertEqual(changes,[]);self.assertEqual(actions,{})
        with self.assertRaises(M.Stop):M.install_plan(SimpleNamespace(run=lambda *a,**k:'Remv redis-server [6.0.16]\n'),{'php8.5-cli':VERSION},{})
        def downgrade(args,**kwargs):return None if args[0]=='/usr/bin/dpkg' else 'Inst php8.5-cli [8.5.14] ('+VERSION+' fixture)\n'
        with self.assertRaises(M.Stop):M.install_plan(SimpleNamespace(run=downgrade),{'php8.5-cli':VERSION},{'php8.5-cli':'8.5.14'})


class NativeTargetFixtures(unittest.TestCase):
    def exercise(self,mutation=None):
        import stat,struct
        native=Path;connections=[]
        class FakePath:
            def __init__(self,path):self.path=native(path)
            def __str__(self):return str(self.path)
            def __truediv__(self,name):return FakePath(self.path/name)
            @property
            def parent(self):return FakePath(self.path.parent)
            def stat(self):
                if str(self).endswith('.sock'):return SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_dev=1,st_ino=88)
                if str(self).startswith('/usr/lib/php/'):
                    return SimpleNamespace(st_mode=stat.S_IFREG|0o644,st_dev=M.os.makedev(8,1),st_ino=77,st_uid=0)
                return SimpleNamespace(st_mode=stat.S_IFREG|0o755,st_dev=1,st_ino=98 if mutation=='stale-exe' and str(self)=='/proc/123/exe' else 99)
            def read_text(self):
                selfpath='/usr/lib/php/'+('20190902' if mutation=='foreign-API' else '20250925')+'/mysqli.so'
                return '1000-2000 r-xp 00000000 08:01 77 '+selfpath+(' (deleted)' if mutation=='deleted-module' else '')+'\n'
        class Peer:
            def __enter__(self):return self
            def __exit__(self,*args):return None
            def settimeout(self,value):self.timeout=value
            def connect(self,address):connections.append(address)
            def getsockopt(self,*args):return struct.pack('3i',124 if mutation=='wrong-peer' else 123,33 if mutation=='wrong-uid' else 0,0)
        def command(args,**kwargs):
            if args==['/usr/sbin/php-fpm8.5','-t']:return ''
            if args==['/usr/sbin/php-fpm8.5','-v']:return 'PHP 8.5.13 (fpm-fcgi)'
            if args[:2]==['/bin/systemctl','is-active']:return 'active'
            self.assertIn('MainPID',args);return '123'
        with patch.object(M,'Path',FakePath),patch.object(M.os,'readlink',return_value='/usr/sbin/php-fpm8.5'),\
             patch.object(M.socket,'socket',return_value=Peer()):
            result=M.native_target(SimpleNamespace(run=command),'/run/php/php8.5-fpm.sock','/usr/lib/php/20250925')
        return result,connections

    def test_native_current_master_peer_and_API_proof_connects_without_application_payload(self):
        proof,connections=self.exercise();self.assertEqual(proof['master_pid'],123)
        self.assertEqual(connections,['/run/php/php8.5-fpm.sock'])

    def test_wrong_peer_stale_executable_foreign_API_and_deleted_module_hold(self):
        for mutation in ('wrong-peer','wrong-uid','stale-exe','foreign-API','deleted-module'):
            with self.subTest(mutation=mutation):
                with self.assertRaises(M.Stop):self.exercise(mutation)



if __name__=='__main__':unittest.main()
