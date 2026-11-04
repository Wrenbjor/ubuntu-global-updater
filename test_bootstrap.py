import ast
import base64
import gzip
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC=importlib.util.spec_from_file_location('simple_builder_tested',Path(__file__).with_name('build_php85_release.py'))
B=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(B)
ENV=dict(PATH='/usr/bin:/bin',HOME='/nonexistent',LANG='C',LC_ALL='C')


class BootstrapFixtures(unittest.TestCase):
    def fixture(self,root):
        marker=root/'ran.json'
        core=("VERSION = '2.0.0'\nimport os,sys,json\nfrom pathlib import Path\n"
            "assert CONFIG_SOURCE=='pass\\n'\n"
            "assert not any(k in os.environ for k in ('APT_CONFIG','PYTHONPATH','PYTHONHOME','LD_PRELOAD','LD_LIBRARY_PATH','BASH_ENV','ENV'))\n"
            "Path("+repr(str(marker))+").write_text(json.dumps(sys.argv[1:]))\n").encode()
        script=B.render(core,b'pass\n')
        script=script.replace(b'if os.geteuid()!=0:',('if os.geteuid()!='+str(os.geteuid())+':').encode())
        script=script.replace(b"dir='/run'",('dir='+repr(str(root))).encode())
        return script,marker

    def test_all_modes_forward_exactly_and_fixture_child_has_minimal_environment(self):
        with tempfile.TemporaryDirectory(prefix='php85-simple-bootstrap-') as temporary:
            root=Path(temporary);script,marker=self.fixture(root);path=root/'entry.sh';path.write_bytes(script)
            runid='run-20261104T010203Z-0123abcd'
            modes=([],['--plan-only'],['--apply'],['--status'],['--rollback'],
                ['--apply','--adopt-vendor-socket'],['--plan-only','--adopt-vendor-socket'],
                ['--rollback','--run',runid],['--rollback','--run','/var/lib/php85-updater/'+runid])
            for args in modes:
                result=subprocess.run(['/bin/bash',str(path)]+args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(json.loads(marker.read_text()),args);marker.unlink()
            for args in ([],['--apply']):
                result=subprocess.run(['/bin/bash','-s','--']+args,input=script,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr.decode());self.assertEqual(json.loads(marker.read_text()),args);marker.unlink()

    def test_every_final_call_prefix_and_corrupted_payload_never_execute_fixture(self):
        with tempfile.TemporaryDirectory(prefix='php85-simple-prefix-') as temporary:
            root=Path(temporary);script,marker=self.fixture(root);path=root/'entry.sh'
            cuts={0,1,script.index(b'blob='),script.index(b'PHP85_PAYLOAD\n)')}
            cuts.update(range(script.rfind(b'\nphp85_main ')+1,len(script)))
            for cut in sorted(cuts):
                path.write_bytes(script[:cut]);subprocess.run(['/bin/bash',str(path),'--apply'],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertFalse(marker.exists(),cut)
            path.write_bytes(script.replace(b'expected=',b'expected="wrong" # ',1))
            result=subprocess.run(['/bin/bash',str(path),'--apply'],env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists())

    def test_unknown_modes_and_unsafe_environment_hold_before_fixture_execution(self):
        with tempfile.TemporaryDirectory(prefix='php85-simple-env-') as temporary:
            root=Path(temporary);script,marker=self.fixture(root);path=root/'entry.sh';path.write_bytes(script)
            for args in (['--unknown'],['--adopt-vendor-socket'],['--status','--apply'],['--rollback','--run','../../etc/passwd']):
                result=subprocess.run(['/bin/bash',str(path)]+args,env=ENV,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists())
            for key in ('APT_CONFIG','PYTHONPATH','LD_LIBRARY_PATH'):
                result=subprocess.run(['/bin/bash',str(path),'--apply'],env=ENV|{key:str(root)},stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertNotEqual(result.returncode,0);self.assertFalse(marker.exists())

    def test_real_bundle_embeds_exact_helper_and_core_bytes_deterministically_without_execution(self):
        root=Path(__file__).parent;core=(root/'php85_upgrade.py').read_bytes();helper=(root/'php85_config.py').read_bytes()
        shell=B.render(core,helper);self.assertEqual(B.render(core,helper),shell);self.assertFalse(shell.endswith(b'\n'))
        program=shell.decode().split("<<'PHP85_PAYLOAD'\n",1)[1].split('\nPHP85_PAYLOAD\n',1)[0]
        values={node.targets[0].id:ast.literal_eval(node.value) for node in ast.parse(program).body
            if isinstance(node,ast.Assign) and isinstance(node.targets[0],ast.Name) and node.targets[0].id in ('blob','expected','size')}
        payload=gzip.decompress(base64.b64decode(values['blob'],validate=True))
        wanted=core.decode().replace("VERSION = '2.0.0'","VERSION = '2.0.0'\nCONFIG_SOURCE = "+repr(helper.decode()),1).encode()
        self.assertEqual(payload,wanted);self.assertEqual(B.sha(payload),values['expected']);self.assertEqual(len(payload),values['size'])
        subprocess.run(['/bin/bash','-n'],input=shell,env=ENV,check=True)


if __name__=='__main__':unittest.main()
