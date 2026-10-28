"""Offline release verification; never execute installer/package/service actions."""
import ast,base64,gzip,hashlib,json,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parent
release=json.loads((root/'release.json').read_text())
modern={'ubuntu_global_runtime.py','php_legacy_packages.py','php_legacy_routing.py','php_legacy_runner.py'}
for name,expected in release['source_sha256'].items():
 assert hashlib.sha256((root/name).read_bytes()).hexdigest()==expected,name
 if name.endswith('.py') and (sys.version_info>=(3,9) or name not in modern):compile((root/name).read_bytes(),name,'exec')
script=(root/'install.sh').read_text()
body=script.split("<<'UBUNTU_UPDATER_INSTALL'\n",1)[1].rsplit('UBUNTU_UPDATER_INSTALL',1)[0]
tree=ast.parse(body);values={}
for item in tree.body:
 if isinstance(item,ast.Assign) and isinstance(item.targets[0],ast.Name) and item.targets[0].id in ('BLOB','EXPECTED','NAMES'):
  values[item.targets[0].id]=ast.literal_eval(item.value)
raw=gzip.decompress(base64.b64decode(values['BLOB']))
assert hashlib.sha256(raw).hexdigest()==values['EXPECTED']
files=json.loads(raw);assert set(files)==set(values['NAMES'])
assert len(files)==15
for name,data in files.items():assert base64.b64decode(data)==(root/name).read_bytes(),name
subprocess.run(['/bin/bash','-n',str(root/'install.sh')],check=True)
assert "str(wrapper),'--apply'" in script
core=(root/'ubuntu_global.py').read_text()
assert "need(identity()['release'] == '24.04', 'PHP_stage_requires_verified_Ubuntu_24_04')" in core
assert 'no_automatic_retry_after_failure' in core
helper=script.split('# BEGIN_REVIEWED_PRELAUNCH_INSTALLER\n',1)[1].split('# END_REVIEWED_PRELAUNCH_INSTALLER',1)[0]
assert helper.encode()==(root/'prelaunch_installer.py').read_bytes()
print('Generic updater release checks passed; no installer or production actions executed.')

assert 'def droplet_id(' not in core and '169.254.169.254' not in core
assert 'host_binding=binding' in core and 'schema=2' in core
