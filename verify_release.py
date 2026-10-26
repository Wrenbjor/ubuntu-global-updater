"""Offline release consistency checks; never execute the installer."""
import ast,base64,gzip,hashlib,json,subprocess
from pathlib import Path
root=Path(__file__).resolve().parent
release=json.loads((root/'release.json').read_text())
for name,expected in release['source_sha256'].items():
 assert hashlib.sha256((root/name).read_bytes()).hexdigest()==expected,name
 if name.endswith('.py'):compile((root/name).read_bytes(),name,'exec')
script=(root/'install.sh').read_text()
body=script.split("<<'UBUNTU_UPDATER_INSTALL'\n",1)[1].rsplit('UBUNTU_UPDATER_INSTALL',1)[0]
tree=ast.parse(body);values={}
for item in tree.body:
 if isinstance(item,ast.Assign) and isinstance(item.targets[0],ast.Name) and item.targets[0].id in ('BLOB','EXPECTED','NAMES'):
  values[item.targets[0].id]=ast.literal_eval(item.value)
raw=gzip.decompress(base64.b64decode(values['BLOB']))
assert hashlib.sha256(raw).hexdigest()==values['EXPECTED']
files=json.loads(raw)
assert set(files)==set(values['NAMES'])
for name,data in files.items():assert base64.b64decode(data)==(root/name).read_bytes(),name
subprocess.run(['/bin/bash','-n',str(root/'install.sh')],check=True)
assert "str(wrapper),'--apply'" in script
assert 'no_automatic_retry_after_failure' in (root/'ubuntu_global.py').read_text()
print('Release checks passed; no installer, package, service or production action executed.')
