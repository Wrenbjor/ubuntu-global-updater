"""Build a complete self-contained Bash entry point; no updater execution."""
import argparse
import base64
import gzip
import hashlib
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def render(core, helper):
    compile(core, 'php85_upgrade.py', 'exec')
    compile(helper, 'php85_config.py', 'exec')
    # Keep readable modules separate in Git; embed both in the one downloaded file.
    assert core.decode().count("VERSION = '2.0.0'") == 1
    source = core.decode().replace("VERSION = '2.0.0'", "VERSION = '2.0.0'\nCONFIG_SOURCE = " + repr(helper.decode()), 1).encode()
    packed = gzip.compress(source, mtime=0)
    blob = base64.b64encode(packed).decode()
    program = '''import base64,gzip,hashlib,io,os,re,subprocess,sys,tempfile
blob=__BLOB__
expected=__SHA__
size=__SIZE__
args=sys.argv[1:]
allowed=([],['--plan-only'],['--apply'],['--status'],['--rollback'],['--apply','--adopt-vendor-socket'],['--plan-only','--adopt-vendor-socket'])
explicit_rollback=(len(args)==3 and args[:2]==['--rollback','--run'] and re.fullmatch(r'(?:/var/lib/php85-updater/)?run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}',args[2]))
if args not in allowed and not explicit_rollback: raise SystemExit('Unsupported PHP updater options')
if os.geteuid()!=0: raise SystemExit('Run as root (or pipe to sudo bash)')
if sys.version_info<(3,10): raise SystemExit('Ubuntu 22.04 Python 3.10 or newer required')
with gzip.GzipFile(fileobj=io.BytesIO(base64.b64decode(blob,validate=True))) as packed:
    code=packed.read(size+1)
if len(code)!=size or hashlib.sha256(code).hexdigest()!=expected: raise SystemExit('Incomplete or modified installer payload')
compile(code,'php85_upgrade.py','exec')
with tempfile.TemporaryDirectory(prefix='php85-bootstrap-',dir='/run') as folder:
    os.chmod(folder,0o700)
    path=os.path.join(folder,'php85_upgrade.py')
    with open(path,'wb') as out:
        os.fchmod(out.fileno(),0o600);out.write(code)
    env=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/root',LANG='C',LC_ALL='C')
    result=subprocess.run(['/usr/bin/python3','-I','-B',path]+args,stdin=subprocess.DEVNULL,env=env)
    raise SystemExit(result.returncode)
'''.replace('__BLOB__',repr(blob)).replace('__SHA__',repr(sha(source))).replace('__SIZE__',str(len(source)))
    sentinel = 'PHP85-COMPLETE-' + sha(source)
    shell = '''#!/bin/bash
# PHP 8.5 updater v2.0.0. No actions until the complete final function call.
php85_main() (
set -euo pipefail
[[ "$#" -ge 1 && "${!#}" == '__SENTINEL__' ]] || { echo 'Incomplete PHP85 bootstrap' >&2; exit 1; }
set -- "${@:1:$#-1}"
for unsafe in LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV APT_CONFIG PYTHONPATH PYTHONHOME; do
    [[ ! -v "$unsafe" ]] || { echo "Remove unsafe environment variable: $unsafe" >&2; exit 1; }
done
/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C /usr/bin/python3 -I -B - "$@" <<'PHP85_PAYLOAD'
__PROGRAM__PHP85_PAYLOAD
)
php85_main "$@" '__SENTINEL__' '''
    return shell.replace('__PROGRAM__', program).replace('__SENTINEL__', sentinel).rstrip().encode()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    shell = render((ROOT / 'php85_upgrade.py').read_bytes(), (ROOT / 'php85_config.py').read_bytes())
    if args.check:
        assert (ROOT / 'php85.sh').read_bytes() == shell, 'Installer differs from readable sources'
    else:
        (ROOT / 'php85.sh').write_bytes(shell)
    subprocess.run(['bash','-n',str(ROOT / 'php85.sh')],check=True)
    assert render((ROOT / 'php85_upgrade.py').read_bytes(), (ROOT / 'php85_config.py').read_bytes()) == shell
    print('Installer SHA256:', sha(shell))


if __name__ == '__main__':
    main()
