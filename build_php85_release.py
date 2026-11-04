"""Build/test the single-file PHP85 bootstrap locally; never publish or run core."""
import argparse
import ast
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
RELEASE = ROOT if (ROOT / 'php85_upgrade.py').is_file() else ROOT / 'php85-release'
CORE = RELEASE / 'php85_upgrade.py'
SHELL = RELEASE / 'php85.sh'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def core_version(payload):
    versions = [ast.literal_eval(node.value) for node in ast.parse(payload).body
                if isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id == 'VERSION']
    assert len(versions) == 1 and isinstance(versions[0], str) and re.fullmatch(r'\d+\.\d+\.\d+', versions[0])
    return versions[0]


def render(payload):
    compile(payload, 'php85_upgrade.py', 'exec')
    compressed = gzip.compress(payload, mtime=0)
    blob = base64.b64encode(compressed).decode('ascii')
    sentinel = 'PHP85-COMPLETE-' + sha(payload)
    verifier = r'''import base64,gzip,hashlib,io,os,stat,subprocess,sys,tempfile
PAYLOAD_SHA=__PAYLOAD_SHA__
COMPRESSED_SHA=__COMPRESSED_SHA__
PAYLOAD_SIZE=__PAYLOAD_SIZE__
BLOB=__BLOB__
def require(value,code):
    if not value:raise RuntimeError(code)
def safe_directory(path,uid,private=False):
    info=os.lstat(path)
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==uid and not info.st_mode&0o022
            and os.path.realpath(path)==path,'unsafe_bootstrap_directory')
    if private:require(stat.S_IMODE(info.st_mode)==0o700,'bootstrap_directory_not_private')
def main():
    uid=int(sys.argv[1]);args=sys.argv[2:]
    require(uid==os.geteuid(),'bootstrap_effective_user_changed')
    require(sys.version_info>=(3,10),'system_Python_3_10_or_newer_required')
    require(args in ([],['--plan-only'],['--apply'],['--status'],['--rollback'],
                    ['--apply','--adopt-vendor-socket'],['--plan-only','--adopt-vendor-socket']),
            'unsupported_bootstrap_arguments')
    compressed=base64.b64decode(BLOB,validate=True)
    require(hashlib.sha256(compressed).hexdigest()==COMPRESSED_SHA,'compressed_payload_checksum_mismatch')
    with gzip.GzipFile(fileobj=io.BytesIO(compressed),mode='rb') as stream:
        payload=stream.read(PAYLOAD_SIZE+1)
    require(len(payload)==PAYLOAD_SIZE and hashlib.sha256(payload).hexdigest()==PAYLOAD_SHA,
            'complete_payload_checksum_mismatch')
    compile(payload,'php85_upgrade.py','exec')
    if '--apply' in args:
        parent=__APPLY_BASE__
        safe_directory(os.path.dirname(parent),uid)
        try:os.mkdir(parent,0o700)
        except FileExistsError:pass
        safe_directory(parent,uid,private=True)
    else:
        parent=__PLAN_PARENT__
        safe_directory(parent,uid)
    work=tempfile.mkdtemp(prefix='php85-bootstrap-',dir=parent)
    path=os.path.join(work,'php85_upgrade.py')
    try:
        safe_directory(work,uid,private=True)
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:
            stream.write(payload);stream.flush();os.fsync(stream.fileno())
        # No timeout or process-kill handler around an explicitly applied core.
        environment=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/root',LANG='C',LC_ALL='C')
        result=subprocess.run(['/usr/bin/python3','-I','-B',path]+args,stdin=subprocess.DEVNULL,env=environment)
        return result.returncode
    finally:
        if os.path.lexists(path):os.unlink(path)
        os.rmdir(work)
try:raise SystemExit(main())
except Exception as error:
    print('PHP85 bootstrap stopped: '+type(error).__name__+': '+str(error),file=sys.stderr)
    raise SystemExit(1)
'''
    for marker, value in (
        ('__PAYLOAD_SHA__', repr(sha(payload))), ('__COMPRESSED_SHA__', repr(sha(compressed))),
        ('__PAYLOAD_SIZE__', str(len(payload))), ('__BLOB__', repr(blob)),
        ('__APPLY_BASE__', repr('/var/lib/ubuntu-php85-upgrade')),
        ('__PLAN_PARENT__', repr('/run'))):
        verifier = verifier.replace(marker, value)
    shell = '''#!/bin/bash
# Generated single-file PHP-only updater. No options means plan-only.
# All executable bootstrap work is inside this function; completion token is last.
php85_bootstrap() (
    set -euo pipefail
    [[ "$#" -ge 1 ]] || { echo 'Incomplete PHP85 bootstrap' >&2; exit 1; }
    [[ "${!#}" == '__SENTINEL__' ]] || { echo 'Incomplete PHP85 bootstrap' >&2; exit 1; }
    set -- "${@:1:$#-1}"
    [[ "$EUID" -eq 0 ]] || { echo 'Run this updater with sudo or as root.' >&2; exit 1; }
    [[ "$#" -le 2 ]] || { echo 'Use --plan-only or --apply with optional --adopt-vendor-socket; --status or --rollback alone.' >&2; exit 1; }
    case "$*" in ''|--plan-only|--apply|--status|--rollback|'--apply --adopt-vendor-socket'|'--plan-only --adopt-vendor-socket') ;; *) echo 'Unsupported PHP85 option combination.' >&2; exit 1 ;; esac
    for php85_unsafe in LD_PRELOAD LD_LIBRARY_PATH BASH_ENV ENV APT_CONFIG PYTHONPATH PYTHONHOME; do
        [[ ! -v "$php85_unsafe" ]] || { echo "Remove unsafe environment variable: $php85_unsafe" >&2; exit 1; }
    done
    /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LANG=C LC_ALL=C /usr/bin/python3 -I -B - "$EUID" "$@" <<'PHP85_VERIFIED_BOOTSTRAP'
__VERIFIER__PHP85_VERIFIED_BOOTSTRAP
)
php85_bootstrap "$@" '__SENTINEL__' '''
    # Deliberately no final LF or trailing byte after the closing quote. Every
    # proper prefix lacks a complete last sentinel argument, or is syntax-invalid.
    shell = shell.replace('__SENTINEL__', sentinel).replace('__VERIFIER__', verifier).rstrip()
    assert shell.endswith("'") and not shell.endswith('\n')
    return shell.encode('utf-8')


def build():
    if not CORE.is_file():
        raise SystemExit('Missing core: ' + str(CORE))
    RELEASE.mkdir(parents=True, exist_ok=True)
    payload = CORE.read_bytes()
    raw = render(payload)
    SHELL.write_bytes(raw)
    subprocess.run(['/bin/bash', '-n', str(SHELL)], check=True)
    verify_artifact(raw, payload)
    result = dict(status='built-local-only', version=core_version(payload), core_sha256=sha(payload), shell_sha256=sha(raw),
                  bytes=len(raw), embedded_payload_verified=True, production_actions=0)
    print(json.dumps(result))
    return result


def verify_artifact(shell, expected):
    """Inspect actual emitted bytes without executing the embedded updater."""
    body = shell.decode().split("<<'PHP85_VERIFIED_BOOTSTRAP'\n", 1)[1].split('\nPHP85_VERIFIED_BOOTSTRAP\n', 1)[0]
    wanted = {'PAYLOAD_SHA', 'COMPRESSED_SHA', 'PAYLOAD_SIZE', 'BLOB'}
    values = {node.targets[0].id: ast.literal_eval(node.value) for node in ast.parse(body).body
              if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)
              and node.targets[0].id in wanted}
    assert set(values) == wanted
    compressed = base64.b64decode(values['BLOB'], validate=True)
    assert sha(compressed) == values['COMPRESSED_SHA']
    decoded = gzip.decompress(compressed)
    assert decoded == expected and len(decoded) == values['PAYLOAD_SIZE'] and sha(decoded) == values['PAYLOAD_SHA']
    assert shell.endswith(("'PHP85-COMPLETE-" + sha(expected) + "'").encode())
    assert not shell.endswith(b'\n')


def self_test():
    """Exercise the generated logic with a harmless fixture core, never real core."""
    for version in ('1.0.0', '1.0.1', '1.0.2', '1.0.3', '1.0.4', '1.0.5', '1.0.6',
                    '1.0.7', '1.0.8', '1.0.9', '1.0.10', '1.0.11', '1.0.12'):
        assert core_version(('VERSION = '+repr(version)+'\n').encode()) == version
    for invalid in (b'pass\n', b"VERSION = 'unknown'\n", b"VERSION='1.0.0'\nVERSION='1.0.1'\n"):
        try:
            core_version(invalid)
        except AssertionError:
            pass
        else:
            raise AssertionError('ambiguous version metadata accepted')
    with tempfile.TemporaryDirectory(prefix='php85-bootstrap-test-') as temporary:
        root = Path(temporary)
        marker = root / 'core-ran.json'
        fixture = ('import json,sys,os\nfrom pathlib import Path\n'
                   'assert os.environ.get("LC_ALL")=="C"\n'
                   'assert not any(k in os.environ for k in ("APT_CONFIG","PYTHONPATH","PYTHONHOME","LD_PRELOAD","LD_LIBRARY_PATH","BASH_ENV","ENV","CURL_HOME"))\nPath(' + repr(str(marker)) +
                   ').write_text(json.dumps(sys.argv[1:]))\n').encode()
        production = render(fixture)
        # Only fixture-owned paths and current UID replace the production root
        # admission/path constants. Payload hashes/truncation logic stay exact.
        script = production.replace(b'[[ "$EUID" -eq 0 ]]', b'[[ "$EUID" -eq "$EUID" ]]')
        script = script.replace(repr('/var/lib/ubuntu-php85-upgrade').encode(), repr(str(root / 'apply')).encode())
        script = script.replace(repr('/run').encode(), repr(str(root)).encode())
        path = root / 'bootstrap.sh'
        path.write_bytes(script)
        allowed_modes=([],['--plan-only'],['--apply'],['--status'],['--rollback'],
                       ['--apply','--adopt-vendor-socket'],['--plan-only','--adopt-vendor-socket'])
        for flags in allowed_modes:
            result = subprocess.run(['/bin/bash', str(path)] + flags, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert result.returncode == 0, result.stderr.decode()
            assert json.loads(marker.read_text()) == flags
            marker.unlink()
        for flags in ([], ['--apply'],['--apply','--adopt-vendor-socket'],['--plan-only','--adopt-vendor-socket']):
            result = subprocess.run(['/bin/bash', '-s', '--'] + flags, input=script,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert result.returncode == 0, result.stderr.decode()
            assert json.loads(marker.read_text()) == flags
            marker.unlink()
        assert not list(root.rglob('php85-bootstrap-*'))
        result = subprocess.run(['/bin/bash', str(path), '--unknown'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert result.returncode != 0 and not marker.exists()
        for flags in (['--adopt-vendor-socket'],['--adopt-vendor-socket','--apply'],
                      ['--status','--adopt-vendor-socket'],['--rollback','--adopt-vendor-socket'],
                      ['--apply','--apply'],['--adopt-vendor-socket','--adopt-vendor-socket']):
            result=subprocess.run(['/bin/bash',str(path)]+flags,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            assert result.returncode!=0 and not marker.exists(),flags
        for key in ('APT_CONFIG', 'PYTHONPATH', 'LD_LIBRARY_PATH'):
            environment=dict(os.environ);environment[key]=str(root)
            result=subprocess.run(['/bin/bash',str(path),'--apply'],env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            assert result.returncode!=0 and not marker.exists()
        # Prefixes at all structural boundaries plus every byte of the final
        # invocation prove no truncated download can execute fixture core.
        cuts = {0, 1, script.index(b'BLOB='), script.index(b'PHP85_VERIFIED_BOOTSTRAP\n)')}
        call = script.rfind(b'\nphp85_bootstrap') + 1
        cuts.update(range(call, len(script)))
        for index in sorted(cuts):
            path.write_bytes(script[:index])
            subprocess.run(['/bin/bash', str(path), '--apply'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            assert not marker.exists(), ('truncated core executed', index)
        corrupt = script.replace(b'COMPRESSED_SHA=', b'COMPRESSED_SHA="broken" # ', 1)
        path.write_bytes(corrupt)
        result = subprocess.run(['/bin/bash', str(path), '--apply'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert result.returncode != 0 and not marker.exists()
        assert not list(root.rglob('php85-bootstrap-*'))
        subprocess.run(['/bin/bash', '-n'], input=production, check=True)
    result = dict(status='bootstrap-fixtures-pass', modes=7, pipeline_modes=4, truncation_prefixes=len(cuts),
                          version_metadata_from_core_literal=True,
                          vendor_socket_opt_in_forwarded_explicit_modes=True,
                          unsafe_environment_rejected=True, minimal_core_environment=True,
                          invalid_option_rejected=True, corrupt_payload_rejected=True, real_core_executed=False,
                          package_actions=0, service_actions=0)
    print(json.dumps(result))
    return result


def packaging_review():
    built = build()
    tested = self_test()
    assert SHELL.read_bytes() == render(CORE.read_bytes()), 'nonreproducible_bootstrap'
    with tempfile.TemporaryDirectory(prefix='php85-root-layout-test-') as temporary:
        staged = Path(temporary)
        (staged / 'build_php85_release.py').write_bytes(Path(__file__).read_bytes())
        (staged / 'php85_upgrade.py').write_bytes(CORE.read_bytes())
        result = subprocess.run(['/usr/bin/python3', str(staged / 'build_php85_release.py')],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert result.returncode == 0, result.stderr.decode()
        assert (staged / 'php85.sh').read_bytes() == SHELL.read_bytes(), 'root_layout_rebuild_differs'
    receipt = dict(schema=1, version=core_version(CORE.read_bytes()), review_scope='local-bootstrap-packaging-only', status='PASS',
        artifact_sha256={name: sha((RELEASE / name).read_bytes()) for name in
                         ('php85_upgrade.py', 'php85.sh', 'README-php85.md')},
        builder_sha256=sha(Path(__file__).read_bytes()), bootstrap= built, fixtures=tested,
        checks=dict(bash_syntax=True, emitted_payload_byte_equality=True,
                    compressed_and_payload_SHA256=True, deterministic_rebuild=True,
                    final_completion_token=True, root_layout_rebuild=True),
        core_policy_test_results='recorded separately by core author and independent reviewer',
        actual_PHP_or_FPM_executed=False, actual_APT_or_service_actions=0,
        production_connections=0, published=False,
        limits=['packaging fixtures do not prove application compatibility',
                'no live PHP migration or package transaction performed in this review'])
    (RELEASE / 'php85-packaging-review.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--review', action='store_true', help='Build, run bootstrap fixtures, and write packaging receipt')
    args = parser.parse_args()
    if args.self_test and args.review:
        parser.error('select only one test/review mode')
    packaging_review() if args.review else self_test() if args.self_test else build()
