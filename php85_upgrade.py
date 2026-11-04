#!/usr/bin/python3
"""Ubuntu 22.04 native Nginx/FPM PHP 8.5 updater. Default: read-only plan."""
import argparse
import fcntl
import glob
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import shlex
import stat
import subprocess
import sys
import time
import tempfile
import uuid
from urllib.parse import urljoin, urlsplit
from urllib.parse import urlsplit

VERSION = '1.0.10'
PREFLIGHT_V100_SHA256 = 'c1a39b696236d6e45d250ddc7efe1a2370c5606727721b8a7ea87dcc1c850002'
PREFLIGHT_V101_SHA256 = '6213fbc4e25fe377b09fa27851f489f0f3de815d5874fcd1632c9ba4f17d41a6'
PREFLIGHT_V102_SHA256 = 'b0e18a2fdca61c7e956ee5c9f0b649be50b39695e560110a1a3142dbfa03e78d'
PREFLIGHT_V103_SHA256 = 'd6e87c645b9360886d865ba20dda61128e42f96b2b6cd94597e6c257c54af24f'
PREFLIGHT_V104_SHA256 = '91a9f6ef4805ecafd8b5c0de5fbaae5eb9c4b9fb475b13086c4c3bc36744b70b'
PREINSTALL_V105_SHA256 = '9f8f78b976925bddb8a1fec30a55c5397c2a2cf34f58b0abb6d9789d2648303f'
BASE = Path('/var/lib/ubuntu-php85-upgrade')
TARGET = '8.5'
FLOOR = '8.5.12'
BRANCH = re.compile(r'^php(7\.[234]|8\.[0-5])(?:-|$)')
NAME = re.compile(r'^[a-z0-9][a-z0-9+.-]*$')
HOST = re.compile(r'^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}$', re.I)
SOCKET = re.compile(r'^/(?:var/)?run/php/[a-zA-Z0-9_.-]+\.sock$')
PROTECTED = re.compile(r'^(?:nginx|libnginx|apache2|libapache2|mysql|mariadb|percona|postgresql|redis-server|nodejs|libnode|node-|openssh|systemd|linux-|ubuntu-|grub|initramfs|php(?:7\.[234]|8\.[0-4])(?:-|$))')
PPA_HOSTS = {'ppa.launchpad.net', 'ppa.launchpadcontent.net', 'ppa.setup-php.com'}
PPA_KEY = 'B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6'
PPA_LEGACY_KEY = '14AA40EC0831756756D7F66C4F4EA0AAE5267A6C'
REMOVED_DEFAULTS = {'disable_classes': '', 'track_errors': '0', 'log_errors_max_len': '1024',
    'session.sid_length': '26', 'session.sid_bits_per_character': '5',
    'assert.active': '1', 'assert.warning': '1', 'assert.bail': '0',
    'assert.callback': '', 'assert.exception': '1'}
SKIP_INI = {'extension_dir', 'extension', 'zend_extension', 'auto_prepend_file', 'auto_append_file',
            'opcache.preload', 'opcache.preload_user'}


RUNTIME_SOURCE = r'''"""Apply-only FPM FastCGI runtime proof; no app files, shell or service actions."""
import os,re,socket,stat,struct,time,uuid
from pathlib import Path

LIMIT=1048576
class ProofError(ValueError):pass
def need(value,code):
    if not value:raise ProofError(code)
def bounded(path,limit):
    with Path(path).open('rb') as stream:raw=stream.read(limit+1)
    need(len(raw)<=limit,'process_evidence_bound');return raw
def proc_stat(root,pid):
    raw=bounded(Path(root)/str(pid)/'stat',65536).decode()
    need(raw.startswith(str(pid)+' (') and ')' in raw,'invalid_process_stat')
    fields=raw.rsplit(')',1)[1].split();need(len(fields)>19,'short_process_stat')
    return (int(fields[1]),int(fields[19]),fields[0])
def service_process_proof(peer_pid,master_pid,extension_dir,proc_root='/proc',expected_executable='/usr/sbin/php-fpm8.5',owner_uid=0,file_stat=None):
    """Require exact executable inode and current target-API extension maps."""
    need(type(master_pid) is int and master_pid>1 and type(peer_pid) is int and peer_pid>1,'invalid_service_PID')
    extension_dir=str(extension_dir);need(re.fullmatch(r'/usr/lib/php/[0-9]{8}',extension_dir),'nonstandard_target_API_directory')
    expected=Path(expected_executable).stat()
    need(stat.S_ISREG(expected.st_mode) and expected.st_uid==owner_uid and not expected.st_mode&0o022,'unsafe_target_FPM_executable')
    root=Path(proc_root);paths=[p for p in root.iterdir() if p.name.isdecimal()]
    need(len(paths)<=65536,'process_inventory_bound');rows={}
    for path in paths:
        try:rows[int(path.name)]=proc_stat(root,int(path.name))
        except FileNotFoundError:continue
    need(master_pid in rows and rows[master_pid][2] not in ('Z','X'),'FPM_master_not_live')
    selected={master_pid}
    for unused in range(64):
        more={pid for pid,row in rows.items() if row[0] in selected}
        if more<=selected:break
        selected.update(more)
    else:raise ProofError('FPM_lineage_depth_bound')
    need(peer_pid in selected and len(selected)<=1024,'FastCGI_peer_not_target_service')
    module_count=0
    for pid in sorted(selected):
        before=rows[pid];need(before[2] not in ('Z','X'),'FPM_lifecycle_incomplete')
        process=root/str(pid);target=os.readlink(str(process/'exe'))
        need(target==str(expected_executable),'noncanonical_or_deleted_FPM_executable')
        actual=(process/'exe').stat()
        need((actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino),'stale_FPM_executable_inode')
        for line in bounded(process/'maps',8388608).decode().splitlines():
            fields=line.split(None,5)
            if len(fields)<6:continue
            path=fields[5]
            if not path.startswith('/usr/lib/php/'):continue
            need(not path.endswith(' (deleted)'),'deleted_PHP_extension_map')
            need(str(Path(path).parent)==extension_dir and path.endswith('.so'),'old_or_custom_PHP_API_map')
            loaded=(file_stat or os.stat)(path);device=fields[3].split(':')
            need(stat.S_ISREG(loaded.st_mode) and loaded.st_uid==owner_uid and not loaded.st_mode&0o022,
                 'unsafe_PHP_extension_file')
            need(len(device)==2 and int(fields[4])==loaded.st_ino and
                 (int(device[0],16),int(device[1],16))==(os.major(loaded.st_dev),os.minor(loaded.st_dev)),
                 'stale_PHP_extension_inode')
            module_count+=1
        need(proc_stat(root,pid)==before,'FPM_process_changed_during_proof')
    need(proc_stat(root,master_pid)==rows[master_pid],'FPM_master_changed_during_proof')
    return dict(peer_pid=peer_pid,master_pid=master_pid,processes=len(selected),
                extension_map_observations=module_count,target_API_directory=extension_dir,
                current_executables_and_PHP_maps=True)

def length(value):
    need(0<=value<2**31,'FastCGI_parameter_length_bound')
    return bytes([value]) if value<128 else struct.pack('!I',value|0x80000000)
def parameters(values):
    raw=b''
    for key,value in values.items():
        key,value=key.encode('ascii'),str(value).encode('utf-8')
        raw+=length(len(key))+length(len(value))+key+value
    need(len(raw)<=65535,'FastCGI_parameters_bound');return raw
def record(kind,content=b''):
    need(len(content)<=65535,'FastCGI_record_bound')
    return struct.pack('!BBHHBB',1,kind,1,len(content),0,0)+content
def receive(connection,count,deadline):
    raw=b''
    while len(raw)<count:
        remaining=deadline-time.monotonic();need(remaining>0,'FastCGI_deadline')
        connection.settimeout(remaining)
        block=connection.recv(count-len(raw));need(bool(block),'FastCGI_truncated_response');raw+=block
    return raw
def response(connection,deadline):
    stdout=b'';used=0;stdout_closed=False
    while True:
        header=receive(connection,8,deadline);used+=8
        version,kind,request,size,padding,reserved=struct.unpack('!BBHHBB',header)
        need(version==1 and request==1 and reserved==0,'invalid_FastCGI_response_header')
        used+=size+padding;need(used<=LIMIT,'FastCGI_response_bound')
        content=receive(connection,size,deadline)
        if padding:receive(connection,padding,deadline)
        if kind==6:
            need(not stdout_closed or not content,'FastCGI_stdout_after_close')
            if content:stdout+=content
            else:stdout_closed=True
        elif kind==7:need(not content,'FastCGI_stderr_observed')
        elif kind==3:
            need(len(content)==8 and stdout_closed,'invalid_FastCGI_END_REQUEST')
            app,protocol=struct.unpack('!IB3x',content)
            need(app==0 and protocol==0,'FastCGI_request_failed');return stdout
        else:raise ProofError('unexpected_FastCGI_record')
def parsed_stdout(raw,nonce):
    need(b'\r\n\r\n' in raw,'FastCGI_CGI_headers_missing')
    headers,body=raw.split(b'\r\n\r\n',1);statuses=[]
    for line in headers.split(b'\r\n'):
        need(b':' in line,'invalid_CGI_header')
        key,value=line.split(b':',1)
        if key.lower()==b'status':statuses.append(value.strip().split(b' ',1)[0])
    need(statuses in ([],[b'200']),'FastCGI_non200_status')
    match=re.fullmatch(re.escape(nonce.encode())+rb'\|(8\.5\.([0-9]+))\|fpm-fcgi',body)
    need(match is not None and int(match[2])>=12,'wrong_nonce_PHP_version_or_SAPI')
    return match[1].decode('ascii')
def cleanup_probe(path,identity,content,owner_uid):
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:info=os.fstat(stream.fileno());raw=stream.read(len(content)+1)
    named=path.lstat()
    need((info.st_dev,info.st_ino)==identity==(named.st_dev,named.st_ino) and
         stat.S_ISREG(info.st_mode) and stat.S_ISREG(named.st_mode) and info.st_nlink==named.st_nlink==1
         and info.st_uid==named.st_uid==owner_uid and stat.S_IMODE(info.st_mode)==stat.S_IMODE(named.st_mode)==0o644
         and raw==content,'probe_cleanup_ownership_or_content_changed')
    path.unlink()
def prove_pool(sockets,master_pid,extension_dir,probe_dir='/run',proc_root='/proc',
               expected_executable='/usr/sbin/php-fpm8.5',process_checker=None,owner_uid=0):
    """Probe each socket once. Injectable checker/directory are fixture-only APIs.

    Default checker inspects current target service master/descendants before and
    after each response. No app/customer path is read or requested. Errors hold;
    callers may perform a separately bounded read-only recheck, never retry APT.
    """
    need(os.geteuid()==owner_uid,'root_required_for_runtime_probe')
    sockets=list(sockets);need(sockets and len(sockets)<=32 and len(set(sockets))==len(sockets),'invalid_pool_socket_set')
    directory=Path(probe_dir);info=directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==owner_uid and not info.st_mode&0o022
         and directory.resolve()==directory,'unsafe_probe_directory')
    nonce=uuid.uuid4().hex;path=directory/('ubuntu-php85-probe-'+uuid.uuid4().hex+'.php')
    content=("<?php header('Content-Type: text/plain'); echo '"+nonce+"|', PHP_VERSION, '|', PHP_SAPI;").encode('ascii')
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),0o644);stream.write(content);stream.flush();os.fsync(stream.fileno())
        own=os.fstat(stream.fileno());identity=(own.st_dev,own.st_ino)
    checker=process_checker or (lambda peer,master,api:service_process_proof(peer,master,api,proc_root,expected_executable,owner_uid))
    proofs=[]
    try:
        for name in sockets:
            need(isinstance(name,str) and name.startswith('/') and '\0' not in name,'absolute_pool_socket_required')
            socket_info=Path(name).lstat();need(stat.S_ISSOCK(socket_info.st_mode),'pool_socket_not_native_socket')
            deadline=time.monotonic()+5
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.settimeout(max(0.001,deadline-time.monotonic()));connection.connect(name)
                peer,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
                checker(peer,master_pid,extension_dir)
                params=parameters(dict(GATEWAY_INTERFACE='CGI/1.1',SERVER_PROTOCOL='HTTP/1.1',REQUEST_METHOD='GET',
                    SCRIPT_FILENAME=str(path),SCRIPT_NAME='/ubuntu-php85-runtime-probe.php',REQUEST_URI='/ubuntu-php85-runtime-probe.php',
                    QUERY_STRING='',CONTENT_LENGTH='0',SERVER_NAME='localhost',SERVER_ADDR='127.0.0.1',SERVER_PORT='80',
                    REMOTE_ADDR='127.0.0.1',REMOTE_PORT='0',REDIRECT_STATUS='200'))
                remaining=deadline-time.monotonic();need(remaining>0,'FastCGI_deadline');connection.settimeout(remaining)
                connection.sendall(record(1,struct.pack('!HB5x',1,0))+record(4,params)+record(4)+record(5))
                version=parsed_stdout(response(connection,deadline),nonce)
                process=checker(peer,master_pid,extension_dir)
                need(time.monotonic()<=deadline,'FastCGI_deadline')
                proofs.append(dict(socket=name,PHP_version=version,PHP_SAPI='fpm-fcgi',nonce_matched=True,
                                   peer_pid=peer,service_processes=process))
        return dict(status='target_FPM_runtime_proved',pools=proofs,temporary_probe_removed=True,
                    customer_application_executed=False,package_actions=0,service_actions=0)
    finally:cleanup_probe(path,identity,content,owner_uid)
'''
RUNTIME = {}
exec(compile(RUNTIME_SOURCE, '<reviewed-FPM-runtime-proof>', 'exec'), RUNTIME)


class Hold(Exception):
    pass


def need(condition, reason):
    if not condition:
        raise Hold(reason)


def exception_details(error):
    """Record only our code locations, never exception text, locals or source lines."""
    frames, trace = [], error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        if code.co_filename in (__file__, '<reviewed-FPM-runtime-proof>'):
            frames.append(dict(function=code.co_name, line=trace.tb_lineno))
        trace = trace.tb_next
    return dict(exception_frames=frames[-12:])


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


_SECURITY_ROOT = Path('/')
_SECURITY_UID = 0


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns)


def _safe_parents(path, requested=None):
    """Validate real parents and only the fixed root-level merged-/usr aliases."""
    root = _SECURITY_ROOT
    requested = path if requested is None else requested
    need(path.is_absolute() and '..' not in path.parts and (path == root or root in path.parents), 'unsafe_absolute_file_path')
    for parent in reversed(path.parents):
        if parent != root and root not in parent.parents:
            continue
        info = parent.lstat()
        if stat.S_ISDIR(info.st_mode) and info.st_uid == _SECURITY_UID and not info.st_mode & 0o022:
            continue
        if (stat.S_ISLNK(info.st_mode) and parent.parent == root
            and parent.name in ('bin', 'sbin', 'lib', 'lib64')
            and info.st_uid == _SECURITY_UID and info.st_nlink == 1):
            target = os.readlink(parent)
            expected = root / 'usr' / parent.name
            if target in ('usr/' + parent.name, str(expected)):
                canonical, aliases = _safe_parents(expected / path.relative_to(parent), requested)
                return canonical, [(parent, _file_identity(info), target)] + aliases
        error = Hold('unsafe_file_parent')
        error.details = dict(requested_path=str(requested), parent_path=str(parent),
            uid=info.st_uid, gid=info.st_gid, mode=oct(stat.S_IMODE(info.st_mode)),
            type='symlink' if stat.S_ISLNK(info.st_mode) else 'directory' if stat.S_ISDIR(info.st_mode) else 'other')
        raise error
    return path, []


def _file_record(path, private=False):
    p = Path(path)
    cursor, parent_aliases = _safe_parents(p)
    logical = p.lstat()
    need(logical.st_uid == _SECURITY_UID, 'unsafe_file_alias_owner')
    link = os.readlink(p) if stat.S_ISLNK(logical.st_mode) else None
    need(not private or link is None, 'private_file_symlink')
    aliases = list(parent_aliases)
    for unused in range(16):
        cursor, more_parents = _safe_parents(cursor, p)
        parent_aliases.extend(more_parents)
        aliases.extend(more_parents)
        alias = cursor.lstat()
        if not stat.S_ISLNK(alias.st_mode):
            break
        need(alias.st_uid == _SECURITY_UID, 'unsafe_file_alias_owner')
        target = os.readlink(cursor)
        aliases.append((cursor, _file_identity(alias), target))
        cursor = Path(os.path.normpath(target if os.path.isabs(target) else str(cursor.parent / target)))
    else:
        raise Hold('file_alias_limit')
    resolved = cursor
    _safe_parents(resolved, p)
    before = resolved.lstat()
    need(stat.S_ISREG(before.st_mode) and before.st_uid == _SECURITY_UID
         and not before.st_mode & 0o022 and before.st_nlink == 1, 'unsafe_file')
    need(not private or before.st_mode & 0o077 == 0, 'private_file_required')
    need(before.st_size <= 16 * 1024 * 1024, 'file_too_large')
    need(not hasattr(os, 'listxattr') or not os.listxattr(resolved), 'file_xattrs_require_preservation_profile')
    fd = os.open(str(resolved), os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        raw = stream.read(16 * 1024 * 1024 + 1)
    need(len(raw) <= 16 * 1024 * 1024 and _file_identity(before) == _file_identity(opened)
         == _file_identity(resolved.lstat()) and _file_identity(logical) == _file_identity(p.lstat())
         and p.resolve(strict=True) == resolved, 'file_changed_during_read')
    need(all(_file_identity(alias.lstat()) == identity and os.readlink(alias) == target
             for alias, identity, target in aliases), 'file_alias_changed_during_read')
    return raw, dict(sha256=digest(raw), link=link, resolved=str(resolved),
        uid=opened.st_uid, gid=opened.st_gid, mode=stat.S_IMODE(opened.st_mode),
        link_uid=logical.st_uid, link_inode=logical.st_ino if link is not None else None,
        parent_aliases=[dict(path=str(alias), identity=list(identity), target=target)
                        for alias, identity, target in parent_aliases])


def safe_file(path, private=False):
    return _file_record(path, private)[0]


def atomic(path, raw, mode=0o600):
    path = Path(path)
    fd = os.open(str(path) + '.new-' + uuid.uuid4().hex, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    name = Path(os.readlink('/proc/self/fd/' + str(fd)))
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if name.exists():
            name.unlink()


def child_environment(env=None):
    need(not os.environ.get('APT_CONFIG'), 'APT_CONFIG_override_forbidden')
    environment = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/nonexistent', LC_ALL='C', LANG='C',
        DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l', UCF_FORCE_CONFFOLD='1',
        APT_LISTCHANGES_FRONTEND='none', PYTHONDONTWRITEBYTECODE='1')
    for key, value in (env or {}).items():
        need(key == 'PHP_INI_SCAN_DIR' and isinstance(value, str)
             and re.fullmatch(r'/etc/php/[0-9]+\.[0-9]+/(?:cli|fpm)/conf\.d', value), 'unapproved_command_environment')
        environment[key] = value
    return environment


def command(args, timeout=30, env=None, input=None):
    environment = child_environment(env)
    try:
        result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=environment)
    except subprocess.TimeoutExpired:
        raise Hold('command_timed_out_' + Path(args[0]).name)
    need(len(result.stdout) <= 16 * 1024 * 1024 and len(result.stderr) <= 16 * 1024 * 1024,
         'command_output_too_large')
    if result.returncode != 0:
        error = Hold('command_failed_' + Path(args[0]).name)
        if args[0] == '/usr/bin/gpgv':
            error.gpgv_result = dict(returncode=result.returncode,
                stdout=result.stdout.decode('utf-8', 'strict'), stderr=result.stderr.decode('utf-8', 'replace'))
            error.details = dict(exit_code=result.returncode,
                status_codes=re.findall(r'(?m)^\[GNUPG:\] ([A-Z_]+)(?: |$)', error.gpgv_result['stdout']))
        raise error
    return result.stdout.decode('utf-8', 'strict')


def apt_install(args, job):
    """Stream the one approved installation to private evidence; never timeout dpkg."""
    need(args[0] == '/usr/bin/apt-get', 'APT_install_executable_required')
    info = job.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == _SECURITY_UID
         and not info.st_mode & 0o077 and not job.is_symlink(), 'unsafe_APT_evidence_directory')
    paths = [job / 'apt-install.stdout', job / 'apt-install.stderr']
    streams, records, created = [], [], []
    try:
        for path in paths:
            canonical, aliases = _safe_parents(path)
            need(canonical == path and not aliases, 'unsafe_APT_evidence_path')
            fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            try:
                os.fchmod(fd, 0o600)
                initial = os.fstat(fd)
                stream = os.fdopen(fd, 'w+b')
            except BaseException:
                try:
                    os.close(fd)
                except OSError:
                    pass
                raise
            streams.append(stream)
            created.append(initial)
        result = subprocess.run(args, stdout=streams[0], stderr=streams[1],
                                env=child_environment(), timeout=None)
        for stream, path, initial in zip(streams, paths, created):
            stream.flush()
            os.fsync(stream.fileno())
            before = os.fstat(stream.fileno())
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink')
            need(stat.S_ISREG(before.st_mode) and before.st_uid == _SECURITY_UID
                 and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                 and all(getattr(before, key) == getattr(initial, key) for key in fields),
                 'APT_evidence_metadata_changed')
            stream.seek(0)
            checksum = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                checksum.update(chunk)
            need(_file_identity(before) == _file_identity(os.fstat(stream.fileno()))
                 == _file_identity(path.lstat()), 'APT_evidence_changed')
            records.append(dict(path=str(path), sha256=checksum.hexdigest(), bytes=before.st_size))
    finally:
        for stream in streams:
            stream.close()
    if result.returncode != 0:
        error = Hold('command_failed_apt-get')
        error.details = dict(exit_code=result.returncode, stdout_log=str(paths[0]), stderr_log=str(paths[1]), logs=records)
        raise error
    return dict(exit_code=result.returncode, logs=records)


def identity():
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1)
            release[key] = value.strip('"')
    need(release.get('ID') == 'ubuntu' and release.get('VERSION_ID') == '22.04'
         and release.get('VERSION_CODENAME') == 'jammy', 'Ubuntu_22_04_Jammy_required')
    need(not Path('/.dockerenv').exists() and not Path('/run/systemd/container').exists()
         and Path('/proc/1/comm').read_text().strip() == 'systemd', 'native_systemd_required')
    need('microsoft' not in os.uname().release.lower(), 'WSL_use_global_updater_profile')
    arch = command(['/usr/bin/dpkg', '--print-architecture']).strip()
    need(arch in ('amd64', 'arm64'), 'unsupported_architecture')
    machine = Path('/etc/machine-id').read_text().strip()
    need(re.fullmatch('[0-9a-f]{32}', machine) is not None, 'machine_identity_required')
    return dict(machine_id=machine, hostname=os.uname().nodename, release='22.04', architecture=arch,
                boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())


def packages():
    need(not command(['/usr/bin/dpkg', '--audit']).strip(), 'unfinished_dpkg_state')
    text = command(['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'])
    result = {}
    for line in text.splitlines():
        fields = line.split('\t')
        need(len(fields) == 4, 'package_inventory_malformed')
        name, version, arch, status = fields
        if status.startswith('ii'):
            need(name not in result, 'multiarch_package_inventory_requires_review')
            result[name] = dict(version=version, architecture=arch)
    return result


def files_snapshot(paths):
    return {path: _file_record(path)[1] for path in sorted(set(map(str, paths)))}


def _deb822_fields(block):
    fields, current = {}, None
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if line.startswith((' ', '\t')):
            need(current is not None, 'malformed_APT_source_stanza')
            fields[current] += '\n' + line[1:]
            continue
        match = re.fullmatch(r'([A-Za-z][A-Za-z-]*):\s*(.*)', line)
        need(match is not None, 'malformed_APT_source_stanza')
        current = match[1].lower()
        need(current not in fields, 'duplicate_APT_source_field')
        fields[current] = match[2]
    return fields


def _safe_source_options(options):
    for name, value in options.items():
        key = name.lower().replace('-', '')
        value = value.strip().lower()
        if key == 'trusted' or key.startswith(('allowinsecure', 'allowweak', 'allowdowngrade')):
            need(value in ('no', 'false', '0'), 'APT_source_authentication_override')
        if key in ('checkvaliduntil', 'checkdate'):
            need(value in ('yes', 'true', '1'), 'APT_source_expiry_override')


def _source_entries(text, suffix):
    entries = []
    if suffix == '.sources':
        for block in re.split(r'\n[ \t]*\n', text):
            fields = _deb822_fields(block)
            if not fields or fields.get('enabled', 'yes').lower() in ('no', 'false', '0'):
                continue
            _safe_source_options(fields)
            entries.append(dict(uris=fields.get('uris', '').split(), suites=fields.get('suites', '').split(),
                                types=fields.get('types', '').split(), signed_by=fields.get('signed-by', '')))
    else:
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            match = re.fullmatch(r'\s*(deb|deb-src)\s+(?:\[([^\]]*)\]\s+)?(\S+)\s+(\S+)\s+.+?(?:\s+#.*)?', line)
            need(match is not None, 'malformed_APT_source_line')
            options = {}
            for item in shlex.split(match[2] or ''):
                need('=' in item, 'unsupported_APT_source_option')
                key, value = item.split('=', 1)
                need(key.lower() not in options, 'duplicate_APT_source_option')
                options[key.lower()] = value
            _safe_source_options(options)
            entries.append(dict(uris=[match[3]], suites=[match[4]], types=[match[1]], signed_by=options.get('signed-by', '')))
    return entries


def _key_paths(value):
    if value.lstrip().startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'):
        return []
    paths = []
    for item in re.split(r'[\s,]+', value.strip()):
        if not item:
            continue
        if re.fullmatch(r'[0-9A-Fa-f]{40}!?', item):
            continue
        need(re.fullmatch(r'/(?:etc/apt|usr/share/keyrings)/[A-Za-z0-9_./-]+\.(?:gpg|asc)', item)
             and '..' not in Path(item).parts, 'unsupported_APT_SignedBy_reference')
        paths.append(item)
    return paths


def _configured_sources():
    paths = sorted(set(glob.glob('/etc/apt/sources.list') + glob.glob('/etc/apt/sources.list.d/*.list')
                       + glob.glob('/etc/apt/sources.list.d/*.sources')))
    entries = []
    for path in paths:
        for entry in _source_entries(safe_file(path).decode(), Path(path).suffix):
            entries.append(dict(entry, source_path=path))
    return paths, entries


def validate_apt_security():
    """Call before any index refresh; rejects environment and effective APT waivers."""
    need(not os.environ.get('APT_CONFIG'), 'APT_CONFIG_override_forbidden')
    import apt_pkg
    apt_pkg.init_config()
    unsafe = ('APT::Get::AllowUnauthenticated', 'Acquire::AllowInsecureRepositories',
              'Acquire::AllowWeakRepositories', 'Acquire::AllowDowngradeToInsecureRepositories',
              'Acquire::AllowWeakDowngradeToInsecureRepositories', 'Acquire::AllowWeakDowngradeToInsecure')
    for key in set(unsafe) | set(apt_pkg.config.keys()):
        canonical = key.lower().replace('-', '')
        if key in unsafe or 'allowunauthenticated' in canonical or ('acquire::' in canonical and
                any(token in canonical for token in ('allowinsecure', 'allowweak', 'allowdowngrade'))):
            need(not apt_pkg.config.find_b(key, False), 'APT_authentication_override')
        if canonical in ('acquire::checkvaliduntil', 'acquire::checkdate'):
            need(apt_pkg.config.find_b(key, True), 'APT_expiry_override')
    _configured_sources()
    return True


def source_files():
    paths = []
    for pattern in ('/etc/apt/sources.list', '/etc/apt/sources.list.d/*.list',
                    '/etc/apt/sources.list.d/*.sources', '/etc/apt/apt.conf',
                    '/etc/apt/apt.conf.d/*', '/etc/apt/trusted.gpg',
                    '/etc/apt/trusted.gpg.d/*', '/etc/apt/keyrings/*'):
        for path in glob.glob(pattern):
            need(Path(path).is_file(), 'unsupported_APT_configuration_entry')
            paths.append(path)
    configured, entries = _configured_sources()
    paths.extend(configured)
    for entry in entries:
        paths.extend(_key_paths(entry['signed_by']))
    return files_snapshot(paths)


def tokens(text):
    """Nginx lexer: return decoded tokens with original byte-preserving character spans."""
    result, i = [], 0
    while i < len(text):
        if text[i].isspace():
            i += 1
        elif text[i] == '#':
            i = text.find('\n', i) if '\n' in text[i:] else len(text)
        elif text[i] in ';{}':
            result.append((text[i], i, i + 1))
            i += 1
        else:
            start, value, quote = i, '', None
            while i < len(text):
                c = text[i]
                if c == '\\':
                    need(i + 1 < len(text), 'bad_nginx_escape')
                    value += text[i + 1]
                    i += 2
                elif quote:
                    if c == quote:
                        quote = None
                    else:
                        value += c
                    i += 1
                elif c in "\"'":
                    quote = c
                    i += 1
                elif c.isspace() or c in ';{}#':
                    break
                else:
                    value += c
                    i += 1
            need(quote is None and i > start, 'bad_nginx_token')
            result.append((value, start, i))
    return result


def directives(text):
    stream, position = tokens(text), 0

    def structural(token):
        return token[0] in (';', '{', '}') and text[token[1]:token[2]] == token[0]

    def parse(nested=False):
        nonlocal position
        result = []
        while position < len(stream):
            if structural(stream[position]) and stream[position][0] == '}':
                need(nested, 'unexpected_nginx_brace')
                position += 1
                return result
            header = []
            while position < len(stream) and not structural(stream[position]):
                header.append(stream[position])
                position += 1
            need(header and position < len(stream), 'unterminated_nginx_directive')
            delimiter = stream[position][0]
            position += 1
            need(delimiter in (';', '{'), 'bad_nginx_directive')
            result.append((header, parse(True) if delimiter == '{' else None))
        need(not nested, 'unterminated_nginx_block')
        return result
    return parse()


def normalize_socket(value):
    need(SOCKET.fullmatch(value) is not None, 'standard_local_PHP_Unix_socket_required')
    return value.replace('/var/run/', '/run/', 1)


def nginx_vendor_file(path):
    rows = command(['/usr/bin/dpkg-query', '-S', str(path)]).splitlines()
    need(len(rows) == 1 and ': ' in rows[0], 'Nginx_vendor_file_owner_ambiguous')
    owner = rows[0].split(': ', 1)[0].split(':', 1)[0]
    need(NAME.fullmatch(owner) is not None and owner.startswith(('nginx', 'libnginx')),
         'Nginx_vendor_package_owner_required')
    state = command(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Abbrev}', owner]).strip()
    need(state in ('ii', 'hi'), 'Nginx_vendor_package_not_installed')
    installed_vendor_file(owner, path)
    return owner


def validate_nginx_path(path, read):
    """Allow only stock package-owned module aliases outside /etc/nginx."""
    logical = Path(path)
    resolved = logical.resolve()
    if logical.is_absolute() and '..' not in logical.parts and str(logical).startswith('/etc/nginx/'):
        if str(resolved).startswith('/etc/nginx/'):
            return False
        if (logical.parent == Path('/etc/nginx/modules-enabled') and logical.suffix == '.conf'
            and logical.is_symlink() and resolved.parent == Path('/usr/share/nginx/modules-available')
            and resolved.suffix == '.conf'):
            # The normal read path validates both the root-owned alias and target.
            text = read(str(logical))
            nginx_vendor_file(resolved)
            definitions = directives(text)
            need(definitions, 'empty_Nginx_vendor_module_fragment')
            for header, children in definitions:
                args = [token[0] for token in header]
                need(children is None and len(args) == 2 and args[0] == 'load_module',
                     'Nginx_vendor_module_fragment_not_loader_only')
                match = re.fullmatch(r'(?:modules/|/usr/(?:lib/nginx|share/nginx)/modules/)([A-Za-z0-9_.-]+\.so)', args[1])
                need(match is not None, 'noncanonical_Nginx_vendor_module_path')
                module = Path('/usr/lib/nginx/modules') / match[1]
                need(module.resolve().parent == Path('/usr/lib/nginx/modules'), 'Nginx_vendor_module_binary_escape')
                nginx_vendor_file(module)
            return True
    error = Hold('nginx_path_outside_config')
    error.details = dict(logical_path=str(logical), resolved_path=str(resolved))
    raise error


def nginx_include_pattern(argument, source):
    """Nginx resolves relative includes against its main configuration prefix."""
    normalized = os.path.normpath(os.path.join('/etc/nginx', argument))
    if (not argument or '$' in argument or any(ord(c) < 32 or ord(c) == 127 for c in argument)
        or '..' in argument.split('/') or not normalized.startswith('/etc/nginx/')):
        error = Hold('unsafe_nginx_include')
        error.details = dict(source_file=str(source), include_argument=argument,
                             normalized_pattern=normalized)
        raise error
    return normalized


def validate_acme_alias(location):
    """Recognize a static ACME location; never read or alter its alias target."""
    reason = 'Nginx_alias_requires_separate_health_profile'
    args = location['args']
    if args and args[0] == '^~':
        args = args[1:]
    need(args in (['/.well-known/acme-challenge'], ['/.well-known/acme-challenge/']), reason)
    statements = location['directives']
    need(sum(name == 'alias' for name, _, _ in statements) == 1, reason)
    for name, values, block in statements:
        need(not block and all('$' not in value and not any(ord(c) < 32 or ord(c) == 127 for c in value)
                               for value in values), reason)
        if name == 'alias':
            need(len(values) == 1 and values[0].startswith('/') and '..' not in values[0].split('/')
                 and os.path.normpath(values[0]) != '/', reason)
        elif name == 'include':
            # The normal graph visitor validates and expands this static pattern.
            need(len(values) == 1, reason)
        elif name in ('allow', 'deny'):
            need(len(values) == 1, reason)
            if values[0] not in ('all', 'unix:'):
                try:
                    ipaddress.ip_network(values[0], strict=False)
                except ValueError:
                    raise Hold(reason)
        elif name == 'auth_basic':
            need(values == ['off'], reason)
        elif name == 'default_type':
            need(len(values) == 1 and re.fullmatch(r'[A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+', values[0]), reason)
        elif name in ('access_log', 'autoindex'):
            need(values == ['off'], reason)
        elif name == 'log_not_found':
            need(values in (['on'], ['off']), reason)
        else:
            raise Hold(reason)


def nginx_inventory(read=None, expand=None):
    read = read or (lambda path: safe_file(path).decode())
    expand = expand or (lambda value: sorted(glob.glob(value)))
    seen, routes, servers, locations = {}, [], [], []

    def walk(path, server=None, location=None, depth=0):
        need(depth <= 20 and len(seen) <= 500, 'nginx_include_limit')
        p = Path(path)
        validated = {}
        def validating_read(name):
            value = read(name)
            validated[name] = value
            return value
        vendor_only = validate_nginx_path(p, validating_read)
        need(not vendor_only or server is None, 'Nginx_vendor_module_in_server_context')
        text = validated[str(p)] if vendor_only else read(str(p))
        seen[str(p)] = text
        if vendor_only:
            return

        def visit(nodes, context, location_context):
            for header, children in nodes:
                name, args = header[0][0], [x[0] for x in header[1:]]
                current = context
                current_location = location_context
                if location_context is not None:
                    location_context['directives'].append((name, args, children is not None))
                if name == 'server' and children is not None:
                    need(not args, 'non_HTTP_server_block')
                    current = dict(names=[], roots=[], listen=[], routes=[])
                    servers.append(current)
                    current_location = None
                elif name == 'location' and children is not None:
                    current_location = dict(args=args, directives=[])
                    locations.append(current_location)
                if name == 'include':
                    need(len(args) == 1, 'single_nginx_include_argument_required')
                    for child in expand(nginx_include_pattern(args[0], str(p))):
                        walk(child, current, current_location, depth + 1)
                elif name == 'fastcgi_pass':
                    need(current is not None and len(args) == 1 and args[0].startswith('unix:'), 'direct_Unix_FastCGI_required')
                    socket = normalize_socket(args[0][5:])
                    record = dict(file=str(p), start=header[1][1], end=header[1][2], socket=socket)
                    routes.append(record)
                    current['routes'].append(record)
                elif name == 'fastcgi_param' and args and args[0] in ('PHP_VALUE', 'PHP_ADMIN_VALUE'):
                    raise Hold('Nginx_injected_PHP_settings_require_review')
                elif name == 'alias':
                    need(current is not None and current_location is not None,
                         'Nginx_alias_requires_separate_health_profile')
                elif current is not None and name in ('server_name', 'root', 'listen'):
                    current[{'server_name': 'names', 'root': 'roots', 'listen': 'listen'}[name]].extend(args if name == 'server_name' else [args])
                if children is not None:
                    visit(children, current, current_location)
        visit(directives(text), server, location)
    walk('/etc/nginx/nginx.conf')
    for location in locations:
        if any(name == 'alias' for name, _, _ in location['directives']):
            validate_acme_alias(location)
    need(routes, 'no_PHP_Nginx_routes')
    health = []
    for server in servers:
        if not server['routes']:
            continue
        names = []
        for value in server['names']:
            try:
                ipaddress.ip_address(value)
            except ValueError:
                if HOST.fullmatch(value) and not value.startswith('.'):
                    names.append(value.lower())
        need(names, 'canonical_site_hostname_required')
        host = names[0]
        need(any(row and re.fullmatch(r'(?:\[::\]:|0\.0\.0\.0:)?443', row[0]) and 'ssl' in row
                 for row in server['listen']), 'local_HTTPS_443_health_profile_required')
        roots = {row[0] for row in server['roots'] if len(row) == 1}
        need(len(roots) == 1 and '$' not in next(iter(roots)), 'literal_single_document_root_required')
        root = Path(next(iter(roots)))
        paths = ['/']
        if (root / 'wp-login.php').is_file():
            paths.append('/wp-login.php')
        health.extend(dict(host=host, path=path, aliases=sorted(set(names))) for path in paths)
    need(health, 'application_health_baselines_required')
    return dict(files=seen, routes=routes, health=sorted(health, key=lambda x: (x['host'], x['path'])))


def parse_pools(texts):
    pools = {}
    for path, text in sorted(texts.items()):
        current = None
        for line in text.splitlines():
            active = line.strip()
            if not active or active.startswith(';'):
                continue
            match = re.fullmatch(r'\[([A-Za-z0-9_.-]+)\]', active)
            if match:
                current = match[1]
                need(current != 'global' and current not in pools, 'duplicate_or_global_pool')
                pools[current] = dict(file=path, listen=None)
            elif re.match(r'^listen\s*=', active):
                need(current is not None, 'unscoped_pool_listener')
                value = active.split('=', 1)[1].split(';', 1)[0].strip().strip('"\'')
                pools[current]['listen'] = normalize_socket(value)
            need(not re.match(r'^(?:include\s*=|php_(?:admin_)?value\[(?:zend_)?extension(?:_dir)?\]\s*=)', active), 'custom_pool_include_or_loader')
            need(not re.search(r'(?:/php/(?:7\.[234]|8\.[0-4])|/php(?:7\.[234]|8\.[0-4])[^0-9]|/20[0-9]{6}/)', active)
                 or re.match(r'^listen\s*=', active), 'legacy_PHP_path_in_pool')
            need(not re.match(r'^chroot\s*=\s*\S', active), 'chroot_requires_separate_runtime_profile')
            sensitive = re.match(r'^php_(?:admin_)?(?:value|flag)\[(auto_prepend_file|auto_append_file|opcache\.preload|opcache\.preload_user|open_basedir)\]\s*=\s*(.*)', active)
            if sensitive:
                need(sensitive[2].split(';', 1)[0].strip().strip('"\'') == '', 'pool_application_bootstrap_or_basedir_requires_review')
    need(pools and all(row['listen'] for row in pools.values()), 'pool_listener_missing')
    need(len({row['listen'] for row in pools.values()}) == len(pools), 'duplicate_pool_socket')
    return pools


def pool_outputs(texts, pools, socket_map):
    result = {}
    for path, text in texts.items():
        current, lines = None, []
        for line in text.splitlines(keepends=True):
            match = re.fullmatch(r'\s*\[([A-Za-z0-9_.-]+)\]\s*', line.strip())
            if match:
                current = match[1]
            if re.match(r'^\s*listen\s*=', line):
                need(current in pools, 'unknown_pool')
                line = re.sub(r'^(\s*listen\s*=).*', lambda m: m[1] + ' ' + socket_map[pools[current]['listen']], line.rstrip('\r\n')) + '\n'
            lines.append(line)
        result[Path(path).name] = ''.join(lines)
    return result


def route_outputs(files, routes, socket_map):
    edits = {}
    for route in routes:
        edits.setdefault(route['file'], {})[(route['start'], route['end'])] = 'unix:' + socket_map[route['socket']]
    result = {}
    for path, replacements in edits.items():
        text = files[path]
        for (start, end), value in sorted(replacements.items(), reverse=True):
            text = text[:start] + value + text[end:]
        result[path] = text
    return result


def registry(branch, fpm=False):
    script = "echo json_encode(['version'=>PHP_VERSION,'directory'=>PHP_EXTENSION_DIR,'modules'=>get_loaded_extensions(),'ini'=>ini_get_all(null,false)]);"
    sapi = 'fpm' if fpm else 'cli'
    args = ['/usr/bin/php' + branch, '-c', '/etc/php/' + branch + '/' + sapi + '/php.ini']
    env = {'PHP_INI_SCAN_DIR': '/etc/php/' + branch + '/' + sapi + '/conf.d'}
    args += ['-d', 'auto_prepend_file=', '-d', 'auto_append_file=', '-d', 'opcache.preload=',
             '-d', 'opcache.preload_user=', '-r', script]
    try:
        value = json.loads(command(args, env=env))
    except (ValueError, FileNotFoundError):
        raise Hold('PHP_registry_unavailable')
    need(value['version'].startswith(branch + '.') and isinstance(value['ini'], dict), 'PHP_registry_mismatch')
    return value


def executable_INI_guard(settings_files):
    final = {}
    for text in settings_files.values():
        need(not re.search(r'(?mi)^\s*\[(?:PATH|HOST)\s*=', text), 'per_directory_INI_profile_required')
        for line in text.splitlines():
            match = re.match(r'^\s*([A-Za-z0-9_.-]+)\s*=(.*)', line)
            if match:
                need('${' not in match[2], 'environment_interpolated_INI_requires_review')
                final[match[1]] = match[2].split(';', 1)[0].strip().strip('"\'')
    for key in ('auto_prepend_file', 'auto_append_file', 'opcache.preload', 'opcache.preload_user', 'open_basedir'):
        need(final.get(key, '') == '', 'application_preload_prepend_or_basedir_requires_review')


def ini_output(old, target, settings_files, socket_override=None):
    executable_INI_guard(settings_files)
    target_keys = set(target['ini'])
    old_modules = {value.lower() for value in old['modules']}
    need(old_modules <= {value.lower() for value in target['modules']}, 'target_extension_parity_failed')
    explicit = set()
    for text in settings_files.values():
        need(not re.search(r'(?mi)^\s*\[(?:PATH|HOST)\s*=', text), 'per_directory_INI_profile_required')
        for line in text.splitlines():
            match = re.match(r'^\s*([A-Za-z0-9_.-]+)\s*=', line)
            if match:
                explicit.add(match[1])
    if socket_override is not None:
        need(socket_override in ('/run/mysqld/mysqld.sock', '/var/run/mysqld/mysqld.sock')
             and 'mysqli.default_socket' in explicit and 'mysqli.default_socket' in target_keys
             and old['ini'].get('mysqli.default_socket', object()) is None
             and {'mysqli', 'mysqlnd'} <= old_modules, 'unapproved_INI_socket_override')
    lines = ['; Preserved settings; PHP 8.5 owns its extension loaders.']
    for key in sorted(explicit):
        if key in SKIP_INI:
            continue
        if key not in old['ini']:
            continue
        value = (socket_override if key == 'mysqli.default_socket' and socket_override is not None
                 else str(old['ini'][key]) if old['ini'][key] is not None else '')
        if key not in target_keys:
            # mysqli.reconnect defaulted to Off and was removed in PHP 8.2.
            # Normalize only this reviewed false value; never drop ON/unknown settings.
            removed_false = (key == 'mysqli.reconnect' and
                             value.strip().lower() in ('', '0', 'off', 'false', 'no', 'none'))
            if not (removed_false or key in REMOVED_DEFAULTS and value == REMOVED_DEFAULTS[key]):
                error = Hold('removed_nondefault_INI_setting')
                error.details = dict(directive=key, files=sorted(path for path, text in settings_files.items()
                    if re.search(r'(?m)^\s*' + re.escape(key) + r'\s*=', text)))
                raise error
            continue
        need(not re.search(r'(?:/php/(?:7\.[234]|8\.[0-4])|/php(?:7\.[234]|8\.[0-4])|/20[0-9]{6}/)', value), 'legacy_PHP_path_in_setting')
        need('\n' not in value and '\r' not in value and '\x00' not in value, 'multiline_INI_value')
        value = value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')
        lines.append(key + '="' + value + '"')
    return '\n'.join(lines) + '\n'


def forwarded_values(old, target, settings_files, socket_override=None):
    ini_output(old, target, settings_files, socket_override)
    keys = {m[1] for text in settings_files.values() for line in text.splitlines()
            if (m := re.match(r'^\s*([A-Za-z0-9_.-]+)\s*=', line))}
    return {key: socket_override if key == 'mysqli.default_socket' and socket_override is not None else old['ini'][key]
            for key in keys - SKIP_INI if key in old['ini'] and key in target['ini']}


def global_FPM_output(text, branch):
    allowed = {'pid', 'error_log', 'include', 'syslog.facility', 'syslog.ident', 'log_level', 'log_limit',
               'log_buffering', 'emergency_restart_threshold', 'emergency_restart_interval', 'process_control_timeout',
               'process.max', 'process.priority', 'daemonize', 'rlimit_files', 'rlimit_core', 'events.mechanism', 'systemd_interval'}
    lines = []
    for line in text.splitlines(keepends=True):
        active = line.strip()
        if active and not active.startswith(';') and active != '[global]':
            need('=' in active, 'custom_FPM_global_syntax')
            key, value = [part.strip() for part in active.split('=', 1)]
            need(key in allowed, 'unsupported_FPM_global_setting')
            if key == 'pid':
                need(value in ('/run/php/php' + branch + '-fpm.pid', '/var/run/php/php' + branch + '-fpm.pid'), 'custom_FPM_PID_requires_review')
                line = 'pid = /run/php/php8.5-fpm.pid\n'
            elif key == 'include':
                need(value == '/etc/php/' + branch + '/fpm/pool.d/*.conf', 'standard_pool_include_required')
                line = 'include = /etc/php/8.5/fpm/pool.d/*.conf\n'
            elif key == 'error_log' and value == '/var/log/php' + branch + '-fpm.log':
                line = 'error_log = /var/log/php8.5-fpm.log\n'
        lines.append(line)
    return ''.join(lines)


def installed_vendor_file(package, path):
    """Check local package-file inventory; repository/archive trust is verified separately."""
    need(NAME.fullmatch(package) is not None, 'invalid_vendor_package')
    raw = safe_file(path)
    arch = command(['/usr/bin/dpkg', '--print-architecture']).strip()
    inventories = [p for p in (Path('/var/lib/dpkg/info/' + package + '.md5sums'),
                   Path('/var/lib/dpkg/info/' + package + ':' + arch + '.md5sums')) if p.is_file()]
    need(len(inventories) == 1, 'vendor_file_inventory_missing_or_ambiguous')
    matched = []
    for line in safe_file(inventories[0]).decode().splitlines():
        fields = line.split(None, 1)
        if len(fields) == 2 and Path('/' + fields[1]).resolve() == Path(path).resolve():
            matched.append(fields[0])
    need(len(matched) == 1 and hashlib.md5(raw, usedforsecurity=False).hexdigest() == matched[0], 'vendor_file_modified_requires_review')


def validate_loaders(branch, profiles, before):
    installed_vendor_file('php' + branch + '-cli', '/usr/bin/php' + branch)
    directory = command(['/usr/bin/php' + branch, '-n', '-r', 'echo PHP_EXTENSION_DIR;']).strip()
    need(re.fullmatch(r'/usr/lib/php/[0-9]{8}', directory) is not None, 'standard_PHP_API_directory_required')
    for files in profiles.values():
        extension_dirs = [match[1].split(';', 1)[0].strip().strip('"\'')
                          for text in files.values() for line in text.splitlines()
                          if (match := re.match(r'^\s*extension_dir\s*=\s*(.*)', line))]
        need(not extension_dirs or extension_dirs[-1].rstrip('/') == directory, 'custom_extension_directory_requires_review')
        for text in files.values():
            for line in text.splitlines():
                match = re.match(r'^\s*(?:zend_)?extension\s*=\s*(.*)', line)
                if not match:
                    continue
                name = match[1].split(';', 1)[0].strip().strip('"\'')
                need(re.fullmatch(r'[A-Za-z0-9_.-]+(?:\.so)?', name) is not None, 'custom_extension_loader_path')
                path = directory + '/' + (name if name.endswith('.so') else name + '.so')
                owners = command(['/usr/bin/dpkg-query', '-S', path]).splitlines()
                need(len(owners) == 1 and ': ' in owners[0], 'extension_package_owner_ambiguous')
                owner = owners[0].split(': ', 1)[0].split(':', 1)[0]
                need(owner in before and owner.startswith('php' + branch + '-'), 'unversioned_or_unowned_extension_requires_review')
                installed_vendor_file(owner, path)


def validate_native_unit(branch, running=False):
    unit = 'php' + branch + '-fpm.service'
    fields = ('FragmentPath', 'DropInPaths', 'Environment', 'EnvironmentFiles', 'PassEnvironment', 'ExecStart', 'MainPID')
    args = ['/bin/systemctl', 'show', unit]
    for field in fields:
        args += ['-p', field]
    raw = command(args)
    values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    need(values.get('FragmentPath') and values.get('DropInPaths', '') == ''
         and values.get('Environment', '') == '' and values.get('PassEnvironment', '') == '', 'custom_FPM_unit_environment_or_dropins')
    if 'EnvironmentFiles' in values:
        need(values['EnvironmentFiles'] == '', 'FPM_environment_file_requires_review')
    else:
        encoded_unit = ''.join(c if c.isalnum() else '_' + format(ord(c), '02x') for c in unit)
        proof = command(['/usr/bin/busctl', 'get-property', 'org.freedesktop.systemd1',
            '/org/freedesktop/systemd1/unit/' + encoded_unit, 'org.freedesktop.systemd1.Service', 'EnvironmentFiles'])
        need(proof.strip() == 'a(sb) 0', 'FPM_environment_files_not_proven_empty')
    installed_vendor_file('php' + branch + '-fpm', values['FragmentPath'])
    argv = re.findall(r'argv\[\]=([^;]+);', values.get('ExecStart', ''))
    need(len(argv) == 1 and argv[0].split() == ['/usr/sbin/php-fpm' + branch,
         '--nodaemonize', '--fpm-config', '/etc/php/' + branch + '/fpm/php-fpm.conf'], 'custom_FPM_ExecStart_config')
    if running:
        pid = values.get('MainPID', '')
        need(pid.isdigit() and int(pid) > 1, 'FPM_master_missing')
        raw = RUNTIME['bounded']('/proc/' + pid + '/environ', 1048576)
        environment = dict(item.split(b'=', 1) for item in raw.split(b'\0') if b'=' in item)
        need(not environment.get(b'LD_PRELOAD') and not environment.get(b'LD_LIBRARY_PATH'), 'FPM_dynamic_loader_environment')
        if b'PHP_INI_SCAN_DIR' in environment:
            need(environment[b'PHP_INI_SCAN_DIR'] == ('/etc/php/' + branch + '/fpm/conf.d').encode(), 'FPM_scan_directory_override')
        if b'PHPRC' in environment:
            need(environment[b'PHPRC'] in (('/etc/php/' + branch + '/fpm').encode(),
                 ('/etc/php/' + branch + '/fpm/php.ini').encode()), 'FPM_INI_path_override')
    return values['FragmentPath']


def unit_enabled(branch):
    value = command(['/bin/systemctl', 'show', 'php' + branch + '-fpm.service', '-p', 'UnitFileState', '--value']).strip()
    need(value in ('enabled', 'disabled'), 'custom_FPM_enablement_state')
    return value == 'enabled'


def merged_mode(records):
    mode = 0o644
    private_groups = {row['gid'] for row in records if not row['mode'] & 0o004}
    need(len(private_groups) <= 1, 'mixed_private_INI_groups_require_review')
    for row in records:
        mode &= row['mode']
    return mode, next(iter(private_groups), 0)


def candidate(cache, name, host):
    need(name in cache and cache[name].candidate is not None, 'candidate_missing_' + name)
    value = cache[name].candidate
    record = value.record
    origins = [dict(trusted=o.trusted, origin=o.origin, archive=o.archive, site=o.site) for o in value.origins]
    real = [o for o in origins if o['archive'] != 'now']
    need(real and all(o['trusted'] and ((o['origin'] == 'Ubuntu' and o['archive'] in
         ('jammy', 'jammy-updates', 'jammy-security', 'jammy-backports')) or
         (o['origin'] == 'LP-PPA-ondrej-php' and o['archive'] == 'jammy' and o['site'] in PPA_HOSTS)) for o in real), 'authenticated_Jammy_candidate_required')
    if name.startswith('php8.5'):
        need(any(o['origin'] == 'LP-PPA-ondrej-php' for o in real) and '+ubuntu22.04.' in value.version,
             'existing_trusted_Jammy_PHP_PPA_required')
    need(value.architecture in ('all', host['architecture']), 'candidate_architecture_mismatch')
    need(re.fullmatch('[a-f0-9]{64}', record.get('SHA256', '')) is not None, 'candidate_archive_SHA_missing')
    need(record.get('Filename', '').startswith('pool/'), 'candidate_archive_path_invalid')
    if name in ('php8.5-cli', 'php8.5-fpm', 'php8.5-common'):
        need(value.source_name == 'php8.5' and compare(value.version.split(':')[-1].split('-')[0], FLOOR) >= 0,
             'patched_8_5_core_candidate_required')
    return dict(version=value.version, architecture=value.architecture, source=value.source_name,
                source_version=value.source_version, sha256=record['SHA256'], filename=record['Filename'], origins=real)


def compare(a, b):
    import apt_pkg
    return apt_pkg.version_compare(a, b)


def initialize_version_comparison():
    """Initialize process-local python-apt state without opening or updating a cache."""
    need(not os.environ.get('APT_CONFIG'), 'APT_CONFIG_override_forbidden')
    import apt_pkg
    apt_pkg.init()


def simulated_changes(text, before, cache, host):
    changes = {}
    for line in text.splitlines():
        need(not line.startswith(('Remv ', 'Purg ')), 'package_removal_forbidden')
        if not line.startswith('Inst '):
            continue
        match = re.match(r'^Inst ([a-z0-9][a-z0-9+.:~-]*)(?: \[([^\]]+)\])? \(([^ ]+)', line)
        need(match is not None, 'malformed_APT_plan')
        name, old, new = match.groups()
        need(NAME.fullmatch(name) is not None and not PROTECTED.match(name), 'protected_package_change')
        need(name not in changes and (name not in before or old == before[name]['version']), 'APT_old_version_mismatch')
        record = candidate(cache, name, host)
        need(record['version'] == new and (old is None or compare(new, old) >= 0), 'APT_candidate_or_downgrade_drift')
        changes[name] = dict(record, old=old or '-')
    return changes


def ppa_signature_status(output, returncode, stderr):
    """Require a pinned signature; recognize only the known missing legacy co-signature."""
    reason = 'PHP_PPA_signature_status_rejected'
    need(returncode in (0, 2), reason)
    groups = []
    for line in output.splitlines():
        fields = line.split()
        need(len(fields) >= 2 and fields[0] == '[GNUPG:]', reason)
        code, values = fields[1], fields[2:]
        if code == 'NEWSIG':
            groups.append([])
        else:
            need(groups and code in ('KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG',
                'VERIFICATION_COMPLIANCE_MODE', 'ERRSIG', 'NO_PUBKEY'), reason)
            groups[-1].append((code, values))
    need(1 <= len(groups) <= 2, reason)
    good, missing = [], []
    for group in groups:
        rows = {}
        for code, values in group:
            rows.setdefault(code, []).append(values)
        if 'ERRSIG' in rows or 'NO_PUBKEY' in rows:
            need(set(rows) == {'ERRSIG', 'NO_PUBKEY'} and len(rows['ERRSIG']) == len(rows['NO_PUBKEY']) == 1, reason)
            row = rows['ERRSIG'][0]
            need(len(row) == 7 and row[0] == PPA_LEGACY_KEY[-16:] and row[1] == '1'
                 and row[2] in ('8', '9', '10') and row[3] == '01' and row[4].isdigit()
                 and row[5] == '9' and row[6] == PPA_LEGACY_KEY
                 and rows['NO_PUBKEY'][0] == [row[0]], reason)
            missing.append(row)
            continue
        need(set(rows) <= {'KEY_CONSIDERED', 'SIG_ID', 'GOODSIG', 'VALIDSIG', 'VERIFICATION_COMPLIANCE_MODE'}
             and len(rows.get('GOODSIG', [])) == len(rows.get('VALIDSIG', [])) == 1, reason)
        row = rows['VALIDSIG'][0]
        need(len(row) in (9, 10) and re.fullmatch(r'[A-F0-9]{40}', row[0]) is not None
             and re.fullmatch(r'\d{4}-\d{2}-\d{2}', row[1]) is not None
             and row[2].isdigit() and row[3].isdigit() and row[4:7] == ['4', '0', '1']
             and row[7] in ('8', '9', '10') and row[8] == '01', reason)
        primary = row[9] if len(row) == 10 else row[0]
        need(primary in (PPA_KEY, PPA_LEGACY_KEY), 'PHP_PPA_signature_fingerprint_mismatch')
        need(rows['GOODSIG'][0] and rows['GOODSIG'][0][0] in (row[0], row[0][-16:]), reason)
        need(int(row[3]) == 0 or int(row[3]) > int(time.time()), reason)
        for considered in rows.get('KEY_CONSIDERED', []):
            need(considered == [primary, '0'], reason)
        need(len(rows.get('SIG_ID', [])) <= 1 and len(rows.get('VERIFICATION_COMPLIANCE_MODE', [])) <= 1, reason)
        for identifier in rows.get('SIG_ID', []):
            need(len(identifier) == 3 and identifier[1:] == row[1:3], reason)
        for compliance in rows.get('VERIFICATION_COMPLIANCE_MODE', []):
            need(len(compliance) == 1 and compliance[0].isdigit(), reason)
        good.append(dict(primary=primary, signer=row[0], timestamp=row[2]))
    pinned = [row for row in good if row['primary'] == PPA_KEY]
    need(len(pinned) == 1, 'PHP_PPA_signature_fingerprint_mismatch')
    need(len({row['primary'] for row in good}) == len(good), reason)
    compatibility = returncode == 2
    if compatibility:
        need(len(groups) == 2 and len(good) == len(missing) == 1
             and missing[0][4] == pinned[0]['timestamp'], reason)
    else:
        need(not missing, reason)
    # Under LC_ALL=C these are the only benign diagnostics for this bounded
    # case. Resource/packet/permission errors must never be hidden by a VALIDSIG.
    if stderr:
        counts = dict(made=0, using=0, good=0, missing=0)
        key_ids = {row['signer'] for row in good} | ({PPA_LEGACY_KEY} if missing else set())
        key_ids |= {key[-16:] for key in key_ids}
        for line in stderr.splitlines():
            if re.fullmatch(r'gpgv: Signature made .+', line):
                counts['made'] += 1
            elif re.fullmatch(r'gpgv:\s+using RSA key [A-F0-9]+', line):
                need(line.split()[-1] in key_ids, reason)
                counts['using'] += 1
            elif re.fullmatch(r'gpgv: Good signature from ".*"', line):
                counts['good'] += 1
            elif line == "gpgv: Can't check signature: No public key":
                counts['missing'] += 1
            else:
                raise Hold(reason)
        need(counts == dict(made=len(groups), using=len(groups), good=len(good), missing=len(missing)), reason)
    else:
        need(not compatibility, reason)
    return dict(primary_fingerprint=PPA_KEY, signing_fingerprint=pinned[0]['signer'],
        missing_legacy_signature=compatibility, gpgv_exit_code=returncode)


def verify_PPA_signature():
    unused, entries = _configured_sources()
    selected = []
    for entry in entries:
        if 'deb' not in entry['types']:
            continue
        for uri in entry['uris']:
            parsed = urlsplit(uri)
            if parsed.hostname not in PPA_HOSTS or parsed.path.rstrip('/') != '/ondrej/php/ubuntu':
                continue
            need(parsed.scheme in ('http', 'https') and not parsed.username and not parsed.password
                 and not parsed.query and not parsed.fragment and parsed.port is None
                 and entry['suites'] == ['jammy'] and 'deb' in entry['types']
                 and len(entry['uris']) == 1, 'ambiguous_or_non_Jammy_PHP_PPA')
            selected.append((entry, parsed))
    need(selected, 'existing_Jammy_PHP_PPA_required')
    proofs = []
    for entry, parsed in selected:
        basename = parsed.hostname + '_' + parsed.path.strip('/').replace('/', '_') + '_dists_jammy_InRelease'
        path = Path('/var/lib/apt/lists') / basename
        raw = safe_file(path)
        text = raw.decode('utf-8')
        need(re.search(r'(?m)^Origin: LP-PPA-ondrej-php\r?$', text)
             and re.search(r'(?m)^Codename: jammy\r?$', text), 'PHP_PPA_Release_identity_mismatch')
        value = entry['signed_by'].strip()
        inline = value.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----')
        paths = _key_paths(value)
        if not value or (not inline and not paths):
            paths = sorted(glob.glob('/etc/apt/trusted.gpg.d/*.gpg') + glob.glob('/etc/apt/trusted.gpg.d/*.asc'))
            if Path('/etc/apt/trusted.gpg').exists() or Path('/etc/apt/trusted.gpg').is_symlink():
                paths.append('/etc/apt/trusted.gpg')
        need(inline or paths, 'existing_PPA_keyring_missing')
        key_proofs = []
        with tempfile.TemporaryDirectory(prefix='php85-key-', dir='/run') as temporary:
            home = Path(temporary)
            materials = [(None, value.replace('\n.\n', '\n\n').encode() + b'\n')] if inline else [(key, safe_file(key)) for key in paths]
            args = ['/usr/bin/gpgv', '--homedir', str(home), '--status-fd=1']
            for index, (key, content) in enumerate(materials):
                need(len(content) <= 1024 * 1024, 'PPA_signing_key_too_large')
                key_proofs.append(dict(path=key, sha256=digest(content)))
                if content.lstrip().startswith(b'-----BEGIN PGP PUBLIC KEY BLOCK-----'):
                    source, binary = home / ('key-' + str(index) + '.asc'), home / ('key-' + str(index) + '.gpg')
                    source.write_bytes(content)
                    command(['/usr/bin/gpg', '--no-options', '--homedir', str(home), '--batch', '--dearmor', '--output', str(binary), str(source)])
                    args += ['--keyring', str(binary)]
                else:
                    binary = home / ('key-' + str(index) + '.gpg')
                    binary.write_bytes(content)
                    args += ['--keyring', str(binary)]
            # Verify the exact bytes whose SHA/Release identity are recorded.
            signed = home / 'InRelease'
            signed.write_bytes(raw)
            try:
                output = command(args + [str(signed)])
                signature = ppa_signature_status(output, 0, '')
            except Hold as error:
                if str(error) != 'command_failed_gpgv' or not hasattr(error, 'gpgv_result'):
                    raise
                result = error.gpgv_result
                try:
                    signature = ppa_signature_status(result['stdout'], result['returncode'], result['stderr'])
                except Hold as failure:
                    failure.details = error.details
                    raise
        proofs.append(dict(path=str(path), sha256=digest(raw), source_path=entry['source_path'],
                           keyrings=key_proofs, **signature))
    return proofs


def health(specs):
    for spec in specs:
        url = 'https://' + spec['host'] + spec['path']
        for hop in range(4):
            parsed = urlsplit(url)
            need(parsed.scheme == 'https' and parsed.hostname in spec['aliases'] and parsed.port in (None, 443)
                 and parsed.username is None and parsed.password is None, 'health_redirect_outside_local_aliases')
            args = ['/usr/bin/curl', '--disable', '--noproxy', '*', '--silent', '--show-error',
                    '--connect-timeout', '5', '--max-time', '20', '--proto', '=https',
                    '--resolve', parsed.hostname + ':443:127.0.0.1', '--output', '/dev/null',
                    '--dump-header', '-', '--write-out', '\nPHP85-CODE:%{http_code}', url]
            result = command(args, 25)
            headers, marker, code = result.rpartition('\nPHP85-CODE:')
            need(marker, 'health_HTTP_status_missing')
            if code == '200':
                break
            need(code in ('301', '302', '303', '307', '308') and hop < 3, 'application_health_failed')
            locations = re.findall(r'(?mi)^location:\s*([^\r\n]+)', headers)
            need(len(locations) == 1, 'ambiguous_health_redirect')
            url = urljoin(url, locations[0])


def inspect(adopt_vendor_socket=False):
    validate_apt_security()
    import apt
    import apt_pkg
    apt_pkg.init()
    for option in ('APT::Get::AllowUnauthenticated', 'Acquire::AllowInsecureRepositories',
                   'Acquire::AllowWeakRepositories', 'Acquire::AllowDowngradeToInsecureRepositories'):
        need(not apt_pkg.config.find_b(option, False), 'APT_authentication_override')
    host, before, sources = identity(), packages(), source_files()
    command(['/usr/sbin/nginx', '-t'])
    command(['/bin/systemctl', 'is-active', '--quiet', 'nginx.service'])
    nginx = nginx_inventory()
    dumped = command(['/usr/sbin/nginx', '-T'])
    observed = {os.path.normpath(path) for path in re.findall(r'^# configuration file (/.+):$', dumped, re.M)}
    need(observed == {os.path.normpath(path) for path in nginx['files']}, 'Nginx_include_graph_mismatch')
    found = []
    pool_sets = {}
    for branch in ('7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4', '8.5'):
        paths = sorted(glob.glob('/etc/php/' + branch + '/fpm/pool.d/*.conf'))
        if not paths or 'php' + branch + '-fpm' not in before:
            continue
        texts = {p: safe_file(p).decode() for p in paths}
        parsed = parse_pools(texts)
        if any(route['socket'] in {p['listen'] for p in parsed.values()} for route in nginx['routes']):
            found.append(branch)
            pool_sets[branch] = (texts, parsed)
    need(len(found) == 1, 'single_active_PHP_branch_required')
    branch = found[0]
    need(all('php' + branch + '-' + suffix in before for suffix in ('cli', 'common', 'fpm')), 'installed_CLI_common_FPM_required')
    need(not any(name.startswith('libapache2-mod-php') or re.match(r'^php[0-9.]+-(?:cgi|phpdbg)$', name) for name in before), 'Apache_CGI_separate_profile_required')
    command(['/bin/systemctl', 'is-active', '--quiet', 'php' + branch + '-fpm.service'])
    unit_path = validate_native_unit(branch, True)
    source_enabled = unit_enabled(branch)
    profile_files = {}
    for sapi in ('cli', 'fpm'):
        paths = ['/etc/php/' + branch + '/' + sapi + '/php.ini']
        paths += sorted(glob.glob('/etc/php/' + branch + '/' + sapi + '/conf.d/*.ini'))
        profile_files[sapi] = {path: safe_file(path).decode() for path in paths}
        executable_INI_guard(profile_files[sapi])
    validate_loaders(branch, profile_files, before)
    cli = registry(branch)
    need(Path('/usr/bin/php').resolve() == Path('/usr/bin/php' + branch).resolve(), 'CLI_and_web_PHP_branch_diverge')
    if branch != TARGET:
        need(not any(name.startswith('php8.5-') for name in before), 'existing_dormant_target_requires_review')
    texts, parsed = pool_sets[branch]
    need(1 <= len(parsed) <= 32, 'pool_count_limit')
    sockets = {row['listen'] for row in parsed.values()}
    need({row['socket'] for row in nginx['routes']} <= sockets, 'unowned_PHP_socket_route')
    mapping = {value: (value if branch == TARGET else '/run/php/php8.5-fpm.sock'
              if value == '/run/php/php' + branch + '-fpm.sock' else
              '/run/php/php8.5-' + digest(value.encode())[:12] + '.sock') for value in sockets}
    config_paths = set(nginx['files']) | set(texts)
    config_paths.add(unit_path)
    config_paths.add('/etc/php/' + branch + '/fpm/php-fpm.conf')
    config_paths.update(path for paths in profile_files.values() for path in paths)
    global_config = safe_file('/etc/php/' + branch + '/fpm/php-fpm.conf').decode()
    includes = re.findall(r'(?m)^\s*include\s*=\s*(.*?)\s*$', global_config)
    need(includes == ['/etc/php/' + branch + '/fpm/pool.d/*.conf'], 'standard_pool_include_required')
    target_global = global_FPM_output(global_config, branch)
    source_registry = registry(branch, True)
    cache = apt.Cache()
    targets = {'php8.5-cli', 'php8.5-common', 'php8.5-fpm'}
    skipped = []
    for name in before:
        if name == 'php' + branch or name.startswith('php' + branch + '-'):
            suffix = name[len('php' + branch):]
            if suffix in ('-json', '-opcache'):
                skipped.append(name)
            else:
                targets.add('php8.5' + suffix)
    records = {name: candidate(cache, name, host) for name in sorted(targets)}
    pins = [name + '=' + record['version'] for name, record in sorted(records.items())]
    text = command(['/usr/bin/apt-get', '--simulate', '--no-remove', '--no-install-recommends', 'install'] + pins, 120)
    changes = simulated_changes(text, before, cache, host)
    snapshot = files_snapshot(config_paths)
    captured_text = dict(nginx['files'], **texts)
    for entries in profile_files.values():
        captured_text.update(entries)
    captured_text['/etc/php/' + branch + '/fpm/php-fpm.conf'] = global_config
    need(all(digest(text.encode()) == snapshot[path]['sha256'] for path, text in captured_text.items()),
         'configuration_changed_during_discovery')
    plan = dict(schema=1, version=VERSION, adopt_vendor_socket=adopt_vendor_socket, code_sha256=digest(Path(__file__).read_bytes()), host=host,
        source_branch=branch, mode='patch' if branch == TARGET else 'migration', packages=before, sources=sources,
        files=snapshot, nginx=nginx, pools=texts, parsed_pools=parsed, socket_map=mapping,
        source_registry=source_registry, source_CLI_registry=cli, INI_files=profile_files, source_enabled=source_enabled,
        target_global_FPM=target_global, target_records=records, pins=pins, changes=changes,
        builtin_mappings=skipped, PPA_signature=verify_PPA_signature())
    health(nginx['health'])
    return plan


def current_snapshot(plan):
    need(identity() == plan['host'], 'host_identity_changed')
    need(source_files() == plan['sources'], 'APT_sources_changed')
    need(files_snapshot(plan['files']) == plan['files'], 'configuration_changed')
    need(packages() == plan['packages'], 'package_inventory_changed')


def hook(path):
    plan = json.loads(safe_file(path, True))
    need(digest(Path(__file__).read_bytes()) == plan['code_sha256'], 'hook_code_changed')
    need(identity() == plan['host'] and source_files() == plan['sources'], 'hook_host_or_sources_changed')
    now = {}
    raw = command(['/usr/bin/dpkg-query', '-W', '-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'])
    for line in raw.splitlines():
        name, version, architecture, status = line.split('\t')
        if status.startswith(('ii', 'iU', 'iF', 'iH', 'iW', 'it')):
            need(name not in now, 'multiarch_under_APT_lock')
            now[name] = dict(version=version, architecture=architecture, status=status[:2])
    need(set(now) <= set(plan['packages']) | set(plan['changes']), 'unplanned_package_under_APT_lock')
    for name, baseline in plan['packages'].items():
        row = now.get(name)
        if name not in plan['changes']:
            need(row == dict(baseline, status='ii'), 'untouched_package_drift_under_APT_lock')
    for name, change in plan['changes'].items():
        row = now.get(name)
        need((row is None and change['old'] == '-') or
             (row is not None and row['version'] in (change['old'], change['version']) and row['architecture'] == change['architecture']),
             'planned_package_drift_under_APT_lock')
    text = sys.stdin.read(4 * 1024 * 1024 + 1)
    need(len(text) <= 4 * 1024 * 1024, 'APT_hook_too_large')
    header, sep, body = text.partition('\n\n')
    need(sep and header.splitlines()[0] == 'VERSION 2', 'APT_v2_hook_required')
    observed, configured = set(), set()
    for line in body.splitlines():
        if not line:
            continue
        fields = line.split()
        need(len(fields) == 5, 'bad_APT_hook_action')
        name, old, direction, new, action = fields
        need(name in plan['changes'] and not PROTECTED.match(name), 'unplanned_APT_action')
        record = plan['changes'][name]
        need(old == record['old'] and new == record['version'] and direction in ('<', '='), 'APT_versions_changed')
        need(action != '**REMOVE**', 'APT_removal_forbidden')
        if action == '**CONFIGURE**':
            need(name not in configured, 'duplicate_APT_configure_action')
            configured.add(name)
            continue
        need(re.fullmatch(r'/var/cache/apt/archives/[A-Za-z0-9%+_.:~=-]+\.deb', action) is not None,
             'unsafe_APT_archive_path')
        raw = safe_file(action)
        need(digest(raw) == record['sha256'] and name not in observed, 'APT_archive_digest_mismatch')
        identity_text = command(['/usr/bin/dpkg-deb', '-f', action, 'Package', 'Version', 'Architecture'])
        actual = dict(row.split(': ', 1) for row in identity_text.splitlines())
        need(actual == dict(Package=name, Version=new, Architecture=record['architecture']), 'APT_archive_identity_mismatch')
        observed.add(name)
    need(observed == set(plan['changes']), 'actual_APT_transaction_changed')
    atomic(Path(path).parent / 'hook-accepted.json', encoded(dict(plan_sha256=digest(safe_file(path, True)), accepted=True)))


class Journal:
    def __init__(self, directory, plan=None):
        self.directory = directory
        self.previous = '0' * 64
        self.plan = plan
        if (directory / 'events.jsonl').exists():
            for raw in safe_file(directory / 'events.jsonl', True).splitlines(keepends=True):
                need(json.loads(raw)['previous_sha256'] == self.previous, 'event_chain_changed')
                self.previous = digest(raw)

    def phase(self, phase, **fields):
        row = dict(time=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), phase=phase,
                   previous_sha256=self.previous, **fields)
        raw = encoded(row)
        with (self.directory / 'events.jsonl').open('ab') as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        self.previous = digest(raw)
        atomic(BASE / 'current.json', encoded(dict(version=VERSION, job=str(self.directory),
               phase=phase, event_sha256=self.previous, **fields)))
        print(json.dumps(dict(phase=phase, **fields)), flush=True)


def fpm_ready(sockets):
    validate_native_unit(TARGET, True)
    command(['/bin/systemctl', 'is-active', '--quiet', 'php8.5-fpm.service'])
    pid = command(['/bin/systemctl', 'show', '-p', 'MainPID', '--value', 'php8.5-fpm.service']).strip()
    need(pid.isdigit() and int(pid) > 1, 'target_master_PID_missing')
    expected, actual = Path('/usr/sbin/php-fpm8.5').stat(), Path('/proc/' + pid + '/exe').stat()
    need((actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino), 'target_executable_stale')
    for value in sockets:
        need(Path(value).exists() and stat.S_ISSOCK(Path(value).stat().st_mode), 'target_socket_missing')
    directory = registry(TARGET, True)['directory']
    for attempt in range(3):
        try:
            return RUNTIME['prove_pool'](list(sockets), int(pid), directory)
        except FileNotFoundError as error:
            if not str(error.filename).startswith('/proc/') or attempt == 2:
                raise Hold('runtime_proof_missing_file')
        except RUNTIME['ProofError'] as error:
            if str(error) not in ('FPM_lifecycle_incomplete', 'FPM_process_changed_during_proof') or attempt == 2:
                raise Hold('runtime_proof_' + str(error))
        time.sleep(0.1)


def apt_options():
    return ['-o', 'Acquire::Retries=0', '-o', 'Acquire::http::Timeout=15', '-o', 'Acquire::https::Timeout=15',
            '-o', 'DPkg::Lock::Timeout=60', '-o', 'APT::Get::AllowUnauthenticated=false']


def package_locks():
    """Bounded wait for native APT POSIX locks; never signal another installer."""
    deadline = time.monotonic() + 60
    paths = ('/var/lib/apt/lists/lock', '/var/cache/apt/archives/lock',
             '/var/lib/dpkg/lock-frontend', '/var/lib/dpkg/lock')
    while True:
        held = []
        try:
            for path in paths:
                fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC)
                held.append(fd)
                info = os.fstat(fd)
                need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1, 'unsafe_APT_lock_file')
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return held
        except BlockingIOError:
            for fd in reversed(held):
                os.close(fd)
            need(time.monotonic() < deadline, 'another_APT_writer_is_busy_no_process_killed')
            time.sleep(1)
        except BaseException:
            for fd in reversed(held):
                os.close(fd)
            raise


def shared_lock():
    directory = Path('/run/ubuntu-php-updater')
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077, 'unsafe_shared_lock_directory')
    fd = os.open(directory / 'worker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and not info.st_mode & 0o077, 'unsafe_shared_lock_file')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise Hold('another_PHP_or_global_updater_is_running')
    return fd


def verify_preflight_archive_journals():
    for path in BASE.glob('preflight-recovery-*.json'):
        receipt = json.loads(safe_file(path, True))
        need(receipt.get('schema') == 1 and receipt.get('phase') == 'complete', 'unfinished_preflight_archive_preserved')
        archive = Path(receipt.get('archive', ''))
        need(archive.parent == BASE and archive.name.startswith('archived-preflight-job-'), 'invalid_preflight_archive_path')
        need(digest(safe_file(archive, True)) == receipt['original_current_sha256'], 'preflight_archive_changed')


def recover_v100_preflight(previous):
    """Archive only byte-identified releases' exact early Nginx rejections."""
    cases = {
        '1.0.0': (PREFLIGHT_V100_SHA256, 'nginx_path_outside_config', False),
        '1.0.1': (PREFLIGHT_V101_SHA256, 'absolute_nginx_include_required', True),
        '1.0.2': (PREFLIGHT_V102_SHA256, 'Nginx_alias_requires_separate_health_profile', True),
        '1.0.3': (PREFLIGHT_V103_SHA256, 'unsafe_file_parent', True),
        '1.0.4': (PREFLIGHT_V104_SHA256, 'command_failed_gpgv', True),
    }
    need(previous.get('version') in cases, 'previous_job_preserved_use_status')
    code_sha, reason, has_details = cases[previous['version']]
    fields = {'version', 'job', 'phase', 'event_sha256', 'reason', 'recovery'}
    if has_details:
        fields.add('details')
    need(set(previous) == fields and previous.get('phase') == 'failed_needs_review'
         and previous.get('reason') == reason
         and (not has_details or (previous['details'] == {} and previous['recovery'] is None)),
         'previous_job_preserved_use_status')
    job = Path(previous.get('job', ''))
    need(job.parent == BASE and re.fullmatch(r'job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', job.name), 'unrecognized_preflight_job')
    info = job.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077 and not job.is_symlink(), 'unsafe_preflight_job')
    need({p.name for p in job.iterdir()} == {'php85_upgrade.py', 'events.jsonl', 'timers.json'}, 'preflight_has_unrecognized_work_artifacts')
    raw_current = safe_file(BASE / 'current.json', True)
    need(json.loads(raw_current) == previous, 'preflight_current_changed')
    old_files = {p.name: digest(safe_file(p, True)) for p in job.iterdir()}
    need(old_files['php85_upgrade.py'] == code_sha, 'unrecognized_preflight_code')
    raw_events = safe_file(job / 'events.jsonl', True).splitlines(keepends=True)
    need(len(raw_events) == 3, 'preflight_journal_has_other_stages')
    events, last = [], '0' * 64
    for raw in raw_events:
        row = json.loads(raw)
        need(row.get('previous_sha256') == last, 'preflight_event_chain_changed')
        events.append(row)
        last = digest(raw)
    need([row.get('phase') for row in events] == ['preflight', 'refreshing_indexes', 'failed_needs_review']
         and events[-1].get('reason') == reason
         and events[-1].get('recovery') == (None if has_details else str(job / 'recovery.json'))
         and (not has_details or events[-1].get('details') == {})
         and previous.get('event_sha256') == last
         and previous.get('recovery') == events[-1]['recovery'], 'preflight_stage_or_current_mismatch')
    event_fields = {'time', 'phase', 'previous_sha256', 'reason', 'recovery'}
    if has_details:
        event_fields.add('details')
    need(set(events[0]) == set(events[1]) == {'time', 'phase', 'previous_sha256'}
         and set(events[-1]) == event_fields, 'unexpected_preflight_event_fields')
    timers = json.loads(safe_file(job / 'timers.json', True))
    need(isinstance(timers, list) and len(set(timers)) == len(timers)
         and set(timers) <= {'apt-daily.timer', 'apt-daily-upgrade.timer'}, 'preflight_timer_receipt_invalid')
    for timer in ('apt-daily.timer', 'apt-daily-upgrade.timer'):
        observed = subprocess.run(['/bin/systemctl', 'is-active', '--quiet', timer],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        need(observed.returncode in (0, 3, 4) and (observed.returncode == 0) == (timer in timers),
             'preflight_timers_not_restored')
    need(not Path('/usr/sbin/policy-rc.d').exists(), 'preflight_service_policy_present')
    archive = BASE / ('archived-preflight-' + job.name + '.json')
    receipt_path = BASE / ('preflight-recovery-' + job.name + '.json')
    need(not archive.exists() and not receipt_path.exists(), 'existing_preflight_archive_preserved')
    # These releases did not persist identity before their early rejections. New apply
    # seals a fresh plan bound to the current machine; no old package plan is reused.
    receipt = dict(schema=1, phase='started', job=str(job), archive=str(archive),
                   original_current_sha256=digest(raw_current), old_files=old_files,
                   current_host=identity(), historical_host_binding='not_persisted_in_v' + previous['version'].replace('.', '_') + '_preflight',
                   old_PHP_package_stage_started=False, prior_index_refresh_possible=True)
    atomic(receipt_path, encoded(receipt))
    need(safe_file(BASE / 'current.json', True) == raw_current, 'preflight_current_changed_before_archive')
    (BASE / 'current.json').rename(archive)
    directory = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    need({p.name: digest(safe_file(p, True)) for p in job.iterdir()} == old_files, 'old_preflight_evidence_changed')
    receipt['phase'] = 'complete'
    atomic(receipt_path, encoded(receipt))
    print(json.dumps(dict(phase='recognized_preflight_archived', old_job=str(job), archive=str(archive))), flush=True)


def _preinstall_object(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate_preinstall_JSON_key')
        result[key] = value
    return result


def _preinstall_json(path):
    return json.loads(safe_file(path, True), object_pairs_hook=_preinstall_object)


def _preinstall_job(job):
    need(job.parent == BASE and re.fullmatch(r'job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', job.name),
         'invalid_preinstall_job_path')
    info = job.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700
         and not job.is_symlink(), 'unsafe_preinstall_job')


def _preinstall_inventory(job):
    return {path.name: digest(safe_file(path, True)) for path in sorted(job.iterdir())}


def _preinstall_fields(raw):
    result = {}
    for field in ('Name', 'Status', 'Value', 'Best'):
        rows = re.findall(r'^' + field + r': (.+)$', raw, re.M)
        need(len(rows) == 1, 'preinstall_alternative_query_incomplete')
        result[field] = rows[0]
    return result


def _preinstall_selectors(values, modes, restored=False):
    allowed = {'php', 'phar', 'phar.phar', 'phpize', 'php-config'}
    need(isinstance(values, dict) and isinstance(modes, dict) and set(values) == set(modes)
         and 'php' in values and set(values) <= allowed, 'invalid_preinstall_alternative_receipts')
    selections = {}
    for line in command(['/usr/bin/update-alternatives', '--get-selections']).splitlines():
        fields = line.split()
        if fields and fields[0] in allowed:
            need(len(fields) == 3 and fields[0] not in selections, 'preinstall_alternative_inventory_changed')
            selections[fields[0]] = fields[1:]
    need(set(selections) == set(values), 'preinstall_alternative_set_changed')
    proof = {}
    for name in sorted(values):
        value, mode = values[name], modes[name]
        need(isinstance(value, str) and value.startswith('/') and '..' not in value.split('/')
             and not any(ord(c) < 32 or ord(c) == 127 for c in value)
             and mode in ('auto', 'manual'), 'invalid_preinstall_alternative_receipt')
        row = _preinstall_fields(command(['/usr/bin/update-alternatives', '--query', name]))
        expected_mode = mode if restored else 'manual'
        need(row['Name'] == name and row['Value'] == value and row['Status'] == expected_mode
             and selections[name] == [expected_mode, value], 'preinstall_alternative_selection_drift')
        if mode == 'auto':
            need(row['Best'] == value, 'preinstall_automatic_Best_changed')
        proof[name] = row
    return proof


def _preinstall_timers(timers):
    need(isinstance(timers, list) and all(isinstance(name, str) for name in timers)
         and len(set(timers)) == len(timers)
         and set(timers) <= {'apt-daily.timer', 'apt-daily-upgrade.timer'}, 'invalid_preinstall_timer_receipt')
    for timer in ('apt-daily.timer', 'apt-daily-upgrade.timer'):
        state = command(['/bin/systemctl', 'show', timer, '-p', 'ActiveState', '--value']).strip()
        need(state in ('active', 'inactive') and (state == 'active') == (timer in timers),
             'preinstall_timers_not_restored')


def _preinstall_runtime(branch):
    unit = 'php' + branch + '-fpm.service'
    command(['/bin/systemctl', 'is-active', '--quiet', unit])
    pid = command(['/bin/systemctl', 'show', unit, '-p', 'MainPID', '--value']).strip()
    need(pid.isdigit() and int(pid) > 1, 'preinstall_original_FPM_master_missing')
    process = Path('/proc') / pid
    def start():
        with (process / 'stat').open('rb') as stream:
            raw = stream.read(65537)
        need(len(raw) <= 65536, 'preinstall_FPM_stat_bound')
        fields = raw.decode().rsplit(')', 1)[1].split()
        need(len(fields) >= 20 and fields[0] not in ('Z', 'X', 'x') and fields[19].isdigit(),
             'preinstall_original_FPM_not_live')
        return fields[19]
    before = start()
    expected = Path('/usr/sbin/php-fpm' + branch)
    disk, live = expected.stat(), (process / 'exe').stat()
    need(os.readlink(process / 'exe') == str(expected)
         and stat.S_ISREG(disk.st_mode) and disk.st_uid == 0 and not disk.st_mode & 0o022
         and (disk.st_dev, disk.st_ino) == (live.st_dev, live.st_ino)
         and start() == before
         and command(['/bin/systemctl', 'show', unit, '-p', 'MainPID', '--value']).strip() == pid,
         'preinstall_original_FPM_identity_changed')
    return dict(master_pid=int(pid), start_time_ticks=before, current_native_executable=True)


def _preinstall_baseline(plan, timers):
    need(identity() == plan['host'], 'preinstall_host_changed')
    need(source_files() == plan['sources'], 'preinstall_sources_or_keys_changed')
    need(files_snapshot(plan['files']) == plan['files'], 'preinstall_configuration_changed')
    need(packages() == plan['packages'], 'preinstall_package_baseline_changed')
    installed = {}
    raw = command(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'])
    for line in raw.splitlines():
        fields = line.split('\t')
        need(len(fields) == 4, 'preinstall_package_query_malformed')
        name, version, architecture, status = fields
        if ':' in name:
            name, suffix = name.rsplit(':', 1)
            need(suffix == architecture, 'preinstall_package_architecture_suffix_mismatch')
        need(re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', name), 'preinstall_package_name_malformed')
        status = status.strip()
        if status.startswith('rc') or status in ('un', 'pn'):
            continue
        need(status == 'ii' and name not in installed, 'preinstall_package_status_not_clean_ii')
        installed[name] = dict(version=version, architecture=architecture)
    need(installed == plan['packages'], 'preinstall_full_installed_table_changed')
    branch = plan['source_branch']
    need(Path('/usr/bin/php').resolve() == Path('/usr/bin/php' + branch).resolve(),
         'preinstall_default_CLI_branch_changed')
    validate_loaders(branch, plan['INI_files'], plan['packages'])
    need(registry(branch) == plan['source_CLI_registry'], 'preinstall_original_CLI_registry_changed')
    need(not Path('/usr/sbin/policy-rc.d').exists() and not Path('/usr/sbin/policy-rc.d').is_symlink(),
         'preinstall_service_policy_present')
    source_unit = validate_native_unit(branch, True)
    need(source_unit in plan['files'] and unit_enabled(branch) is plan['source_enabled'],
         'preinstall_original_FPM_unit_or_enablement_changed')
    proof = _preinstall_runtime(branch)
    _preinstall_timers(timers)
    health(plan['nginx']['health'])
    return proof


def verify_preinstall_recovery_journals():
    """Run before any new apply, including when current.json is absent."""
    for path in BASE.glob('preinstall-recovery-*.json'):
        receipt = _preinstall_json(path)
        need(receipt.get('schema') == 1 and receipt.get('phase') == 'complete',
             'unfinished_preinstall_recovery_preserved')
        job, archive = Path(receipt.get('job', '')), Path(receipt.get('archive', ''))
        _preinstall_job(job)
        need(path.name == 'preinstall-recovery-' + job.name + '.json'
             and archive == BASE / ('archived-preinstall-' + job.name + '.json'), 'invalid_preinstall_archive_path')
        need(digest(safe_file(archive, True)) == receipt['original_current_sha256']
             and _preinstall_inventory(job) == receipt['old_files'], 'preinstall_archived_evidence_changed')


def recover_v105_preinstall(previous):
    """Archive only proven zero-package-effect v1.0.5 hook-transport failure."""
    need(set(previous) == {'version', 'job', 'phase', 'event_sha256', 'reason', 'details', 'recovery'}
         and previous['version'] == '1.0.5' and previous['phase'] == 'failed_needs_review'
         and previous['reason'] == 'command_failed_apt-get' and previous['details'] == {},
         'previous_install_job_requires_review')
    job = Path(previous['job'])
    _preinstall_job(job)
    need(previous['recovery'] == str(job / 'recovery.json'), 'unexpected_preinstall_recovery_pointer')
    raw_current = safe_file(BASE / 'current.json', True)
    need(_preinstall_json(BASE / 'current.json') == previous, 'preinstall_current_changed')
    plan_raw = safe_file(job / 'plan.json', True)
    plan = _preinstall_json(job / 'plan.json')
    need(plan.get('schema') == 1 and plan.get('version') == '1.0.5'
         and plan.get('code_sha256') == PREINSTALL_V105_SHA256
         and digest(safe_file(job / 'php85_upgrade.py', True)) == PREINSTALL_V105_SHA256,
         'unrecognized_preinstall_source_or_plan')
    seal = safe_file(job / 'plan.sha256', True).decode()
    need(plan_raw == encoded(plan) and seal == digest(plan_raw) + '\n', 'preinstall_plan_seal_changed')
    branch = plan.get('source_branch', '')
    need(re.fullmatch(r'7\.[234]|8\.[0-5]', branch) and plan.get('mode') == ('patch' if branch == '8.5' else 'migration')
         and isinstance(plan.get('changes'), dict) and plan['changes'], 'unexpected_preinstall_plan_mode')
    expected_names = {'php85_upgrade.py', 'events.jsonl', 'timers.json', 'plan.json', 'plan.sha256',
                      'recovery.json', 'alternatives.json', 'alternative-modes.json'}
    expected_names.update('configuration-' + str(index) for index in range(len(plan['files'])))
    need({path.name for path in job.iterdir()} == expected_names, 'preinstall_has_other_work_artifacts')
    old_files = _preinstall_inventory(job)
    for index, (path, row) in enumerate(sorted(plan['files'].items())):
        need(digest(safe_file(job / ('configuration-' + str(index)), True)) == row['sha256'],
             'preinstall_configuration_backup_changed')
    recovery = _preinstall_json(job / 'recovery.json')
    need(set(recovery) == {'files', 'old_service', 'old_cli'} and recovery['files'] == plan['files']
         and recovery['old_service'] == 'php' + branch + '-fpm.service', 'preinstall_recovery_receipt_changed')
    values, modes = _preinstall_json(job / 'alternatives.json'), _preinstall_json(job / 'alternative-modes.json')
    old_cli = _preinstall_fields(recovery['old_cli'])
    need(old_cli['Name'] == 'php' and old_cli['Value'] == values.get('php')
         and old_cli['Status'] == modes.get('php'), 'preinstall_original_CLI_receipts_disagree')
    events, last = [], '0' * 64
    raw_events = safe_file(job / 'events.jsonl', True).splitlines(keepends=True)
    need(len(raw_events) == 6, 'unexpected_preinstall_journal_length')
    for raw in raw_events:
        row = json.loads(raw, object_pairs_hook=_preinstall_object)
        need(row.get('previous_sha256') == last and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', row.get('time', '')),
             'preinstall_event_chain_changed')
        events.append(row)
        last = digest(raw)
    need([row['phase'] for row in events] == ['preflight', 'refreshing_indexes', 'plan_sealed',
         'downloading_packages', 'installing_packages', 'failed_needs_review'], 'unexpected_preinstall_stages')
    common = {'time', 'phase', 'previous_sha256'}
    need(all(set(events[index]) == common for index in (0, 1, 3, 4))
         and set(events[2]) == common | {'source', 'target', 'changed_packages', 'plan_sha256'}
         and events[2]['source'] == branch and events[2]['target'] == '8.5'
         and events[2]['changed_packages'] == sorted(plan['changes']) and events[2]['plan_sha256'] == digest(plan_raw)
         and set(events[5]) == common | {'reason', 'details', 'recovery'}
         and all(events[5][key] == previous[key] for key in ('reason', 'details', 'recovery'))
         and previous['event_sha256'] == last, 'preinstall_event_or_current_mismatch')
    archive = BASE / ('archived-preinstall-' + job.name + '.json')
    receipt_path = BASE / ('preinstall-recovery-' + job.name + '.json')
    need(not archive.exists() and not archive.is_symlink() and not receipt_path.exists()
         and not receipt_path.is_symlink(), 'existing_preinstall_recovery_preserved')
    shared, held = None, []
    try:
        shared = shared_lock()
        held = package_locks()
        timers = _preinstall_json(job / 'timers.json')
        runtime_before = _preinstall_baseline(plan, timers)
        selectors = _preinstall_selectors(values, modes)
        need(_preinstall_inventory(job) == old_files and safe_file(BASE / 'current.json', True) == raw_current,
             'preinstall_evidence_changed_before_recovery')
        restore = [dict(name=name, value=values[name], original_mode=modes[name]) for name in sorted(values)]
        receipt = dict(schema=1, phase='started', time=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            job=str(job), archive=str(archive), old_files=old_files, original_current_sha256=digest(raw_current),
            original_source_sha256=PREINSTALL_V105_SHA256, plan_sha256=digest(plan_raw), restore_alternatives=restore,
            cause_basis='confirmed_v105_hook_transport_defect_and_unchanged_baseline',
            prior_index_refresh_possible=True, old_APT_stderr_not_preserved=True,
            package_actions=0, service_actions=0, runtime_before=runtime_before)
        atomic(receipt_path, encoded(receipt))
        for name in sorted(values):
            if modes[name] == 'auto':
                command(['/usr/bin/update-alternatives', '--auto', name])
        _preinstall_selectors(values, modes, restored=True)
        receipt['runtime_after'] = _preinstall_baseline(plan, timers)
        need(_preinstall_inventory(job) == old_files and safe_file(BASE / 'current.json', True) == raw_current,
             'preinstall_baseline_or_evidence_changed_after_restore')
        (BASE / 'current.json').rename(archive)
        fd = os.open(BASE, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        need(digest(safe_file(archive, True)) == receipt['original_current_sha256'], 'preinstall_archive_changed')
        receipt['phase'] = 'complete'
        receipt['completed_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        atomic(receipt_path, encoded(receipt))
        return dict(phase='recognized_v105_preinstall_failure_archived', old_job=str(job), archive=str(archive),
                    package_actions=0, service_actions=0)
    finally:
        for fd in reversed(held):
            os.close(fd)
        if shared is not None:
            os.close(shared)


def rollback():
    """Operator-requested route/CLI recovery only; never reverse package installs."""
    need(os.geteuid() == 0, 'root_required')
    with (BASE / 'maintenance.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = json.loads(safe_file(BASE / 'current.json', True))
        job = Path(current['job'])
        need(job.parent == BASE and not job.is_symlink(), 'invalid_recovery_job')
        plan = json.loads(safe_file(job / 'plan.json', True))
        need(digest(encoded(plan)) == safe_file(job / 'plan.sha256', True).decode().strip(), 'recovery_plan_changed')
        # Older readers rejected every parent alias and omitted this field. Use
        # an in-memory comparison view only; never rewrite the sealed old plan.
        original_files = {path: dict(row, parent_aliases=row.get('parent_aliases', []))
                          for path, row in plan['files'].items()}
        host = identity()
        need(all(host[key] == plan['host'][key] for key in ('machine_id', 'release', 'architecture')), 'recovery_host_mismatch')
        need(plan['mode'] == 'migration', 'same_branch_packages_require_external_recovery_no_downgrade')
        shared = shared_lock()
        held = []
        journal = Journal(job)
        try:
            held = package_locks()
            installed = packages()
            for name, record in plan['packages'].items():
                if name == 'php' + plan['source_branch'] or name.startswith('php' + plan['source_branch'] + '-'):
                    need(installed.get(name) == record, 'original_PHP_packages_changed_cannot_restore')
            old_configs = {path: row for path, row in original_files.items() if path.startswith('/etc/php/')}
            need(files_snapshot(old_configs) == old_configs, 'original_PHP_configuration_changed')
            source_unit = validate_native_unit(plan['source_branch'])
            need(source_unit in original_files and files_snapshot([source_unit])[source_unit] == original_files[source_unit],
                 'original_FPM_unit_changed')
            edits = json.loads(safe_file(job / 'owned-Nginx-edits.json', True)) if (job / 'owned-Nginx-edits.json').exists() else {}
            for path, new_sha in edits.items():
                need(path in plan['files'], 'unowned_recovery_path')
                before = original_files[path]
                observed = files_snapshot([path])[path]
                need(all(observed[key] == before[key] for key in ('link', 'resolved', 'uid', 'gid', 'mode'))
                     and observed.get('parent_aliases', []) == before.get('parent_aliases', []),
                     'recovery_path_metadata_changed')
                need(observed['sha256'] in (new_sha, before['sha256']), 'configuration_changed_after_cutover')
            command(['/usr/sbin/php-fpm' + plan['source_branch'], '-t'])
            command(['/bin/systemctl', 'start', 'php' + plan['source_branch'] + '-fpm.service'])
            journal.phase('operator_rollback_routes')
            for path, new_sha in edits.items():
                index = sorted(plan['files']).index(path)
                raw = safe_file(job / ('configuration-' + str(index)), True)
                before = plan['files'][path]
                need(digest(raw) == before['sha256'], 'recovery_backup_changed')
                atomic(Path(path).resolve(), raw, before['mode'])
                os.chown(Path(path).resolve(), before['uid'], before['gid'])
            command(['/usr/sbin/nginx', '-t'])
            command(['/bin/systemctl', 'reload', 'nginx.service'])
            alternatives = json.loads(safe_file(job / 'alternatives.json', True)) if (job / 'alternatives.json').exists() else {}
            for name, value in alternatives.items():
                need(name in ('php', 'phar', 'phar.phar', 'phpize', 'php-config') and value.startswith('/usr/bin/'), 'invalid_recovery_alternative')
                command(['/usr/bin/update-alternatives', '--set', name, value])
            time.sleep(2)
            health(plan['nginx']['health'])
            journal.phase('rolled_back', packages_retained=True)
        except BaseException as error:
            journal.phase('rollback_failed_needs_review', reason=str(error) if isinstance(error, Hold) else type(error).__name__)
            raise
        finally:
            for fd in reversed(held):
                os.close(fd)
            os.close(shared)


CONTINUATION_V106_SHA256 = '09ea4c451a7bcd5aa4248aded6e5dabefae1b54c602f3dd49ed02ad73245d80f'


def installed_package_INI(package, path):
    """Verify a directly packaged module INI against dpkg's installed inventory.

    Package/version/archive authentication remains the sealed plan's separate gate.
    Conffiles are normally absent from the package md5sums control file.
    """
    need(NAME.fullmatch(package) is not None and package.startswith('php8.5-'), 'invalid_module_INI_package')
    logical = Path(path)
    need(re.fullmatch(r'/etc/php/8\.5/mods-available/[A-Za-z0-9_-]+\.ini', str(logical))
         and not logical.is_symlink() and logical.resolve(strict=True) == logical,
         'noncanonical_packaged_module_INI')
    raw = safe_file(logical)
    records = []
    for line in command(['/usr/bin/dpkg-query', '-W', '-f=${Conffiles}\\n', package]).splitlines():
        fields = line.split()
        if fields and fields[0] == str(logical):
            records.append(fields)
    if records:
        need(len(records) == 1 and len(records[0]) == 2
             and re.fullmatch(r'[0-9a-f]{32}', records[0][1]), 'ambiguous_or_obsolete_module_INI_conffile')
        need(hashlib.md5(raw, usedforsecurity=False).hexdigest() == records[0][1],
             'packaged_module_INI_modified_requires_review')
    else:
        installed_vendor_file(package, str(logical))
    need(safe_file(logical) == raw, 'packaged_module_INI_changed_during_verification')
    return raw


def _configuration_vendor_profiles(profiles, after):
    """Admit only freshly installed, package-proven default target INI bytes."""
    inventory = {}
    for package in sorted(after):
        if package.startswith('php8.5-'):
            paths = command(['/usr/bin/dpkg-query', '-L', package]).splitlines()
            for path in paths:
                if path.startswith('/') and (path.endswith('.ini') or '/php.ini-production' in path):
                    inventory.setdefault(path, []).append(package)
    verified = {}
    def vendor(path):
        if path not in verified:
            owners = inventory.get(path, [])
            try:
                need(len(owners) == 1, 'configuration_continuation_INI_template_owner_ambiguous')
                if path.startswith('/etc/php/8.5/mods-available/'):
                    verified[path] = installed_package_INI(owners[0], path)
                else:
                    installed_vendor_file(owners[0], path)
                    verified[path] = safe_file(path)
            except Hold as error:
                error.details = dict(file=path, packages=owners)
                raise
        return verified[path]
    for sapi, settings in profiles.items():
        seen_modules = set()
        template = '/usr/lib/php/8.5/php.ini-production' + ('.cli' if sapi == 'cli' else '')
        need(settings['/etc/php/8.5/' + sapi + '/php.ini'].encode() == vendor(template),
             'configuration_continuation_target_php_ini_not_vendor_default')
        for path, text in settings.items():
            if path.endswith('/php.ini'):
                continue
            logical = Path(path)
            need(logical.is_symlink(), 'configuration_continuation_extra_target_INI')
            resolved = logical.resolve(strict=True)
            need(resolved.parent == Path('/etc/php/8.5/mods-available')
                 and re.fullmatch(r'[A-Za-z0-9_-]+\.ini', resolved.name),
                 'configuration_continuation_nonstandard_target_INI_alias')
            raw = safe_file(logical)
            need(raw == text.encode(), 'configuration_continuation_target_INI_changed')
            candidates = [p for p in inventory if Path(p).name == resolved.name
                          and re.match(r'^/usr/share/php8\.5-[A-Za-z0-9+.-]+/', p)]
            if candidates:
                matches = [p for p in candidates if vendor(p) == raw]
                need(len(matches) == 1, 'configuration_continuation_target_INI_not_unique_vendor_template')
            else:
                # Some extension packages ship the mods-available file directly.
                # File-list membership alone is insufficient: verify its recorded checksum.
                need(vendor(str(resolved)) == raw, 'configuration_continuation_packaged_module_INI_changed')
            # Match php-common's get_priority/get_live_link convention exactly.
            priorities = re.findall(r'(?m)^;[ \t]*priority[ \t]*=[ \t]*([0-9]+)[ \t]*$', text)
            need(len(priorities) <= 1, 'configuration_continuation_INI_priority_ambiguous')
            priority = priorities[0] if priorities else '20'
            need(logical.name == priority + '-' + resolved.name and str(resolved) not in seen_modules,
                 'configuration_continuation_extra_or_reordered_target_INI')
            seen_modules.add(str(resolved))


def _configuration_selectors(values, modes):
    allowed = {'php', 'phar', 'phar.phar', 'phpize', 'php-config'}
    need(isinstance(values, dict) and set(values) == set(modes)
         and 'php' in values and set(values) <= allowed,
         'configuration_continuation_selector_receipts_changed')
    selected = {}
    for line in command(['/usr/bin/update-alternatives', '--get-selections']).splitlines():
        fields = line.split()
        if fields and fields[0] in allowed:
            need(len(fields) == 3 and fields[0] not in selected,
                 'configuration_continuation_selector_inventory_changed')
            selected[fields[0]] = fields
    need(set(selected) == set(values), 'configuration_continuation_selector_inventory_changed')
    observed = {}
    for name in sorted(values):
        need(modes[name] in ('auto', 'manual') and re.fullmatch(r'/usr/bin/[A-Za-z0-9.+_-]+', values[name]),
             'configuration_continuation_selector_receipt_invalid')
        row = _preinstall_fields(command(['/usr/bin/update-alternatives', '--query', name]))
        need(row['Name'] == name and row['Status'] == 'manual' and row['Value'] == values[name]
             and selected[name][1:] == ['manual', values[name]],
             'configuration_continuation_selector_changed')
        # The approved new packages may legitimately change Best to 8.5.
        need(values[name] == '/usr/bin/' + name + '7.4'
             and row['Best'] in (values[name], '/usr/bin/' + name + '8.5'),
             'configuration_continuation_selector_best_unapproved')
        observed[name] = row
    return observed


def _configuration_after(plan):
    expected = {name: dict(row) for name, row in plan['packages'].items()}
    for name, row in plan['changes'].items():
        expected[name] = dict(version=row['version'], architecture=row['architecture'])
    need(packages() == expected, 'configuration_continuation_package_table_changed')
    installed = {}
    raw = command(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'])
    for line in raw.splitlines():
        fields = line.split('\t')
        need(len(fields) == 4, 'configuration_continuation_package_query_malformed')
        name, version, architecture, status = fields
        if ':' in name:
            name, suffix = name.rsplit(':', 1)
            need(suffix == architecture, 'configuration_continuation_package_architecture_changed')
        if status.strip().startswith('rc') or status.strip() in ('un', 'pn'):
            continue
        need(status.strip() == 'ii' and name not in installed
             and re.fullmatch(r'[a-z0-9][a-z0-9+.-]*', name),
             'configuration_continuation_package_status_changed')
        installed[name] = dict(version=version, architecture=architecture)
    need(installed == expected, 'configuration_continuation_full_package_table_changed')
    return expected


def _configuration_partial(plan, job, after, timers, values, modes):
    need(identity() == plan['host'] and source_files() == plan['sources'],
         'configuration_continuation_host_or_sources_changed')
    need(files_snapshot(plan['files']) == plan['files'], 'configuration_continuation_source_configuration_changed')
    branch = plan['source_branch']
    need(Path('/usr/bin/php').resolve() == Path('/usr/bin/php' + branch).resolve(),
         'configuration_continuation_default_CLI_changed')
    need(not Path('/usr/sbin/policy-rc.d').exists() and not Path('/usr/sbin/policy-rc.d').is_symlink(),
         'configuration_continuation_service_policy_present')
    validate_loaders(branch, plan['INI_files'], after)
    need(registry(branch) == plan['source_CLI_registry'] and registry(branch, True) == plan['source_registry'],
         'configuration_continuation_source_registry_changed')
    source_unit = validate_native_unit(branch, True)
    need(source_unit in plan['files'] and unit_enabled(branch) is plan['source_enabled'],
         'configuration_continuation_source_unit_changed')
    runtime = _preinstall_runtime(branch)
    _preinstall_timers(timers)
    selectors = _configuration_selectors(values, modes)
    target_unit = validate_native_unit(TARGET)
    state = command(['/bin/systemctl', 'show', 'php8.5-fpm.service', '-p', 'ActiveState', '--value']).strip()
    pid = command(['/bin/systemctl', 'show', 'php8.5-fpm.service', '-p', 'MainPID', '--value']).strip()
    need(state == 'inactive' and pid == '0', 'configuration_continuation_target_not_inactive')
    profiles = {}
    for sapi in ('cli', 'fpm'):
        migration = Path('/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini')
        need(not migration.exists() and not migration.is_symlink(), 'configuration_continuation_INI_already_written')
        paths = ['/etc/php/8.5/' + sapi + '/php.ini'] + sorted(glob.glob('/etc/php/8.5/' + sapi + '/conf.d/*.ini'))
        profiles[sapi] = {path: safe_file(path).decode() for path in paths}
        executable_INI_guard(profiles[sapi])
    _configuration_vendor_profiles(profiles, after)
    validate_loaders(TARGET, profiles, after)
    target_fpm, target_cli = registry(TARGET, True), registry(TARGET, False)
    need(compare(target_fpm['version'], FLOOR) >= 0 and compare(target_cli['version'], FLOOR) >= 0,
         'configuration_continuation_target_below_floor')
    for sapi, old, target in (('fpm', plan['source_registry'], target_fpm),
                             ('cli', plan['source_CLI_registry'], target_cli)):
        need({'mysqli', 'mysqlnd'} <= {name.lower() for name in old['modules']}
             and str(old['ini'].get('mysqli.reconnect', '')).strip().lower() in ('', '0', 'off', 'false', 'no')
             and 'mysqli.reconnect' in old['ini'] and 'mysqli.reconnect' not in target['ini'],
             'configuration_continuation_not_known_mysqli_OFF_case')
        ini_output(old, target, plan['INI_files'][sapi])
    directory = Path('/etc/php/8.5/fpm/pool.d')
    outputs = pool_outputs(plan['pools'], plan['parsed_pools'], plan['socket_map'])
    distribution = 'www.conf.distribution-' + job.name
    need({p.name for p in directory.iterdir()} == set(outputs) | {distribution},
         'configuration_continuation_target_pool_inventory_changed')
    partial_paths = []
    for name, content in outputs.items():
        path = directory / name
        before = plan['files'][next(p for p in plan['pools'] if Path(p).name == name)]
        row = files_snapshot([str(path)])[str(path)]
        need(row['link'] is None and safe_file(path) == content.encode()
             and all(row[key] == before[key] for key in ('mode', 'uid', 'gid')),
             'configuration_continuation_partial_pool_changed')
        partial_paths.append(str(path))
    global_path = '/etc/php/8.5/fpm/php-fpm.conf'
    before = plan['files']['/etc/php/' + branch + '/fpm/php-fpm.conf']
    row = files_snapshot([global_path])[global_path]
    need(row['link'] is None and safe_file(global_path) == plan['target_global_FPM'].encode()
         and all(row[key] == before[key] for key in ('mode', 'uid', 'gid')),
         'configuration_continuation_partial_global_changed')
    need(not (directory / distribution).is_symlink()
         and safe_file(directory / distribution) == safe_file(job / 'target-default-www.conf', True),
         'configuration_continuation_default_pool_backup_changed')
    safe_file(job / 'target-default-global.conf', True)
    partial_paths += [global_path, str(directory / distribution), target_unit]
    for settings in profiles.values():
        partial_paths.extend(settings)
    health(plan['nginx']['health'])
    return dict(runtime=runtime, selectors=selectors, target_files=files_snapshot(partial_paths))


def verify_configuration_continuation_journals(skip_job=None):
    for path in BASE.glob('configuration-continuation-*.json'):
        receipt = _preinstall_json(path)
        job = Path(receipt.get('job', ''))
        if not (receipt.get('schema') == 1 and receipt.get('phase') == 'complete'):
            admissible = (receipt.get('schema') == 1 and receipt.get('phase') == 'started'
                          and job.parent == BASE and re.fullmatch(r'job-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', job.name))
            if admissible and ((skip_job is not None and job == skip_job) or postconfiguration_supersedes(job)):
                _preinstall_job(job)
                need(path.name == 'configuration-continuation-' + job.name + '.json', 'invalid_configuration_continuation_receipt')
                continue
            raise Hold('unfinished_configuration_continuation_preserved')
        _preinstall_job(job)
        need(path.name == 'configuration-continuation-' + job.name + '.json', 'invalid_configuration_continuation_receipt')
        for name, sha in receipt['original_files'].items():
            raw = safe_file(job / name, True)
            if name == 'events.jsonl':
                raw = raw[:receipt['original_event_bytes']]
            need(digest(raw) == sha, 'configuration_continuation_original_evidence_changed')
        need(digest(safe_file(job / 'configuration-continuation-original-current.json', True)) == receipt['original_current_sha256'],
             'configuration_continuation_original_current_changed')
        need(digest(safe_file(job / 'configuration-continuation-source.py', True)) == receipt['continuation_source_sha256'],
             'configuration_continuation_source_changed')


def continue_v106_configuration(previous, adopt_vendor_socket=False):
    need(set(previous) == {'version', 'job', 'phase', 'event_sha256', 'reason', 'details', 'recovery'}
         and previous['version'] == '1.0.6' and previous['phase'] == 'failed_needs_review'
         and previous['reason'] == 'removed_nondefault_INI_setting' and previous['details'] == {},
         'previous_configuration_job_requires_review')
    job = Path(previous['job'])
    _preinstall_job(job)
    need(previous['recovery'] == str(job / 'recovery.json'), 'configuration_continuation_recovery_pointer_changed')
    raw_current = safe_file(BASE / 'current.json', True)
    need(_preinstall_json(BASE / 'current.json') == previous, 'configuration_continuation_current_changed')
    plan_raw, plan = safe_file(job / 'plan.json', True), _preinstall_json(job / 'plan.json')
    need(plan.get('schema') == 1 and plan.get('version') == '1.0.6'
         and plan.get('code_sha256') == CONTINUATION_V106_SHA256
         and digest(safe_file(job / 'php85_upgrade.py', True)) == CONTINUATION_V106_SHA256
         and plan.get('mode') == 'migration' and plan.get('source_branch') == '7.4'
         and plan.get('changes'), 'configuration_continuation_unrecognized_source_or_plan')
    need(plan_raw == encoded(plan) and safe_file(job / 'plan.sha256', True).decode() == digest(plan_raw) + '\n',
         'configuration_continuation_plan_seal_changed')
    names = {'php85_upgrade.py', 'events.jsonl', 'timers.json', 'plan.json', 'plan.sha256', 'recovery.json',
             'alternatives.json', 'alternative-modes.json', 'apt-hook', 'hook-accepted.json',
             'apt-install.stdout', 'apt-install.stderr', 'target-default-www.conf', 'target-default-global.conf'}
    names.update('configuration-' + str(i) for i in range(len(plan['files'])))
    need({p.name for p in job.iterdir()} == names, 'configuration_continuation_unrecognized_artifacts')
    original_files = _preinstall_inventory(job)
    for i, (path, row) in enumerate(sorted(plan['files'].items())):
        need(digest(safe_file(job / ('configuration-' + str(i)), True)) == row['sha256'],
             'configuration_continuation_backup_changed')
    recovery = _preinstall_json(job / 'recovery.json')
    need(set(recovery) == {'files', 'old_service', 'old_cli'} and recovery['files'] == plan['files']
         and recovery['old_service'] == 'php7.4-fpm.service', 'configuration_continuation_recovery_changed')
    values, modes = _preinstall_json(job / 'alternatives.json'), _preinstall_json(job / 'alternative-modes.json')
    old_cli = _preinstall_fields(recovery['old_cli'])
    need(old_cli['Name'] == 'php' and old_cli['Value'] == values.get('php') and old_cli['Status'] == modes.get('php'),
         'configuration_continuation_CLI_receipts_disagree')
    events_raw = safe_file(job / 'events.jsonl', True)
    events, last = [], '0' * 64
    for raw in events_raw.splitlines(keepends=True):
        row = json.loads(raw, object_pairs_hook=_preinstall_object)
        need(row.get('previous_sha256') == last and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', row.get('time', '')),
             'configuration_continuation_event_chain_changed')
        events.append(row)
        last = digest(raw)
    need([r.get('phase') for r in events] == ['preflight', 'refreshing_indexes', 'plan_sealed', 'downloading_packages',
         'installing_packages', 'APT_install_exited', 'target_configuration', 'failed_needs_review'],
         'configuration_continuation_unexpected_stages')
    common = {'time', 'phase', 'previous_sha256'}
    need(all(set(events[i]) == common for i in (0, 1, 3, 4, 6))
         and set(events[2]) == common | {'source', 'target', 'changed_packages', 'plan_sha256'}
         and events[2]['source'] == '7.4' and events[2]['target'] == '8.5'
         and events[2]['changed_packages'] == sorted(plan['changes']) and events[2]['plan_sha256'] == digest(plan_raw)
         and set(events[5]) == common | {'exit_code', 'logs'} and events[5]['exit_code'] == 0
         and set(events[7]) == common | {'reason', 'details', 'recovery'}
         and all(events[7][k] == previous[k] for k in ('reason', 'details', 'recovery'))
         and previous['event_sha256'] == last, 'configuration_continuation_event_or_current_changed')
    logs = []
    for name in ('apt-install.stdout', 'apt-install.stderr'):
        raw = safe_file(job / name, True)
        logs.append(dict(path=str(job / name), sha256=digest(raw), bytes=len(raw)))
    need(events[5]['logs'] == logs and _preinstall_json(job / 'hook-accepted.json') ==
         dict(accepted=True, plan_sha256=digest(plan_raw)), 'configuration_continuation_APT_proof_changed')
    expected_hook = ('#!/bin/sh\nexec /usr/bin/python3 -I ' + str(job / 'php85_upgrade.py') +
                     ' --apt-hook ' + str(job / 'plan.json') + '\n').encode()
    need(safe_file(job / 'apt-hook', True) == expected_hook and stat.S_IMODE((job / 'apt-hook').stat().st_mode) == 0o700,
         'configuration_continuation_APT_hook_changed')
    receipt_path = BASE / ('configuration-continuation-' + job.name + '.json')
    saved_current = job / 'configuration-continuation-original-current.json'
    need(not receipt_path.exists() and not receipt_path.is_symlink() and not saved_current.exists()
         and not saved_current.is_symlink(), 'configuration_continuation_already_attempted')
    shared, held, paused, journal = None, [], False, None
    receipt, original_current_saved = None, False
    try:
        shared = shared_lock()
        held = package_locks()
        timers = _preinstall_json(job / 'timers.json')
        initialize_version_comparison()
        after = _configuration_after(plan)
        proof = _configuration_partial(plan, job, after, timers, values, modes)
        need(_preinstall_inventory(job) == original_files and safe_file(BASE / 'current.json', True) == raw_current,
             'configuration_continuation_evidence_changed')
        continuation_source = safe_file(__file__)
        receipt = dict(schema=1, phase='started', job=str(job), original_files=original_files,
            original_event_bytes=len(events_raw), original_current_sha256=digest(raw_current),
            original_source_sha256=CONTINUATION_V106_SHA256, continuation_source_sha256=digest(continuation_source),
            plan_sha256=digest(plan_raw), prior_APT_succeeded=True, replay_APT=False,
            cause_basis='removed_mysqli_reconnect_confirmed_OFF_configuration_only', before=proof,
            time=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        atomic(receipt_path, encoded(receipt))
        atomic(saved_current, raw_current)
        need(safe_file(saved_current, True) == raw_current,
             'configuration_continuation_current_backup_changed')
        original_current_saved = True
        atomic(job / 'configuration-continuation-source.py', continuation_source)
        paused = True
        if timers:
            command(['/bin/systemctl', 'stop'] + timers)
        # Recheck immediately after durable one-use admission, before config mutation.
        need(_configuration_after(plan) == after and _configuration_partial(plan, job, after, [], values, modes) == proof
             and safe_file(BASE / 'current.json', True) == raw_current,
             'configuration_continuation_baseline_changed_after_admission')
        need(all(digest(safe_file(job / name, True)) == sha for name, sha in original_files.items()),
             'configuration_continuation_original_evidence_changed_after_admission')
        journal = Journal(job)
        journal.phase('configuration_only_continuation', original_version='1.0.6', plan_sha256=digest(plan_raw), APT_replayed=False)
        finish_configuration(plan, job, journal, values, modes, after, prepared=True, adopt_vendor_socket=adopt_vendor_socket)
        if timers:
            command(['/bin/systemctl', 'start'] + timers)
        _preinstall_timers(timers)
        paused = False
        receipt['phase'] = 'complete'
        receipt['completed_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
        atomic(receipt_path, encoded(receipt))
        return dict(phase='configuration_continuation_complete', job=str(job), APT_replayed=False)
    except BaseException as error:
        if receipt is not None and original_current_saved:
            journal = journal or Journal(job)
            journal.phase('configuration_continuation_failed_needs_review',
                          reason=str(error) if isinstance(error, Hold) else type(error).__name__,
                          recovery=str(job / 'recovery.json'), continuation_receipt=str(receipt_path),
                          details=getattr(error, 'details', {}) if isinstance(error, Hold) else exception_details(error))
        raise
    finally:
        try:
            if paused:
                if timers:
                    command(['/bin/systemctl', 'start'] + timers)
                _preinstall_timers(timers)
        finally:
            for fd in reversed(held):
                os.close(fd)
            if shared is not None:
                os.close(shared)


def _ss_vfs_device(device):
    """ss applies libc major/minor to the UNIX_DIAG_VFS raw kernel 12:20 dev_t."""
    need(type(device) is int and device >= 0, 'socket_adoption_invalid_filesystem_device')
    major, minor = os.major(device), os.minor(device)
    need(major <= 0xfff and minor <= 0xfffff, 'socket_adoption_filesystem_device_out_of_range')
    kernel_device = (major << 20) | minor
    return os.major(kernel_device), os.minor(kernel_device)


def verified_vendor_socket(plan, after):
    """Explicit opt-in adoption of one standard live local MySQL socket; no DB connection."""
    eligible = {}
    for sapi, field in (('fpm', 'source_registry'), ('cli', 'source_CLI_registry')):
        old = plan[field]
        explicit = any(re.search(r'(?m)^\s*mysqli\.default_socket\s*=', text)
                       for text in plan['INI_files'][sapi].values())
        if explicit and old['ini'].get('mysqli.default_socket', object()) is None:
            need({'mysqli', 'mysqlnd'} <= {m.lower() for m in old['modules']}, 'socket_adoption_requires_mysqlnd')
            eligible[sapi] = field
    if not eligible:
        return dict(socket_overrides={}, proof=None)
    installed_vendor_file('php8.5-cli', '/usr/bin/php8.5')
    need('php8.5-mysql' in after, 'socket_adoption_mysql_package_missing')
    current = {sapi: registry(TARGET, sapi == 'fpm') for sapi in eligible}
    directories = {row['directory'] for row in current.values()}
    need(len(directories) == 1, 'socket_adoption_API_ambiguous')
    directory = next(iter(directories))
    need(re.fullmatch(r'/usr/lib/php/[0-9]{8}', directory), 'socket_adoption_API_nonstandard')
    paths = [directory + '/' + name + '.so' for name in ('mysqlnd', 'mysqli')]
    for path in paths:
        installed_vendor_file('php8.5-mysql', path)
    script = "echo json_encode(['version'=>PHP_VERSION,'modules'=>get_loaded_extensions(),'socket'=>ini_get_all(null,false)['mysqli.default_socket']??null]);"
    compiled = json.loads(command(['/usr/bin/php8.5', '-n', '-d', 'extension=' + paths[0],
                                  '-d', 'extension=' + paths[1], '-r', script]))
    need(compiled['version'].startswith('8.5.') and {'mysqli', 'mysqlnd'} <=
         {m.lower() for m in compiled['modules']}, 'socket_adoption_compiled_registry_invalid')
    profiles = {}
    for sapi in eligible:
        files = ['/etc/php/8.5/' + sapi + '/php.ini'] + sorted(glob.glob('/etc/php/8.5/' + sapi + '/conf.d/*.ini'))
        profiles[sapi] = {p: safe_file(p).decode() for p in files
                         if p != '/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini'}
    _configuration_vendor_profiles(profiles, after)
    choices = {}
    for sapi, files in profiles.items():
        value = compiled['socket']
        for text in files.values():
            executable_INI_guard({'vendor.ini': text})
            for line in text.splitlines():
                match = re.match(r'^\s*mysqli\.default_socket\s*=\s*(.*?)\s*(?:;.*)?$', line)
                if match:
                    literal = match[1].strip().strip('"\'')
                    # PHP's OnUpdateStringUnempty rejects an empty assignment.
                    if literal:
                        need(literal in ('/run/mysqld/mysqld.sock', '/var/run/mysqld/mysqld.sock'),
                             'socket_adoption_vendor_default_nonstandard')
                        value = literal
        need(value in ('/run/mysqld/mysqld.sock', '/var/run/mysqld/mysqld.sock')
             and current[sapi]['ini'].get('mysqli.default_socket') == value,
             'socket_adoption_default_not_vendor_proven')
        choices[sapi] = value
    need(len(set(choices.values())) == 1, 'socket_adoption_SAPI_defaults_differ')
    chosen = next(iter(choices.values()))
    canonical = Path('/run/mysqld/mysqld.sock')
    aliases = [Path('/run/mysqld/mysqld.sock'), Path('/var/run/mysqld/mysqld.sock')]
    def socket_rows():
        result = []
        for path in aliases:
            info = path.stat()
            need(path.resolve(strict=True) == canonical and stat.S_ISSOCK(info.st_mode),
                 'socket_adoption_endpoint_not_canonical_socket')
            result.append(dict(path=str(path), device=info.st_dev, inode=info.st_ino,
                               uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode)))
        need(all(row['device'] == result[0]['device'] and row['inode'] == result[0]['inode']
                 for row in result), 'socket_adoption_alias_endpoint_mismatch')
        need(not canonical.is_symlink(), 'socket_adoption_leaf_alias_requires_review')
        return result
    sockets = socket_rows()
    for path in ('/', '/var', '/run', '/run/mysqld'):
        info = Path(path).lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, sockets[0]['uid'])
             and not info.st_mode & 0o022, 'socket_adoption_unsafe_endpoint_parent')
    varrun = Path('/var/run').lstat()
    need(stat.S_ISLNK(varrun.st_mode) and varrun.st_uid == 0
         and Path('/var/run').resolve(strict=True) == Path('/run'), 'socket_adoption_run_alias_changed')
    listeners = []
    for line in command(['/usr/bin/ss', '-H', '-lxnpe']).splitlines():
        fields = line.split()
        if len(fields) >= 9 and fields[0:2] == ['u_str', 'LISTEN'] and fields[4] in {str(path) for path in aliases}:
            suffix = ' '.join(fields[8:])
            owners = re.findall(r'users:\(\("(mysqld|mariadbd)",pid=([0-9]+),fd=([0-9]+)\)\)', suffix)
            vfs = re.findall(r'\bino:([0-9]+)\s+dev:([0-9]+)/([0-9]+)\b', suffix)
            need(len(owners) == 1 and len(vfs) == 1 and fields[5].isdigit(), 'socket_adoption_listener_owner_ambiguous')
            owner, node = owners[0], tuple(map(int, vfs[0]))
            need(node == (sockets[0]['inode'], *_ss_vfs_device(sockets[0]['device'])),
                 'socket_adoption_listener_filesystem_inode_mismatch')
            listeners.append(dict(name=owner[0], pid=int(owner[1]), fd=int(owner[2]), kernel_inode=int(fields[5]),
                                  filesystem_inode=node[0], device_major=node[1], device_minor=node[2]))
    need(len(listeners) == 1, 'socket_adoption_listener_ambiguous_or_absent')
    listener = listeners[0]
    process = Path('/proc/' + str(listener['pid']))
    before = RUNTIME['proc_stat']('/proc', listener['pid'])
    need(before[2] not in ('Z', 'X'), 'socket_adoption_database_not_live')
    executable = Path('/usr/sbin/' + listener['name']).resolve(strict=True)
    need(str(executable) in ('/usr/sbin/mysqld', '/usr/sbin/mariadbd')
         and os.readlink(process / 'exe') == str(executable), 'socket_adoption_noncanonical_database_executable')
    owners = command(['/usr/bin/dpkg-query', '-S', str(executable)]).splitlines()
    need(len(owners) == 1 and ': ' in owners[0], 'socket_adoption_database_package_ambiguous')
    owner = owners[0].split(': ', 1)[0].split(':', 1)[0]
    need(owner in after and owner.startswith(('mysql-server-core', 'mariadb-server-core')),
         'socket_adoption_database_package_unapproved')
    installed_vendor_file(owner, str(executable))
    disk, live = executable.stat(), (process / 'exe').stat()
    need((disk.st_dev, disk.st_ino) == (live.st_dev, live.st_ino), 'socket_adoption_database_executable_stale')
    status = RUNTIME['bounded'](process / 'status', 65536).decode()
    uid = re.findall(r'^Uid:\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s+([0-9]+)\s*$', status, re.M)
    need(len(uid) == 1 and all(int(value) == sockets[0]['uid'] for value in uid[0]),
         'socket_adoption_database_socket_owner_mismatch')
    need(os.readlink(process / 'fd' / str(listener['fd'])) == 'socket:[' + str(listener['kernel_inode']) + ']',
         'socket_adoption_listener_fd_changed')
    final = RUNTIME['proc_stat']('/proc', listener['pid'])
    need(final[:2] == before[:2] and final[2] not in ('Z', 'X') and socket_rows() == sockets
         and os.readlink(process / 'exe') == str(executable), 'socket_adoption_endpoint_changed')
    return dict(socket_overrides=choices, proof=dict(explicit_adoption=True, source_value=None,
                chosen_socket=chosen, compiled_default=compiled['socket'], PHP_version=compiled['version'],
                filesystem_sockets=sockets, listener=listener, database_package=owner,
                process_start_ticks=before[1], customer_database_connection_attempted=False))


POSTCONFIG_V109_SHA256 = 'b09929b996936f1b9e72e3222bc1f9300a1a11bab905bc82fe5d8c923b003ca6'


def _postconfig_events(job):
    raw = safe_file(job / 'events.jsonl', True)
    rows, last = [], '0' * 64
    for line in raw.splitlines(keepends=True):
        row = json.loads(line, object_pairs_hook=_preinstall_object)
        need(row.get('previous_sha256') == last
             and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z', row.get('time', '')),
             'postconfiguration_event_chain_changed')
        rows.append(row)
        last = digest(line)
    return raw, rows, last


def _postconfig_old_evidence(job, pending, plan):
    need(pending.get('schema') == 1 and pending.get('phase') == 'started' and pending.get('job') == str(job)
         and pending.get('original_source_sha256') == CONTINUATION_V106_SHA256
         and pending.get('continuation_source_sha256') == POSTCONFIG_V109_SHA256
         and pending.get('plan_sha256') == digest(encoded(plan))
         and pending.get('prior_APT_succeeded') is True and pending.get('replay_APT') is False,
         'postconfiguration_unrecognized_pending_receipt')
    original = pending['original_files']
    expected = {'php85_upgrade.py', 'events.jsonl', 'timers.json', 'plan.json', 'plan.sha256', 'recovery.json',
                'alternatives.json', 'alternative-modes.json', 'apt-hook', 'hook-accepted.json',
                'apt-install.stdout', 'apt-install.stderr', 'target-default-www.conf', 'target-default-global.conf'}
    expected.update('configuration-' + str(i) for i in range(len(plan['files'])))
    need(set(original) == expected, 'postconfiguration_original_artifact_inventory_changed')
    need(original['php85_upgrade.py'] == CONTINUATION_V106_SHA256,
         'postconfiguration_original_source_changed')
    for name, sha in original.items():
        raw = safe_file(job / name, True)
        if name == 'events.jsonl':
            raw = raw[:pending['original_event_bytes']]
        need(digest(raw) == sha, 'postconfiguration_original_evidence_changed')
    need(digest(safe_file(job / 'configuration-continuation-source.py', True)) == POSTCONFIG_V109_SHA256
         and digest(safe_file(job / 'configuration-continuation-original-current.json', True)) == pending['original_current_sha256'],
         'postconfiguration_original_continuation_changed')


def _postconfig_legacy_renderer(job):
    need(digest(safe_file(job / 'configuration-continuation-source.py', True)) == POSTCONFIG_V109_SHA256,
         'postconfiguration_old_renderer_source_changed')
    # Default rendering deliberately retains v109 bytes; only explicit override differs.
    return ini_output


def _postconfig_baseline(plan, job, pending, after, timers, values, modes, renderer):
    need(identity() == plan['host'] and source_files() == plan['sources']
         and files_snapshot(plan['files']) == plan['files'], 'postconfiguration_original_baseline_changed')
    need(_configuration_after(plan) == after, 'postconfiguration_package_table_changed')
    branch = plan['source_branch']
    need(Path('/usr/bin/php').resolve() == Path('/usr/bin/php' + branch).resolve(), 'postconfiguration_default_CLI_changed')
    validate_loaders(branch, plan['INI_files'], after)
    need(registry(branch) == plan['source_CLI_registry'] and registry(branch, True) == plan['source_registry'],
         'postconfiguration_source_registry_changed')
    unit = validate_native_unit(branch, True)
    need(unit in plan['files'] and unit_enabled(branch) is plan['source_enabled'], 'postconfiguration_source_unit_changed')
    need(not Path('/usr/sbin/policy-rc.d').exists() and not Path('/usr/sbin/policy-rc.d').is_symlink(),
         'postconfiguration_policy_present')
    _preinstall_runtime(branch)
    _configuration_selectors(values, modes)
    _preinstall_timers(timers)
    validate_native_unit(TARGET)
    need(command(['/bin/systemctl', 'show', 'php8.5-fpm.service', '-p', 'ActiveState', '--value']).strip() == 'inactive'
         and command(['/bin/systemctl', 'show', 'php8.5-fpm.service', '-p', 'MainPID', '--value']).strip() == '0',
         'postconfiguration_target_not_inactive')
    before = pending['before']['target_files']
    need(files_snapshot(before) == before, 'postconfiguration_preexisting_target_files_changed')
    profiles, ini_rows = {}, {}
    for sapi, old in (('fpm', plan['source_registry']), ('cli', plan['source_CLI_registry'])):
        migration = '/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini'
        expected_paths = {p for p in before if p.startswith('/etc/php/8.5/' + sapi + '/conf.d/')}
        need(set(glob.glob('/etc/php/8.5/' + sapi + '/conf.d/*.ini')) == expected_paths | {migration},
             'postconfiguration_extra_target_INI')
        profiles[sapi] = {p: safe_file(p).decode() for p in sorted(expected_paths)}
        main = '/etc/php/8.5/' + sapi + '/php.ini'
        profiles[sapi][main] = safe_file(main).decode()
        row = files_snapshot([migration])[migration]
        mode, gid = merged_mode([plan['files'][p] for p in plan['INI_files'][sapi]])
        need(row['link'] is None and row['mode'] == mode and row['uid'] == 0 and row['gid'] == gid,
             'postconfiguration_owned_INI_metadata_changed')
        ini_rows[migration] = row
    _configuration_vendor_profiles(profiles, after)
    complete_profiles = {sapi: dict(settings) for sapi, settings in profiles.items()}
    for sapi in ('fpm', 'cli'):
        path = '/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini'
        complete_profiles[sapi][path] = safe_file(path).decode()
        executable_INI_guard(complete_profiles[sapi])
    validate_loaders(TARGET, complete_profiles, after)
    for sapi, old in (('fpm', plan['source_registry']), ('cli', plan['source_CLI_registry'])):
        target = registry(TARGET, sapi == 'fpm')
        path = '/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini'
        need(safe_file(path) == renderer(old, target, plan['INI_files'][sapi]).encode(),
             'postconfiguration_owned_INI_bytes_changed')
        expected = forwarded_values(old, target, plan['INI_files'][sapi])
        mismatches = {key for key, value in expected.items() if target['ini'].get(key) != value}
        need(mismatches == {'mysqli.default_socket'} and old['ini']['mysqli.default_socket'] is None,
             'postconfiguration_effective_drift_outside_reviewed_socket')
    directory = Path('/etc/php/8.5/fpm/pool.d')
    pools = pool_outputs(plan['pools'], plan['parsed_pools'], plan['socket_map'])
    need({p.name for p in directory.iterdir()} == set(pools) | {'www.conf.distribution-' + job.name},
         'postconfiguration_extra_pool')
    health(plan['nginx']['health'])
    return ini_rows


def verify_postconfiguration_journals():
    for path in BASE.glob('postconfiguration-*.json'):
        receipt = _preinstall_json(path)
        need(receipt.get('schema') == 1 and receipt.get('phase') == 'complete', 'unfinished_postconfiguration_preserved')
        job = Path(receipt.get('job', ''))
        _preinstall_job(job)
        need(path == BASE / ('postconfiguration-' + job.name + '.json'), 'invalid_postconfiguration_receipt')
        pending_path = BASE / ('configuration-continuation-' + job.name + '.json')
        need(digest(safe_file(pending_path, True)) == receipt['pending_receipt_sha256'], 'postconfiguration_pending_receipt_changed')
        plan = _preinstall_json(job / 'plan.json')
        pending = _preinstall_json(pending_path)
        _postconfig_old_evidence(job, pending, plan)
        need(set(receipt['preserved_files']) == set(pending['original_files']) |
             {'configuration-continuation-source.py', 'configuration-continuation-original-current.json'},
             'postconfiguration_preserved_inventory_changed')
        for name, sha in receipt['preserved_files'].items():
            raw = safe_file(job / name, True)
            if name == 'events.jsonl':
                raw = raw[:receipt['original_event_bytes']]
            need(digest(raw) == sha, 'postconfiguration_preserved_evidence_changed')
        completion_names = {'postconfiguration-original-current.json', 'postconfiguration-source.py',
            'postconfiguration-original-fpm.ini', 'postconfiguration-original-cli.ini',
            'runtime-before-cutover.json', 'runtime-after-cutover.json', 'verification.json', 'owned-Nginx-edits.json'}
        need(set(receipt['completion_files']) == completion_names
             and receipt['completion_files']['postconfiguration-original-current.json'] == receipt['original_current_sha256']
             and receipt['completion_files']['postconfiguration-source.py'] == receipt['new_source_sha256'],
             'postconfiguration_completion_inventory_changed')
        for sapi in ('fpm', 'cli'):
            path_ini = '/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini'
            need(receipt['completion_files']['postconfiguration-original-' + sapi + '.ini'] == receipt['owned_ini_before'][path_ini]['sha256'],
                 'postconfiguration_old_INI_backup_changed')
        for name, sha in receipt['completion_files'].items():
            need(digest(safe_file(job / name, True)) == sha, 'postconfiguration_completion_proof_changed')
        events_raw, rows, last = _postconfig_events(job)
        need(rows[-1]['phase'] == 'complete' and last == receipt['completion_event_sha256'],
             'postconfiguration_final_journal_changed')
        need([row['phase'] for row in rows[11:]] == ['postconfiguration_only_continuation', 'Nginx_cutover', 'web_verification', 'complete']
             and rows[11].get('explicit_vendor_socket_adoption') is True
             and rows[11].get('APT_replayed') is False, 'postconfiguration_completion_stages_changed')
        verification = _preinstall_json(job / 'verification.json')
        need(verification.get('web_smoke_checks') is True and verification.get('application_compatibility_claim') is False
             and verification.get('Nginx_sockets') == sorted(plan['socket_map'].values())
             and verification.get('adopted_vendor_socket') ==
                 {sapi: receipt['socket_proof']['chosen_socket'] for sapi in ('fpm', 'cli')},
             'postconfiguration_final_verification_changed')
        for name in ('runtime-before-cutover.json', 'runtime-after-cutover.json'):
            need(isinstance(_preinstall_json(job / name), dict) and _preinstall_json(job / name),
                 'postconfiguration_runtime_proof_missing')


def postconfiguration_supersedes(job):
    """Only a fully verified complete successor may supersede one old pending receipt."""
    verify_postconfiguration_journals()
    path = BASE / ('postconfiguration-' + job.name + '.json')
    return path.exists() and _preinstall_json(path).get('phase') == 'complete'


def continue_v109_configuration(previous, adopt_vendor_socket=False):
    need(adopt_vendor_socket is True, 'explicit_adopt_vendor_socket_required')
    need(set(previous) == {'version', 'job', 'phase', 'event_sha256', 'reason', 'details', 'recovery', 'continuation_receipt'}
         and previous['version'] == '1.0.9' and previous['phase'] == 'configuration_continuation_failed_needs_review'
         and previous['reason'] == 'forwarded_INI_effective_value_mismatch' and previous['details'] == {},
         'postconfiguration_unrecognized_failure')
    job = Path(previous['job'])
    _preinstall_job(job)
    pending_path = BASE / ('configuration-continuation-' + job.name + '.json')
    need(previous['recovery'] == str(job / 'recovery.json') and previous['continuation_receipt'] == str(pending_path),
         'postconfiguration_failure_pointer_changed')
    verify_preflight_archive_journals()
    verify_preinstall_recovery_journals()
    verify_postconfiguration_journals()
    # Root wires this optional skip only for this exact pending admission.
    verify_configuration_continuation_journals(skip_job=job)
    raw_current = safe_file(BASE / 'current.json', True)
    need(_preinstall_json(BASE / 'current.json') == previous, 'postconfiguration_current_changed')
    plan_raw, plan = safe_file(job / 'plan.json', True), _preinstall_json(job / 'plan.json')
    need(plan_raw == encoded(plan) and safe_file(job / 'plan.sha256', True).decode() == digest(plan_raw) + '\n'
         and plan.get('version') == '1.0.6' and plan.get('schema') == 1
         and plan.get('code_sha256') == CONTINUATION_V106_SHA256 and plan.get('source_branch') == '7.4'
         and plan.get('mode') == 'migration', 'postconfiguration_plan_changed')
    pending_raw, pending = safe_file(pending_path, True), _preinstall_json(pending_path)
    _postconfig_old_evidence(job, pending, plan)
    events_raw, rows, last = _postconfig_events(job)
    need(len(rows) == 11 and [r['phase'] for r in rows[-3:]] == ['configuration_only_continuation', 'target_configuration',
         'configuration_continuation_failed_needs_review'] and last == previous['event_sha256']
         and rows[-3].get('original_version') == '1.0.6' and rows[-3].get('plan_sha256') == digest(plan_raw)
         and rows[-3].get('APT_replayed') is False
         and all(rows[-1].get(k) == previous[k] for k in ('reason', 'details', 'recovery', 'continuation_receipt')),
         'postconfiguration_unrecognized_event_suffix')
    common = {'time', 'phase', 'previous_sha256'}
    need(set(rows[8]) == common | {'original_version', 'plan_sha256', 'APT_replayed'}
         and set(rows[9]) == common
         and set(rows[10]) == common | {'reason', 'details', 'recovery', 'continuation_receipt'},
         'postconfiguration_event_suffix_fields_changed')
    need(all(set(rows[i]) == common for i in (0, 1, 3, 4, 6))
         and set(rows[2]) == common | {'source', 'target', 'changed_packages', 'plan_sha256'}
         and rows[2]['source'] == '7.4' and rows[2]['target'] == TARGET
         and rows[2]['changed_packages'] == sorted(plan['changes']) and rows[2]['plan_sha256'] == digest(plan_raw)
         and set(rows[5]) == common | {'exit_code', 'logs'}
         and set(rows[7]) == common | {'reason', 'details', 'recovery'}
         and rows[7]['details'] == {} and rows[7]['recovery'] == str(job / 'recovery.json')
         and pending['original_event_bytes'] == len(b''.join(events_raw.splitlines(keepends=True)[:8])),
         'postconfiguration_original_event_fields_changed')
    original_current = _preinstall_json(job / 'configuration-continuation-original-current.json')
    need(set(original_current) == {'version', 'job', 'phase', 'event_sha256', 'reason', 'details', 'recovery'}
         and original_current['version'] == '1.0.6' and original_current['job'] == str(job)
         and original_current['phase'] == 'failed_needs_review'
         and original_current['reason'] == 'removed_nondefault_INI_setting' and original_current['details'] == {}
         and original_current['recovery'] == str(job / 'recovery.json')
         and digest(events_raw[:pending['original_event_bytes']].splitlines(keepends=True)[-1]) == original_current['event_sha256']
         and [r['phase'] for r in rows[:8]] == ['preflight', 'refreshing_indexes', 'plan_sealed', 'downloading_packages',
            'installing_packages', 'APT_install_exited', 'target_configuration', 'failed_needs_review']
         and rows[5].get('exit_code') == 0 and rows[7].get('reason') == 'removed_nondefault_INI_setting',
         'postconfiguration_original_failure_changed')
    logs = [dict(path=str(job / name), sha256=digest(safe_file(job / name, True)),
                 bytes=len(safe_file(job / name, True))) for name in ('apt-install.stdout', 'apt-install.stderr')]
    need(rows[5].get('logs') == logs and _preinstall_json(job / 'hook-accepted.json') ==
         dict(accepted=True, plan_sha256=digest(plan_raw)), 'postconfiguration_APT_proof_changed')
    expected_names = set(pending['original_files']) | {'configuration-continuation-source.py', 'configuration-continuation-original-current.json'}
    need({p.name for p in job.iterdir()} == expected_names, 'postconfiguration_extra_job_artifacts')
    preserved = _preinstall_inventory(job)
    receipt_path = BASE / ('postconfiguration-' + job.name + '.json')
    need(not receipt_path.exists() and not receipt_path.is_symlink(), 'postconfiguration_already_attempted')
    shared, held, paused, saved, journal = None, [], False, False, None
    receipt = None
    try:
        shared = shared_lock()
        held = package_locks()
        initialize_version_comparison()
        after = _configuration_after(plan)
        timers = _preinstall_json(job / 'timers.json')
        values, modes = _preinstall_json(job / 'alternatives.json'), _preinstall_json(job / 'alternative-modes.json')
        renderer = _postconfig_legacy_renderer(job)
        ini_rows = _postconfig_baseline(plan, job, pending, after, timers, values, modes, renderer)
        socket_result = verified_vendor_socket(plan, after)
        socket_proof, overrides = socket_result['proof'], socket_result['socket_overrides']
        need(set(overrides) == {'fpm', 'cli'} and socket_proof.get('explicit_adoption') is True,
             'postconfiguration_socket_adoption_not_applicable')
        rendered = {}
        for sapi, old in (('fpm', plan['source_registry']), ('cli', plan['source_CLI_registry'])):
            rendered[sapi] = ini_output(old, registry(TARGET, sapi == 'fpm'), plan['INI_files'][sapi],
                                       socket_override=overrides[sapi]).encode()
        new_source = safe_file(__file__)
        receipt = dict(schema=1, phase='started', job=str(job), pending_receipt_sha256=digest(pending_raw),
            preserved_files=preserved, original_event_bytes=len(events_raw), original_current_sha256=digest(raw_current),
            new_source_sha256=digest(new_source), plan_sha256=digest(plan_raw), package_actions=0,
            explicit_vendor_socket_adoption=True, socket_proof=socket_proof, owned_ini_before=ini_rows)
        need(_preinstall_inventory(job) == preserved and safe_file(BASE / 'current.json', True) == raw_current
             and safe_file(pending_path, True) == pending_raw, 'postconfiguration_evidence_changed')
        atomic(receipt_path, encoded(receipt))
        atomic(job / 'postconfiguration-original-current.json', raw_current)
        need(safe_file(job / 'postconfiguration-original-current.json', True) == raw_current, 'postconfiguration_current_backup_changed')
        saved = True
        atomic(job / 'postconfiguration-source.py', new_source)
        for sapi in ('fpm', 'cli'):
            path = '/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini'
            atomic(job / ('postconfiguration-original-' + sapi + '.ini'), safe_file(path))
            need(digest(safe_file(job / ('postconfiguration-original-' + sapi + '.ini'), True)) == ini_rows[path]['sha256'],
                 'postconfiguration_old_INI_backup_changed')
        paused = True
        if timers:
            command(['/bin/systemctl', 'stop'] + timers)
        need(_postconfig_baseline(plan, job, pending, after, [], values, modes, renderer) == ini_rows
             and verified_vendor_socket(plan, after) == socket_result
             and safe_file(BASE / 'current.json', True) == raw_current and safe_file(pending_path, True) == pending_raw
             and all(digest(safe_file(job / name, True)) == sha for name, sha in preserved.items()),
             'postconfiguration_baseline_changed_after_admission')
        journal = Journal(job)
        journal.phase('postconfiguration_only_continuation', original_version='1.0.9', APT_replayed=False,
                      explicit_vendor_socket_adoption=True)
        for sapi, old in (('fpm', plan['source_registry']), ('cli', plan['source_CLI_registry'])):
            path = Path('/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini')
            row = ini_rows[str(path)]
            atomic(path, rendered[sapi], row['mode'])
            os.chown(path, row['uid'], row['gid'])
        finalize_configured(plan, job, journal, values, modes, after, socket_overrides=overrides)
        if timers:
            command(['/bin/systemctl', 'start'] + timers)
        _preinstall_timers(timers)
        paused = False
        receipt['completion_files'] = {name: digest(safe_file(job / name, True)) for name in (
            'postconfiguration-original-current.json', 'postconfiguration-source.py',
            'postconfiguration-original-fpm.ini', 'postconfiguration-original-cli.ini',
            'runtime-before-cutover.json', 'runtime-after-cutover.json', 'verification.json', 'owned-Nginx-edits.json')}
        receipt['completion_event_sha256'] = _postconfig_events(job)[2]
        receipt['phase'] = 'complete'
        atomic(receipt_path, encoded(receipt))
        return dict(phase='postconfiguration_complete', job=str(job), APT_replayed=False)
    except BaseException as error:
        if saved:
            journal = journal or Journal(job)
            journal.phase('postconfiguration_failed_needs_review', reason=str(error) if isinstance(error, Hold) else type(error).__name__,
                          recovery=str(job / 'recovery.json'), postconfiguration_receipt=str(receipt_path),
                          details=getattr(error, 'details', {}) if isinstance(error, Hold) else exception_details(error))
        raise
    finally:
        try:
            if paused:
                if timers:
                    command(['/bin/systemctl', 'start'] + timers)
                _preinstall_timers(timers)
        finally:
            for fd in reversed(held):
                os.close(fd)
            if shared is not None:
                os.close(shared)


def finish_configuration(plan, job, journal, alternatives, alternative_modes, after, prepared=False, adopt_vendor_socket=False):
    journal.phase('target_configuration')
    target_profiles = {}
    for sapi in ('cli', 'fpm'):
        paths = ['/etc/php/8.5/' + sapi + '/php.ini']
        paths += sorted(glob.glob('/etc/php/8.5/' + sapi + '/conf.d/*.ini'))
        target_profiles[sapi] = {path: safe_file(path).decode() for path in paths}
        executable_INI_guard(target_profiles[sapi])
    validate_loaders(TARGET, target_profiles, after)
    validate_native_unit(TARGET)
    target = registry(TARGET, True)
    target_cli = registry(TARGET, False)
    need(compare(target['version'], FLOOR) >= 0, 'target_runtime_below_security_floor')
    socket_result = (verified_vendor_socket(plan, after) if adopt_vendor_socket and plan['mode'] == 'migration'
                     else dict(socket_overrides={}, proof=None))
    socket_overrides = socket_result['socket_overrides']
    if socket_result['proof'] is not None:
        atomic(job / 'vendor-socket-proof.json', encoded(socket_result['proof']))
    if plan['mode'] == 'migration':
        need(files_snapshot(plan['files']) == plan['files'], 'source_configuration_changed')
        rendered_pools = pool_outputs(plan['pools'], plan['parsed_pools'], plan['socket_map'])
        rendered_ini, ini_metadata = {}, {}
        for sapi, old_registry, target_registry in (
            ('fpm', plan['source_registry'], target), ('cli', plan['source_CLI_registry'], target_cli)):
            settings = plan['INI_files'][sapi]
            rendered_ini[sapi] = ini_output(old_registry, target_registry, settings, socket_overrides.get(sapi)).encode()
            ini_metadata[sapi] = merged_mode([plan['files'][path] for path in settings])
        for text in plan['pools'].values():
            for key in re.findall(r'(?m)^\s*php_(?:admin_)?(?:value|flag)\[([^\]]+)\]\s*=', text):
                need(key in target['ini'], 'unsupported_forwarded_pool_INI_setting')
        for sapi in ('fpm', 'cli'):
            destination = Path('/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini')
            need(not destination.exists() and not destination.is_symlink(), 'migration_INI_destination_already_exists')
        target_dir = Path('/etc/php/8.5/fpm/pool.d')
        pool_metadata = {name: plan['files'][next(path for path in plan['pools'] if Path(path).name == name)]
                         for name in rendered_pools}
        global_record = plan['files']['/etc/php/' + plan['source_branch'] + '/fpm/php-fpm.conf']
        global_path = Path('/etc/php/8.5/fpm/php-fpm.conf')
        if not prepared:
            need(sorted(p.name for p in target_dir.glob('*.conf')) == ['www.conf'], 'unexpected_target_pools')
            need(not (job / 'target-default-www.conf').exists() and
                 not (job / 'target-default-global.conf').exists() and
                 not (target_dir / ('www.conf.distribution-' + job.name)).exists(), 'target_defaults_already_archived')
            default_www = safe_file(target_dir / 'www.conf')
            default_global = safe_file(global_path)
            atomic(job / 'target-default-www.conf', default_www)
            # Archive rather than delete the distribution's unused default pool.
            (target_dir / 'www.conf').rename(target_dir / ('www.conf.distribution-' + job.name))
        for name, content in rendered_pools.items():
            record = pool_metadata[name]
            atomic(target_dir / name, content.encode(), record['mode'])
            os.chown(target_dir / name, record['uid'], record['gid'])
        if not prepared:
            atomic(job / 'target-default-global.conf', default_global)
        record = global_record
        atomic(global_path, plan['target_global_FPM'].encode(), record['mode'])
        os.chown(global_path, record['uid'], record['gid'])
        for sapi, old_registry, target_registry in (
            ('fpm', plan['source_registry'], target), ('cli', plan['source_CLI_registry'], target_cli)):
            settings = plan['INI_files'][sapi]
            mode, gid = ini_metadata[sapi]
            path = Path('/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini')
            atomic(path, rendered_ini[sapi], mode)
            os.chown(path, 0, gid)
    finalize_configured(plan, job, journal, alternatives, alternative_modes, after, socket_overrides)


def finalize_configured(plan, job, journal, alternatives, alternative_modes, after, socket_overrides=None):
    socket_overrides = socket_overrides or {}
    target, target_cli = registry(TARGET, True), registry(TARGET, False)
    need(compare(target['version'], FLOOR) >= 0, 'target_runtime_below_security_floor')
    need(files_snapshot(plan['files']) == plan['files'], 'source_configuration_changed')
    if plan['mode'] == 'migration':
        for sapi, old_registry, target_registry in (
            ('fpm', plan['source_registry'], target), ('cli', plan['source_CLI_registry'], target_cli)):
            current = registry(TARGET, sapi == 'fpm')
            expected = forwarded_values(old_registry, target_registry, plan['INI_files'][sapi], socket_overrides.get(sapi))
            mismatches = sorted(key for key, value in expected.items() if current['ini'].get(key) != value)
            if mismatches:
                error = Hold('forwarded_INI_effective_value_mismatch')
                error.details = dict(sapi=sapi, directives=mismatches)
                raise error
            need({x.lower() for x in old_registry['modules']} <= {x.lower() for x in current['modules']}, 'forwarded_extension_parity_failed')
    else:
        for sapi, baseline, observed in (('fpm', plan['source_registry'], target),
                                          ('cli', plan['source_CLI_registry'], target_cli)):
            expected = forwarded_values(baseline, observed, plan['INI_files'][sapi])
            need(all(observed['ini'].get(key) == value for key, value in expected.items()), 'patched_INI_effective_value_drift')
            need({x.lower() for x in baseline['modules']} <= {x.lower() for x in observed['modules']}, 'patched_extension_parity_failed')
    command(['/usr/sbin/php-fpm8.5', '-t'])
    if plan['mode'] == 'migration':
        command(['/bin/systemctl', 'enable' if plan['source_enabled'] else 'disable', 'php8.5-fpm.service'])
    if plan['mode'] == 'migration' or plan['changes']:
        command(['/bin/systemctl', 'restart', 'php8.5-fpm.service'], 90)
    runtime_proof = fpm_ready(plan['socket_map'].values())
    atomic(job / 'runtime-before-cutover.json', encoded(runtime_proof))
    if plan['mode'] == 'migration':
        # Recheck complete Nginx source graph before committing exact operand edits.
        need(files_snapshot(plan['nginx']['files']) == {p: plan['files'][p] for p in plan['nginx']['files']}, 'Nginx_configuration_drift')
        journal.phase('Nginx_cutover')
        outputs = route_outputs(plan['nginx']['files'], plan['nginx']['routes'], plan['socket_map'])
        atomic(job / 'owned-Nginx-edits.json', encoded({path: digest(text.encode()) for path, text in outputs.items()}))
        for path, text in outputs.items():
            p = Path(path).resolve()
            record = plan['files'][path]
            atomic(p, text.encode(), record['mode'])
            os.chown(p, record['uid'], record['gid'])
        command(['/usr/sbin/nginx', '-t'])
        command(['/bin/systemctl', 'reload', 'nginx.service'])
    journal.phase('web_verification')
    for attempt in range(3):
        time.sleep(2)
        try:
            health(plan['nginx']['health'])
            break
        except Hold:
            if attempt == 2:
                raise
    atomic(job / 'runtime-after-cutover.json', encoded(fpm_ready(plan['socket_map'].values())))
    final_nginx = nginx_inventory()
    expected_routes = {plan['socket_map'][row['socket']] for row in plan['nginx']['routes']}
    need({r['socket'] for r in final_nginx['routes']} == expected_routes, 'final_Nginx_socket_mismatch')
    if plan['mode'] == 'migration':
        for name in alternatives:
            target_path = '/usr/bin/' + name + TARGET
            if Path(target_path).is_file():
                command(['/usr/bin/update-alternatives', '--set', name, target_path])
    elif plan['changes']:
        for name, mode in alternative_modes.items():
            if mode == 'auto':
                command(['/usr/bin/update-alternatives', '--auto', name])
                selected = command(['/usr/bin/update-alternatives', '--query', name])
                need(re.search(r'^Value: (.+)$', selected, re.M)[1] == alternatives[name], 'automatic_selector_drift')
    need(command(['/usr/bin/php', '-n', '-r', 'echo PHP_MAJOR_VERSION,".",PHP_MINOR_VERSION;']).strip() == TARGET, 'default_CLI_not_8_5')
    atomic(job / 'verification.json', encoded(dict(PHP_version=target['version'],
           target_packages={name: after[name] for name in plan['target_records']},
           Nginx_sockets=sorted(plan['socket_map'].values()), web_smoke_checks=True,
           application_compatibility_claim=False, legacy_packages_preserved=True,
           scope='Nginx_FPM_and_default_CLI', hardcoded_legacy_CLI_jobs_migrated=False, adopted_vendor_socket=socket_overrides)))
    journal.phase('complete', PHP_version=target['version'], legacy_retirement_required=plan['mode'] == 'migration',
                  scope='Nginx_FPM_and_default_CLI', hardcoded_legacy_CLI_jobs_migrated=False)




def apply(adopt_vendor_socket=False):
    need(os.geteuid() == 0, 'root_required')
    identity()
    BASE.mkdir(mode=0o700, exist_ok=True)
    need(BASE.stat().st_uid == 0 and not BASE.stat().st_mode & 0o077 and not BASE.is_symlink(), 'unsafe_state_directory')
    with (BASE / 'maintenance.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Hold('another_PHP85_job_is_running')
        verify_preflight_archive_journals()
        verify_preinstall_recovery_journals()
        verify_postconfiguration_journals()
        if (BASE / 'current.json').exists():
            pending_current = _preinstall_json(BASE / 'current.json')
            if pending_current.get('version') == '1.0.9' and pending_current.get('phase') != 'complete':
                print(json.dumps(continue_v109_configuration(pending_current, adopt_vendor_socket)), flush=True)
                return
        verify_configuration_continuation_journals()
        if (BASE / 'current.json').exists():
            previous = json.loads(safe_file(BASE / 'current.json', True))
            if previous.get('phase') != 'complete':
                if previous.get('version') == '1.0.6':
                    print(json.dumps(continue_v106_configuration(previous, adopt_vendor_socket)), flush=True)
                    return
                if previous.get('version') == '1.0.5':
                    recovered = recover_v105_preinstall(previous)
                    print(json.dumps(recovered), flush=True)
                else:
                    recover_v100_preflight(previous)
        need(not Path('/usr/sbin/policy-rc.d').exists(), 'existing_service_policy_requires_review')
        job = BASE / ('job-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8])
        job.mkdir(mode=0o700)
        atomic(job / 'php85_upgrade.py', Path(__file__).read_bytes())
        journal = Journal(job)
        active_timers, policy_digest, policy_identity, shared, held = [], None, None, None, []
        try:
            journal.phase('preflight')
            shared = shared_lock()
            for timer in ('apt-daily.timer', 'apt-daily-upgrade.timer'):
                result = subprocess.run(['/bin/systemctl', 'is-active', '--quiet', timer], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    active_timers.append(timer)
            atomic(job / 'timers.json', encoded(active_timers))
            if active_timers:
                command(['/bin/systemctl', 'stop'] + active_timers)
            validate_apt_security()
            source_files()
            journal.phase('refreshing_indexes')
            command(['/usr/bin/apt-get'] + apt_options() + ['-o', 'APT::Update::Error-Mode=any', 'update'], 300)
            held = package_locks()
            plan = inspect(adopt_vendor_socket=adopt_vendor_socket)
            atomic(job / 'plan.json', encoded(plan))
            atomic(job / 'plan.sha256', (digest(encoded(plan)) + '\n').encode())
            journal.phase('plan_sealed', source=plan['source_branch'], target=TARGET,
                          changed_packages=sorted(plan['changes']), plan_sha256=digest(encoded(plan)))
            for index, (path, record) in enumerate(sorted(plan['files'].items())):
                atomic(job / ('configuration-' + str(index)), safe_file(path))
            atomic(job / 'recovery.json', encoded(dict(files=plan['files'], old_service='php' + plan['source_branch'] + '-fpm.service',
                                                     old_cli=command(['/usr/bin/update-alternatives', '--query', 'php']))))
            current_snapshot(plan)
            # Preserve existing PHP/PHAR/development tool selections during APT.
            alternatives, alternative_modes = {}, {}
            for name in ('php', 'phar', 'phar.phar', 'phpize', 'php-config'):
                result = subprocess.run(['/usr/bin/update-alternatives', '--query', name], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
                if result.returncode == 0:
                    value = re.search(r'^Value: (.+)$', result.stdout.decode(), re.M)
                    need(value is not None, 'alternative_value_missing')
                    alternatives[name] = value[1]
                    mode = re.search(r'^Status: (auto|manual)$', result.stdout.decode(), re.M)
                    need(mode is not None, 'alternative_selection_mode_missing')
                    alternative_modes[name] = mode[1]
                    if plan['mode'] == 'migration' or plan['changes']:
                        command(['/usr/bin/update-alternatives', '--set', name, value[1]])
            atomic(job / 'alternatives.json', encoded(alternatives))
            atomic(job / 'alternative-modes.json', encoded(alternative_modes))
            for fd in reversed(held):
                os.close(fd)
            held = []
            if plan['changes']:
                journal.phase('downloading_packages')
                command(['/usr/bin/apt-get', '--yes', '--download-only', '--no-remove', '--no-install-recommends'] + apt_options() + ['install'] + plan['pins'], 600)
                current_snapshot(plan)
                policy = b'#!/bin/sh\nwhile [ "${1#-}" != "$1" ]; do shift; done\ncase "$1" in php8.5-fpm|php8.5-fpm.service) exit 101;; *) exit 0;; esac\n'
                fd = os.open('/usr/sbin/policy-rc.d', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(policy)
                    stream.flush()
                    os.fsync(stream.fileno())
                    info = os.fstat(stream.fileno())
                    policy_identity = (info.st_dev, info.st_ino)
                policy_digest = digest(policy)
                journal.phase('installing_packages')
                hook_command = str(job / 'apt-hook')
                wrapper = ('#!/bin/sh\nexec /usr/bin/python3 -I ' + str(job / 'php85_upgrade.py')
                           + ' --apt-hook ' + str(job / 'plan.json') + '\n').encode()
                atomic(job / 'apt-hook', wrapper, 0o700)
                need(safe_file(job / 'apt-hook', True) == wrapper, 'APT_hook_wrapper_changed')
                # Do not wall-clock kill a running dpkg transaction.
                installation = apt_install(['/usr/bin/apt-get', '--yes', '--no-remove', '--no-download', '--no-install-recommends'] + apt_options() +
                    ['-o', 'Dpkg::Options::=--force-confold', '-o', 'DPkg::Pre-Install-Pkgs::=' + hook_command,
                     '-o', 'DPkg::Tools::Options::' + hook_command + '::Version=2',
                     '-o', 'DPkg::Tools::Options::' + hook_command + '::InfoFD=0', 'install'] + plan['pins'], job)
                journal.phase('APT_install_exited', **installation)
                proof = json.loads(safe_file(job / 'hook-accepted.json', True))
                need(proof == dict(plan_sha256=digest(encoded(plan)), accepted=True), 'actual_APT_hook_proof_missing')
                info = Path('/usr/sbin/policy-rc.d').lstat()
                need((info.st_dev, info.st_ino) == policy_identity and digest(safe_file('/usr/sbin/policy-rc.d')) == policy_digest, 'owned_service_policy_changed')
                Path('/usr/sbin/policy-rc.d').unlink()
                policy_digest = None
            held = package_locks()
            after = packages()
            need(set(after) == set(plan['packages']) | set(plan['changes']), 'unplanned_final_package_set')
            for name, record in after.items():
                expected = plan['changes'].get(name)
                need(record == (dict(version=expected['version'], architecture=expected['architecture']) if expected else plan['packages'][name]),
                     'final_package_version_mismatch')
            need(source_files() == plan['sources'] and identity() == plan['host'], 'post_APT_host_or_sources_changed')
            # Pin phar/development selectors back while compatibility checks run.
            if plan['mode'] == 'migration' or plan['changes']:
                for name, value in alternatives.items():
                    command(['/usr/bin/update-alternatives', '--set', name, value])
            finish_configuration(plan, job, journal, alternatives, alternative_modes, after, adopt_vendor_socket=adopt_vendor_socket)
        except BaseException as error:
            journal.phase('failed_needs_review', reason=str(error) if isinstance(error, Hold) else type(error).__name__,
                          recovery=str(job / 'recovery.json') if (job / 'recovery.json').exists() else None,
                          details=getattr(error, 'details', {}) if isinstance(error, Hold) else exception_details(error))
            raise
        finally:
            cleanup_errors = []
            if policy_digest is not None:
                try:
                    info = Path('/usr/sbin/policy-rc.d').lstat() if Path('/usr/sbin/policy-rc.d').exists() else None
                    need(info is not None and (info.st_dev, info.st_ino) == policy_identity
                         and digest(safe_file('/usr/sbin/policy-rc.d')) == policy_digest, 'owned_service_policy_changed')
                    Path('/usr/sbin/policy-rc.d').unlink()
                except (Hold, OSError):
                    cleanup_errors.append('owned_service_policy_not_restored')
            for fd in reversed(held):
                try:
                    os.close(fd)
                except OSError:
                    cleanup_errors.append('APT_lock_close_failed')
            for timer in active_timers:
                try:
                    command(['/bin/systemctl', 'start', timer])
                    command(['/bin/systemctl', 'is-active', '--quiet', timer])
                except (Hold, OSError):
                    cleanup_errors.append('timer_restore_failed')
            if shared is not None:
                try:
                    os.close(shared)
                except OSError:
                    cleanup_errors.append('shared_lock_close_failed')
            if cleanup_errors:
                journal.phase('cleanup_failed', reasons=cleanup_errors)
                if sys.exc_info()[0] is None:
                    raise Hold('cleanup_requires_review')


def main():
    os.umask(0o077)
    if len(sys.argv) == 3 and sys.argv[1] == '--apt-hook':
        need(os.geteuid() == 0 and re.fullmatch(r'/var/lib/ubuntu-php85-upgrade/job-[A-Za-z0-9-]+/plan.json', sys.argv[2]), 'invalid_hook_context')
        hook(sys.argv[2])
        return
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--apply', action='store_true')
    modes.add_argument('--plan-only', action='store_true')
    modes.add_argument('--status', action='store_true')
    modes.add_argument('--rollback', action='store_true')
    parser.add_argument('--adopt-vendor-socket', action='store_true')
    args = parser.parse_args()
    need(not args.adopt_vendor_socket or args.apply or args.plan_only, 'socket_adoption_requires_explicit_plan_or_apply')
    need(os.geteuid() == 0, 'root_required')
    if args.status:
        print(safe_file(BASE / 'current.json', True).decode() if (BASE / 'current.json').exists() else json.dumps(dict(status='no_job')))
    elif args.apply:
        apply(adopt_vendor_socket=args.adopt_vendor_socket)
    elif args.rollback:
        rollback()
    else:
        plan = inspect(adopt_vendor_socket=args.adopt_vendor_socket)
        print(json.dumps(dict(mode='plan-only', version=VERSION, host=plan['host'], source=plan['source_branch'],
            target=TARGET, operation=plan['mode'], adopt_vendor_socket=args.adopt_vendor_socket, packages=sorted(plan['target_records']),
            changed_packages=sorted(plan['changes']), socket_map=plan['socket_map'], sites=len(plan['nginx']['health']),
            plan_sha256=digest(encoded(plan)), note='APT indexes were not refreshed; apply refreshes and seals a new local plan.'), indent=2))


if __name__ == '__main__':
    try:
        main()
    except Hold as error:
        print(json.dumps(dict(status='held', reason=str(error), details=getattr(error, 'details', {}))), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(json.dumps(dict(status='failed', reason=type(error).__name__, details=exception_details(error))), file=sys.stderr)
        sys.exit(1)
