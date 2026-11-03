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

VERSION = '1.0.0'
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


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


_SECURITY_ROOT = Path('/')
_SECURITY_UID = 0


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size, info.st_mtime_ns)


def _safe_parents(path):
    root = _SECURITY_ROOT
    need(path.is_absolute() and '..' not in path.parts and (path == root or root in path.parents), 'unsafe_absolute_file_path')
    for parent in reversed(path.parents):
        if parent != root and root not in parent.parents:
            continue
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode) and info.st_uid == _SECURITY_UID
             and not info.st_mode & 0o022, 'unsafe_file_parent')


def _file_record(path, private=False):
    p = Path(path)
    _safe_parents(p)
    logical = p.lstat()
    need(logical.st_uid == _SECURITY_UID, 'unsafe_file_alias_owner')
    link = os.readlink(p) if stat.S_ISLNK(logical.st_mode) else None
    need(not private or link is None, 'private_file_symlink')
    cursor, aliases = p, []
    for unused in range(16):
        _safe_parents(cursor)
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
    _safe_parents(resolved)
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
        link_uid=logical.st_uid, link_inode=logical.st_ino if link is not None else None)


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


def command(args, timeout=30, env=None, input=None):
    need(not os.environ.get('APT_CONFIG'), 'APT_CONFIG_override_forbidden')
    environment = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/nonexistent', LC_ALL='C', LANG='C',
        DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l', UCF_FORCE_CONFFOLD='1',
        APT_LISTCHANGES_FRONTEND='none', PYTHONDONTWRITEBYTECODE='1')
    for key, value in (env or {}).items():
        need(key == 'PHP_INI_SCAN_DIR' and isinstance(value, str)
             and re.fullmatch(r'/etc/php/[0-9]+\.[0-9]+/(?:cli|fpm)/conf\.d', value), 'unapproved_command_environment')
        environment[key] = value
    try:
        result = subprocess.run(args, input=input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=timeout, env=environment)
    except subprocess.TimeoutExpired:
        raise Hold('command_timed_out_' + Path(args[0]).name)
    need(result.returncode == 0, 'command_failed_' + Path(args[0]).name)
    need(len(result.stdout) <= 16 * 1024 * 1024, 'command_output_too_large')
    return result.stdout.decode('utf-8', 'strict')


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


def nginx_inventory(read=None, expand=None):
    read = read or (lambda path: safe_file(path).decode())
    expand = expand or (lambda value: sorted(glob.glob(value)))
    seen, routes, servers = {}, [], []

    def walk(path, server=None, depth=0):
        need(depth <= 20 and len(seen) <= 500, 'nginx_include_limit')
        p = Path(path)
        need(str(p).startswith('/etc/nginx/') and str(p.resolve()).startswith('/etc/nginx/'), 'nginx_path_outside_config')
        text = read(str(p))
        seen[str(p)] = text

        def visit(nodes, context):
            for header, children in nodes:
                name, args = header[0][0], [x[0] for x in header[1:]]
                current = context
                if name == 'server' and children is not None:
                    need(not args, 'non_HTTP_server_block')
                    current = dict(names=[], roots=[], listen=[], routes=[])
                    servers.append(current)
                if name == 'include':
                    need(len(args) == 1 and args[0].startswith('/etc/nginx/') and '$' not in args[0], 'absolute_nginx_include_required')
                    for child in expand(args[0]):
                        walk(child, current, depth + 1)
                elif name == 'fastcgi_pass':
                    need(current is not None and len(args) == 1 and args[0].startswith('unix:'), 'direct_Unix_FastCGI_required')
                    socket = normalize_socket(args[0][5:])
                    record = dict(file=str(p), start=header[1][1], end=header[1][2], socket=socket)
                    routes.append(record)
                    current['routes'].append(record)
                elif name == 'fastcgi_param' and args and args[0] in ('PHP_VALUE', 'PHP_ADMIN_VALUE'):
                    raise Hold('Nginx_injected_PHP_settings_require_review')
                elif current is not None and name == 'alias':
                    raise Hold('Nginx_alias_requires_separate_health_profile')
                elif current is not None and name in ('server_name', 'root', 'listen'):
                    current[{'server_name': 'names', 'root': 'roots', 'listen': 'listen'}[name]].extend(args if name == 'server_name' else [args])
                if children is not None:
                    visit(children, current)
        visit(directives(text), server)
    walk('/etc/nginx/nginx.conf')
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


def ini_output(old, target, settings_files):
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
    lines = ['; Preserved settings; PHP 8.5 owns its extension loaders.']
    for key in sorted(explicit):
        if key in SKIP_INI:
            continue
        if key not in old['ini']:
            continue
        value = str(old['ini'][key]) if old['ini'][key] is not None else ''
        if key not in target_keys:
            need(key in REMOVED_DEFAULTS and value == REMOVED_DEFAULTS[key], 'removed_nondefault_INI_setting')
            continue
        need(not re.search(r'(?:/php/(?:7\.[234]|8\.[0-4])|/php(?:7\.[234]|8\.[0-4])|/20[0-9]{6}/)', value), 'legacy_PHP_path_in_setting')
        need('\n' not in value and '\r' not in value and '\x00' not in value, 'multiline_INI_value')
        value = value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')
        lines.append(key + '="' + value + '"')
    return '\n'.join(lines) + '\n'


def forwarded_values(old, target, settings_files):
    ini_output(old, target, settings_files)
    keys = {m[1] for text in settings_files.values() for line in text.splitlines()
            if (m := re.match(r'^\s*([A-Za-z0-9_.-]+)\s*=', line))}
    return {key: old['ini'][key] for key in keys - SKIP_INI if key in old['ini'] and key in target['ini']}


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
            output = command(args + [str(signed)])
        fingerprints = []
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[:2] == ['[GNUPG:]', 'VALIDSIG']:
                fingerprints.append(fields[-1] if re.fullmatch(r'[0-9A-Fa-f]{40}', fields[-1]) else fields[2])
        need(PPA_KEY in fingerprints, 'PHP_PPA_signature_fingerprint_mismatch')
        proofs.append(dict(path=str(path), sha256=digest(raw), source_path=entry['source_path'],
                           primary_fingerprint=PPA_KEY, keyrings=key_proofs))
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


def inspect():
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
    observed = set(re.findall(r'^# configuration file (/.+):$', dumped, re.M))
    need(observed == set(nginx['files']), 'Nginx_include_graph_mismatch')
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
    plan = dict(schema=1, version=VERSION, code_sha256=digest(Path(__file__).read_bytes()), host=host,
        source_branch=branch, mode='patch' if branch == TARGET else 'migration', packages=before, sources=sources,
        files=files_snapshot(config_paths), nginx=nginx, pools=texts, parsed_pools=parsed, socket_map=mapping,
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
            old_configs = {path: row for path, row in plan['files'].items() if path.startswith('/etc/php/')}
            need(files_snapshot(old_configs) == old_configs, 'original_PHP_configuration_changed')
            source_unit = validate_native_unit(plan['source_branch'])
            need(source_unit in plan['files'] and files_snapshot([source_unit])[source_unit] == plan['files'][source_unit],
                 'original_FPM_unit_changed')
            edits = json.loads(safe_file(job / 'owned-Nginx-edits.json', True)) if (job / 'owned-Nginx-edits.json').exists() else {}
            for path, new_sha in edits.items():
                need(path in plan['files'], 'unowned_recovery_path')
                before = plan['files'][path]
                observed = files_snapshot([path])[path]
                need(all(observed[key] == before[key] for key in ('link', 'resolved', 'uid', 'gid', 'mode')), 'recovery_path_metadata_changed')
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


def apply():
    need(os.geteuid() == 0, 'root_required')
    identity()
    BASE.mkdir(mode=0o700, exist_ok=True)
    need(BASE.stat().st_uid == 0 and not BASE.stat().st_mode & 0o077 and not BASE.is_symlink(), 'unsafe_state_directory')
    with (BASE / 'maintenance.lock').open('a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Hold('another_PHP85_job_is_running')
        if (BASE / 'current.json').exists():
            previous = json.loads(safe_file(BASE / 'current.json', True))
            need(previous.get('phase') == 'complete', 'previous_job_preserved_use_status')
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
            plan = inspect()
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
                hook_command = '/usr/bin/python3 -I ' + str(job / 'php85_upgrade.py') + ' --apt-hook ' + str(job / 'plan.json')
                # Do not wall-clock kill a running dpkg transaction.
                command(['/usr/bin/apt-get', '--yes', '--no-remove', '--no-download', '--no-install-recommends'] + apt_options() +
                    ['-o', 'Dpkg::Options::=--force-confold', '-o', 'DPkg::Pre-Install-Pkgs::=' + hook_command,
                     '-o', 'DPkg::Tools::Options::' + hook_command + '::Version=2',
                     '-o', 'DPkg::Tools::Options::' + hook_command + '::InfoFD=0', 'install'] + plan['pins'], None)
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
            if plan['mode'] == 'migration':
                need(files_snapshot(plan['files']) == plan['files'], 'source_configuration_changed')
                target_dir = Path('/etc/php/8.5/fpm/pool.d')
                need(sorted(p.name for p in target_dir.glob('*.conf')) == ['www.conf'], 'unexpected_target_pools')
                atomic(job / 'target-default-www.conf', safe_file(target_dir / 'www.conf'))
                # Archive rather than delete the distribution's unused default pool.
                (target_dir / 'www.conf').rename(target_dir / ('www.conf.distribution-' + job.name))
                for name, content in pool_outputs(plan['pools'], plan['parsed_pools'], plan['socket_map']).items():
                    old_path = next(path for path in plan['pools'] if Path(path).name == name)
                    record = plan['files'][old_path]
                    atomic(target_dir / name, content.encode(), record['mode'])
                    os.chown(target_dir / name, record['uid'], record['gid'])
                global_path = Path('/etc/php/8.5/fpm/php-fpm.conf')
                atomic(job / 'target-default-global.conf', safe_file(global_path))
                record = plan['files']['/etc/php/' + plan['source_branch'] + '/fpm/php-fpm.conf']
                atomic(global_path, plan['target_global_FPM'].encode(), record['mode'])
                os.chown(global_path, record['uid'], record['gid'])
                for sapi, old_registry, target_registry in (
                    ('fpm', plan['source_registry'], target), ('cli', plan['source_CLI_registry'], target_cli)):
                    settings = plan['INI_files'][sapi]
                    mode, gid = merged_mode([plan['files'][path] for path in settings])
                    path = Path('/etc/php/8.5/' + sapi + '/conf.d/99-ubuntu-php85-migration.ini')
                    atomic(path, ini_output(old_registry, target_registry, settings).encode(), mode)
                    os.chown(path, 0, gid)
                for text in plan['pools'].values():
                    for key in re.findall(r'(?m)^\s*php_(?:admin_)?(?:value|flag)\[([^\]]+)\]\s*=', text):
                        need(key in target['ini'], 'unsupported_forwarded_pool_INI_setting')
                for sapi, old_registry, target_registry in (
                    ('fpm', plan['source_registry'], target), ('cli', plan['source_CLI_registry'], target_cli)):
                    current = registry(TARGET, sapi == 'fpm')
                    expected = forwarded_values(old_registry, target_registry, plan['INI_files'][sapi])
                    need(all(current['ini'].get(key) == value for key, value in expected.items()), 'forwarded_INI_effective_value_mismatch')
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
                   scope='Nginx_FPM_and_default_CLI', hardcoded_legacy_CLI_jobs_migrated=False)))
            journal.phase('complete', PHP_version=target['version'], legacy_retirement_required=plan['mode'] == 'migration',
                          scope='Nginx_FPM_and_default_CLI', hardcoded_legacy_CLI_jobs_migrated=False)
        except BaseException as error:
            journal.phase('failed_needs_review', reason=str(error) if isinstance(error, Hold) else type(error).__name__,
                          recovery=str(job / 'recovery.json'))
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
    args = parser.parse_args()
    need(os.geteuid() == 0, 'root_required')
    if args.status:
        print(safe_file(BASE / 'current.json', True).decode() if (BASE / 'current.json').exists() else json.dumps(dict(status='no_job')))
    elif args.apply:
        apply()
    elif args.rollback:
        rollback()
    else:
        plan = inspect()
        print(json.dumps(dict(mode='plan-only', version=VERSION, host=plan['host'], source=plan['source_branch'],
            target=TARGET, operation=plan['mode'], packages=sorted(plan['target_records']),
            changed_packages=sorted(plan['changes']), socket_map=plan['socket_map'], sites=len(plan['nginx']['health']),
            plan_sha256=digest(encoded(plan)), note='APT indexes were not refreshed; apply refreshes and seals a new local plan.'), indent=2))


if __name__ == '__main__':
    try:
        main()
    except Hold as error:
        print(json.dumps(dict(status='held', reason=str(error))), file=sys.stderr)
        sys.exit(1)
    except Exception as error:
        print(json.dumps(dict(status='failed', reason=type(error).__name__)), file=sys.stderr)
        sys.exit(1)
