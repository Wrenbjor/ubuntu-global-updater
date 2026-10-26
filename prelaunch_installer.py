"""Install/refresh updater CODE only before any job exists (Python3.6 compatible).

Used by the reviewed one-file installer. Running this library itself takes no
action. A recognized preflight-only payload is archived, never deleted. Existing
job state, units, unknown files or code changes refuse refresh.
"""
import fcntl,hashlib,json,os,re,stat,subprocess,tempfile
from pathlib import Path

WRAPPER=b'#!/bin/bash\nset -euo pipefail\nexec /usr/bin/python3 -B /var/lib/visionline-global-updater/payload/ubuntu_global.py "$@"\n'
UNIT='visionline-global-updater.service'
class InstallError(Exception):pass
def require(value,code):
    if not value:raise InstallError(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def exists(path):return path.exists() or path.is_symlink()
def sync_directory(path):
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def safe_file(path,uid,bound=2097152):
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid==uid and not info.st_mode&0o022
                and info.st_nlink==1 and info.st_size<=bound,'unsafe_existing_updater_file')
        raw=stream.read(bound+1)
    require(len(raw)<=bound,'updater_file_too_large')
    return raw
def directory(path,uid,create=False):
    if create and not exists(path):path.mkdir(mode=0o700)
    info=path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==uid and stat.S_IMODE(info.st_mode)==0o700
            and path.resolve()==path,'unsafe_updater_directory')
def native_unit_state():
    result=subprocess.run(['/bin/systemctl','show',UNIT,'-p','LoadState','-p','ActiveState','-p','MainPID'],
                          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
    values=dict(line.split('=',1) for line in result.stdout.decode().splitlines() if '=' in line)
    return values
def no_running_payload(base,wrapper,uid):
    core=os.fsencode(str(base/'payload'/'ubuntu_global.py'));wrapper=os.fsencode(str(wrapper))
    for path in Path('/proc').iterdir():
        if not path.name.isdecimal() or int(path.name)==os.getpid():continue
        try:
            if path.stat().st_uid!=uid:continue
            with (path/'cmdline').open('rb') as stream:raw=stream.read(65537)
            require(len(raw)<=65536,'process_argument_inventory_too_large')
            args=raw.split(b'\0')
            applying=b'--apply' in args or b'--worker' in args
            module=any(args[i:i+2]==[b'-m',b'ubuntu_global'] for i in range(len(args)-1))
            matched=core in args or wrapper in args
            if applying and not matched:
                # A prior launcher may use ./ubuntu_global.py from payload cwd.
                # Resolve candidate paths without printing process arguments.
                targets={os.path.realpath(core),os.path.realpath(wrapper)}
                cwd=None
                for arg in args:
                    if not arg or arg.startswith(b'-'):continue
                    if os.path.isabs(arg):candidate=arg
                    else:
                        if cwd is None:cwd=os.fsencode(os.readlink(str(path/'cwd')))
                        candidate=os.path.join(cwd,arg)
                    if os.path.realpath(candidate) in targets:
                        matched=True;break
            require(not applying or not matched and not module,
                    'live_prelaunch_or_worker_process_preserved')
        except (FileNotFoundError,ProcessLookupError):pass

def wrapper_parent(wrapper,uid):
    parent=wrapper.parent;info=parent.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid==uid and not info.st_mode&0o022
            and parent.resolve()==parent,'unsafe_wrapper_parent')

def no_job(base,unit_paths,system_reader,wrapper,uid):
    require(not exists(base/'state.json'),'existing_job_preserved_use_status')
    require(not exists(base/'worker.lock'),'prior_worker_marker_requires_review')
    require(all(not exists(path) for path in unit_paths),'existing_unit_preserved_use_status')
    state=system_reader()
    require(state.get('LoadState')=='not-found' and state.get('ActiveState') in ('inactive','failed')
            and state.get('MainPID')=='0','loaded_or_running_updater_requires_review')
    no_running_payload(base,wrapper,uid)
def inspect_payload(path,allowed,uid):
    directory(path,uid)
    entries=list(path.iterdir());names={p.name for p in entries if p.name!='__pycache__'}
    matches=[manifest for manifest in allowed if names==set(manifest)]
    require(bool(matches),'unrecognized_prelaunch_payload_file_set')
    hashes={p.name:digest(safe_file(p,uid)) for p in entries if p.name!='__pycache__'}
    require(any(hashes==manifest for manifest in matches),'unrecognized_or_modified_prelaunch_payload')
    cache=path/'__pycache__'
    if exists(cache):
        i=cache.lstat()
        require(stat.S_ISDIR(i.st_mode) and i.st_uid==uid and not i.st_mode&0o022,'unsafe_prelaunch_bytecode_directory')
        modules={name[:-3] for name in names}
        for entry in cache.iterdir():
            require(any(re.fullmatch(re.escape(name)+r'\.[A-Za-z0-9_-]+(?:\.opt-[12])?\.pyc',entry.name) for name in modules),
                    'unknown_prelaunch_bytecode_file')
            safe_file(entry,uid)
    return hashes
def write_new(path,data,mode=0o600):
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())

def install_bundle(files,allowed_payloads,base=Path('/var/lib/visionline-global-updater'),
                   wrapper=Path('/root/ubuntu-global-updater.sh'),
                   unit_paths=(Path('/etc/systemd/system')/UNIT,Path('/run/systemd/system')/UNIT),
                   system_reader=native_unit_state,start=True,owner_uid=None):
    uid=os.geteuid() if owner_uid is None else owner_uid
    require(not start or uid==os.geteuid()==0,'root_required')
    base,wrapper=Path(base),Path(wrapper)
    require(base.is_absolute() and wrapper.is_absolute(),'absolute_installation_paths_required')
    require(files and 'ubuntu_global.py' in files and all(re.fullmatch(r'[a-z][a-z0-9_]*\.py',n) and isinstance(raw,bytes)
            and len(raw)<=2097152 for n,raw in files.items()),'invalid_installation_payload')
    directory(base,uid,create=True)
    lockfd=os.open(str(base/'installer.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
    info=os.fstat(lockfd)
    require(stat.S_ISREG(info.st_mode) and info.st_uid==uid and not info.st_mode&0o077 and info.st_nlink==1,'unsafe_installer_lock')
    try:
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        no_job(base,unit_paths,system_reader,wrapper,uid)
        wrapper_parent(wrapper,uid)
        if exists(wrapper):
            require(stat.S_IMODE(wrapper.lstat().st_mode)==0o700,'existing_wrapper_permissions_not_700')
            require(safe_file(wrapper,uid)==WRAPPER,'existing_wrapper_not_recognized')
        payload=base/'payload';new_hashes={n:digest(raw) for n,raw in files.items()}
        old_hashes=inspect_payload(payload,list(allowed_payloads)+[new_hashes],uid) if exists(payload) else None
        archive=None
        if old_hashes!=new_hashes:
            staged=Path(tempfile.mkdtemp(prefix='payload-next-',dir=str(base)))
            for name,data in files.items():write_new(staged/name,data)
            sync_directory(staged)
            no_job(base,unit_paths,system_reader,wrapper,uid)
            if old_hashes is not None:
                require(inspect_payload(payload,list(allowed_payloads)+[new_hashes],uid)==old_hashes,'payload_changed_during_refresh')
                archive=Path(tempfile.mkdtemp(prefix='prelaunch-',dir=str(base)))
                os.rename(str(payload),str(archive/'payload'))
                sync_directory(archive)
            else:require(not exists(payload),'payload_appeared_during_install')
            os.rename(str(staged),str(payload));sync_directory(base)
        if not exists(wrapper):write_new(wrapper,WRAPPER,0o700);sync_directory(wrapper.parent)
        no_job(base,unit_paths,system_reader,wrapper,uid)
        result=dict(status='prelaunch-payload-ready',version='2.0.1',previous_payload_archived=archive.name if archive else None,
                    source_sha256=new_hashes,application_configuration_changes=0,job_state_changes=0)
        record_fd,record=tempfile.mkstemp(prefix='installation-',suffix='.json',dir=str(base))
        with os.fdopen(record_fd,'wb') as stream:
            stream.write((json.dumps(result,sort_keys=True)+'\n').encode());stream.flush();os.fsync(stream.fileno())
        sync_directory(base)
        if start:
            # Retain admission lock through the foreground preflight/launch.
            os.set_inheritable(lockfd,True)
            os.execve('/bin/bash',['/bin/bash',str(wrapper),'--apply'],
                      dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/root',LANG='C',LC_ALL='C',
                           VISIONLINE_INSTALLER_FD=str(lockfd)))
        return result
    finally:os.close(lockfd)
