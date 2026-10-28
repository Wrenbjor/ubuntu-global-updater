"""Explicit recovery of the exact v2.1.1 Apache preflight failure only.

No package/configuration writes and no resumption of an old job. The caller
holds installer admission throughout prepare/apply/install. Evidence is copied,
fsynced, and retained before any original checkpoint is moved. Python3.6.
"""
import fcntl,hashlib,json,os,re,stat,tempfile
from pathlib import Path
import host_identity
import prelaunch_installer as installer

class RecoveryError(Exception):pass
def need(value,code):
    if not value:raise RecoveryError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
KNOWN_PAYLOAD = {'fpm_pool_parser.py': 'f2bcd43183791c1f1cb2b4affc17a232ee2184494b16fb9a441f824f36bca00a', 'health_policy.py': '9b10d5485721305f27b25cb395a99cd03ff036dcc80860acca33b5696832c76b', 'host_identity.py': '5186a627fd27971c29991b47a2a5739b53a0310934a43e08d01b85a208cb342d', 'php_legacy_packages.py': '5a081fc018b709b98717d9226d91c2f7971d58ea0ad5480ebb1dd8fdb47abadb', 'php_legacy_routing.py': 'a92b5cf952f77def23e32adfbac5aea540635b2eddd2872ebbdce4dec8e93e79', 'php_legacy_runner.py': 'aec8e2599a45307b32422565a026c42e7f9d04da825d0c3727ba0bbe2c17946e', 'ubuntu_global.py': '0f5aa5ebbf652626f3c94166e11e626ba1400fab9fc4099b3656f59ef8d508df', 'ubuntu_global_early.py': '67872bb704097189b413a853a942e9cb98599127b692e1c65d2378349c26b3ca', 'ubuntu_global_guard.py': '6e03904bc5c31f622214828c623200036117a7e425a4083f7dbdd895abffc9bc', 'ubuntu_global_handoff.py': 'dc0886dfe15bce3d36e7d2fb193ec763754ebb630f0f59b1047e25266ddf2bae', 'ubuntu_global_os.py': '9e9dfd0edfdd0beff94acbb8f2b0c445f693fed0c9d0dc76b6b8a3c8923d53bb', 'ubuntu_global_runtime.py': '198b82d97df6c6c465b8a5841745877476a9bbb192940ee18a57125d5ab2a3a3', 'ubuntu_global_support.py': 'd7c6ad7674e620f1ab84a40287be162706810abcf940aa418cb4e1df96d5f402', 'unattended_handoff_v7.py': 'caf30e5d501747dabdcb04947e28b93cb521006b24476c49c78edef043c1e6ca', 'updater_layout.py': 'fb5721081367b76113ea1f4db3460b2961f83c3e932578ad1ac51f0e77417f88', 'upgrade_state_guard_v10_1.py': 'e30ba445cb7fe2a4bc7fd7d8a5da705de5b0794364123df0914a44475694cb06'}
ERROR='Apache_PHP_requires_separate_migration_profile'

def unit_bytes(base):
    return ('[Unit]\nDescription=Ubuntu and runtime updater\nAfter=network-online.target\nWants=network-online.target\n'
      '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B '+str(base)+'/payload/ubuntu_global.py --worker\n'
      'TimeoutStartSec=infinity\nTimeoutStopSec=infinity\nKillMode=process\nRestart=no\nUMask=0077\n'
      '[Install]\nWantedBy=multi-user.target\n').encode()
def wrapper_bytes(base):
    return ('#!/bin/bash\nset -euo pipefail\nexec /usr/bin/python3 -B '+str(base)+'/payload/ubuntu_global.py "$@"\n').encode()
def unique_object(pairs):
    value={}
    for key,item in pairs:
        need(key not in value,'duplicate_recovery_state_key');value[key]=item
    return value
def tree(path,uid):
    """Bounded evidence inventory; reject symlinks, hardlinks and writable data."""
    result={};total=0
    def walk(item):
        nonlocal total
        info=item.lstat();relative=str(item.relative_to(path.parent))
        need(info.st_uid==uid and not info.st_mode&0o022,'unsafe_recovery_evidence')
        if stat.S_ISDIR(info.st_mode):
            need(item.resolve()==item,'recovery_symlink_parent')
            result[relative]=dict(kind='directory',mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
            for child in sorted(item.iterdir()):walk(child)
        else:
            raw=installer.safe_file(item,uid,16777216);total+=len(raw)
            need(total<=67108864 and len(result)<4096,'recovery_evidence_bound')
            result[relative]=dict(kind='file',sha256=sha(raw),size=len(raw),mode=stat.S_IMODE(info.st_mode),uid=info.st_uid,gid=info.st_gid)
    walk(path);return result
def manager_ok(value,unit):
    need(value.get('LoadState')=='loaded' and value.get('ActiveState')=='failed'
         and value.get('MainPID')=='0' and value.get('UnitFileState')=='disabled'
         and value.get('DropInPaths','')=='' and value.get('Job','') in ('','0'),
         'recovery_requires_disabled_failed_idle_unit')
    need(value.get('FragmentPath')==str(unit),'recovery_unit_fragment_mismatch')
def admission(fd,base,uid):
    need(type(fd) is int and fd>=3,'held_installer_admission_fd_required')
    info=os.fstat(fd);named=(base/'installer.lock').lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==uid and info.st_nlink==1
         and stat.S_IMODE(info.st_mode)==0o600 and (info.st_dev,info.st_ino)==(named.st_dev,named.st_ino)
         and not stat.S_ISLNK(named.st_mode),'unsafe_recovery_admission_fd')
    # Flock on a caller-owned FD adopts its open-file-description lock.
    fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
def namespace_ok(base,unit):
    layout=installer.layout
    if str(base) not in (layout.GENERIC_BASE,layout.LEGACY_BASE):return
    selected=layout.installer_layout()
    need(selected['base']==str(base),'recovery_namespace_drift')
    expected=str(Path('/etc/systemd/system')/selected['unit'])
    need(str(unit)==expected,'recovery_requires_canonical_persistent_unit')
    need(set(layout.namespace_artifacts(str(base)))=={str(base),expected},'recovery_namespace_has_other_artifacts')
    opposite=layout.LEGACY_UNIT if selected['unit']==layout.GENERIC_UNIT else layout.GENERIC_UNIT
    other=installer.native_unit_state(opposite)
    need(other.get('LoadState')=='not-found' and other.get('MainPID')=='0'
         and other.get('ActiveState') in ('inactive','failed'),'opposite_recovery_unit_loaded')
def prepare_recovery(base,wrapper,unit_path,system_reader,admission_fd,
                     owner_uid=0,identity_root=Path('/')):
    base,wrapper,unit=Path(base),Path(wrapper),Path(unit_path)
    installer.directory(base,owner_uid);admission(admission_fd,base,owner_uid)
    namespace_ok(base,unit)
    installer.wrapper_parent(wrapper,owner_uid)
    installer.wrapper_parent(unit,owner_uid)
    need(stat.S_IMODE(wrapper.lstat().st_mode)==0o700 and installer.safe_file(wrapper,owner_uid)==wrapper_bytes(base),'unrecognized_recovery_wrapper')
    need(installer.safe_file(unit,owner_uid)==unit_bytes(base),'unrecognized_recovery_unit')
    manager_ok(system_reader(),unit)
    installer.no_running_payload(base,wrapper,owner_uid)
    payload=installer.inspect_payload(base/'payload',[KNOWN_PAYLOAD],owner_uid)
    raw=installer.safe_file(base/'state.json',owner_uid)
    need(stat.S_IMODE((base/'state.json').lstat().st_mode)==0o600,'unsafe_recovery_state_mode')
    state=json.loads(raw.decode(),object_pairs_hook=unique_object)
    allowed={'schema','status','identity','host_binding','services','health','completed','operation_running','updated_at','error'}
    need(set(state)<=allowed and state.get('schema')==2 and state.get('status')=='failed-needs-review'
         and state.get('error')==ERROR and type(state.get('completed')) is list and state['completed']==[]
         and state.get('operation_running') is False,'checkpoint_not_exact_preflight_failure')
    host_identity.verify(state.get('host_binding'),identity_root)
    need(state.get('identity',{}).get('machine_id')==state['host_binding']['machine_id'],'recovery_original_identity_mismatch')
    # Only known code-installation history and the early worker artifacts exist.
    # Authenticated repository evidence stays in place; it is never discarded.
    archive_names=[];preserved=[];inventory={}
    for item in sorted(base.iterdir()):
        name=item.name
        if name=='installer.lock':continue
        if re.fullmatch(r'local-PHP-(?:source|packages)-[A-Za-z0-9_-]+',name):
            need(item.is_dir(),'invalid_local_source_evidence');preserved.append(name)
        elif name in ('payload','state.json','worker.lock','events.jsonl','unattended-state.json') or re.fullmatch(r'installation-[A-Za-z0-9_-]+\.json',name) or re.fullmatch(r'prelaunch-[A-Za-z0-9_-]+',name):
            archive_names.append(name)
        else:raise RecoveryError('unknown_or_postpreflight_job_artifact')
        inventory.update(tree(item,owner_uid))
    need('worker.lock' in archive_names,'missing_preflight_worker_marker')
    lockfd=os.open(str(base/'worker.lock'),os.O_RDWR|os.O_NOFOLLOW)
    try:fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
    finally:os.close(lockfd)
    return dict(schema=1,status='eligible-exact-preflight-failure',base=str(base),wrapper=str(wrapper),unit=str(unit),
       state_sha256=sha(raw),payload_sha256=payload,inventory=inventory,archive_names=archive_names,preserved_names=preserved,
       unit_sha256=sha(unit_bytes(base)),host_binding=state['host_binding'])

def apply_recovery(reviewed,system_reader,unit_control,admission_fd,owner_uid=0,identity_root=Path('/')):
    """Caller explicitly opts in, retains admission and refreshes payload afterward.

    unit_control('daemon-reload'/'reset-failed') must raise on failure. This module
    leaves the wrapper and installer lock untouched. Any partial failure stops.
    """
    base=Path(reviewed['base']);worker=None
    try:
        current=prepare_recovery(base,reviewed['wrapper'],reviewed['unit'],system_reader,admission_fd,owner_uid,identity_root)
        need(current==reviewed,'preflight_recovery_plan_drift')
        worker=os.open(str(base/'worker.lock'),os.O_RDWR|os.O_NOFOLLOW)
        fcntl.flock(worker,fcntl.LOCK_EX|fcntl.LOCK_NB)
        # Recheck state, code and process inventory while both locks are held.
        # prepare's probe lock would conflict with our worker descriptor.
        installer.no_running_payload(base,Path(reviewed['wrapper']),owner_uid)
        namespace_ok(base,Path(reviewed['unit']))
        manager_ok(system_reader(),Path(reviewed['unit']))
        need(sha(installer.safe_file(base/'state.json',owner_uid))==reviewed['state_sha256'],'recovery_state_drift')
        need(installer.inspect_payload(base/'payload',[KNOWN_PAYLOAD],owner_uid)==reviewed['payload_sha256'],'recovery_payload_drift')
        inventory={}
        for name in reviewed['archive_names']+reviewed['preserved_names']:inventory.update(tree(base/name,owner_uid))
        need(inventory==reviewed['inventory'],'recovery_evidence_drift')
        evidence=Path(tempfile.mkdtemp(prefix='recovered-preflight-',dir=str(base)))
        # Copy the original external unit durably before unlinking it.
        unit=Path(reviewed['unit']);raw=installer.safe_file(unit,owner_uid)
        need(sha(raw)==reviewed['unit_sha256'],'recovery_unit_drift')
        installer.write_new(evidence/'unit-before',raw)
        installer.write_new(evidence/'recovery-plan.json',(json.dumps(reviewed,sort_keys=True)+'\n').encode())
        installer.sync_directory(evidence);installer.sync_directory(base)
        for name in reviewed['archive_names']:
            os.rename(str(base/name),str(evidence/name));installer.sync_directory(evidence);installer.sync_directory(base)
        need(installer.safe_file(unit,owner_uid)==raw,'recovery_unit_changed_before_unlink')
        os.unlink(str(unit));installer.sync_directory(unit.parent)
        unit_control('daemon-reload');unit_control('reset-failed')
        after=system_reader()
        need(after.get('LoadState')=='not-found' and after.get('MainPID')=='0'
             and after.get('ActiveState') in ('inactive','failed'),'recovery_unit_still_loaded')
        return dict(status='exact-preflight-archived',evidence=evidence.name,preserved_names=reviewed['preserved_names'],application_configuration_changes=0)
    finally:
        if worker is not None:os.close(worker)
