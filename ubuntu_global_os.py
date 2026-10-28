"""Host-local sequential Ubuntu LTS adapter. Import/plan have no side effects.

Parent owns the retained systemd worker, updater lock, APT timers, config backup,
vendor-source restoration and explicit reboot. No package child has a timeout.
NativeBackend callbacks are mandatory: snapshot_reader(), preflight_checks(plan)
and postinstall_checks(plan). Both check callbacks return {check_name: True}.
The parent must require identity/config/boot/space/service checks in those maps.
No failed or interrupted checkpoint is automatically retried or overwritten.
"""
import configparser,copy,hashlib,importlib,importlib.util,json,os,re,select,stat,subprocess,sys,tarfile,types,urllib.request
from pathlib import Path,PurePosixPath

class OSHold(Exception):pass
HOPS={'18.04':('20.04','bionic','focal'),'20.04':('22.04','focal','jammy'),'22.04':('24.04','jammy','noble')}
TARGET='24.04'
ENV=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/root',LANG='C',LC_ALL='C',DEBIAN_FRONTEND='noninteractive',UCF_FORCE_CONFFOLD='1',APT_LISTCHANGES_FRONTEND='none',NEEDRESTART_MODE='l',NEEDRESTART_SUSPEND='y',RELEASE_UPGRADER_NO_SCREEN='1')
REQUIRED_CHECKS=('identity','configuration_backup','package_guard','boot_targets','disk_space','services','no_active_installer')
POST_CHECKS=('identity','configuration_preserved','services','boot_targets','vendor_sources_restored')
def need(value,code):
 if not value:raise OSHold(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()
def snapshot_hash(snapshot):return digest(canonical(snapshot))
def private_read(path,bound=8388608):
 path=Path(path);before=path.lstat();fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:
  opened=os.fstat(stream.fileno());raw=stream.read(bound+1)
 after=path.lstat()
 def identity(i):return (i.st_dev,i.st_ino,i.st_size,i.st_mtime_ns,i.st_uid,i.st_mode,i.st_nlink)
 need(stat.S_ISREG(opened.st_mode) and opened.st_uid==0 and not opened.st_mode&0o077 and opened.st_nlink==1 and len(raw)<=bound and identity(before)==identity(opened)==identity(after),'unsafe_or_changed_private_OS_file')
 return raw
def save_new(path,value):
 path=Path(path);fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
 with os.fdopen(fd,'wb') as f:f.write(canonical(value)+b'\n');f.flush();os.fsync(f.fileno())
 fd=os.open(str(path.parent),os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
def replace_bound_private(path,value,expected):
 path=Path(path);need(digest(private_read(path))==expected,'owned_OS_baseline_changed')
 temporary=path.with_name(path.name+'.visionline-os-next')
 save_new(temporary,value)
 need(digest(private_read(path))==expected,'owned_OS_baseline_race')
 os.replace(temporary,path)
 fd=os.open(str(path.parent),os.O_DIRECTORY|os.O_NOFOLLOW)
 try:os.fsync(fd)
 finally:os.close(fd)
 return digest(private_read(path))
def old_progress_allowed(value):
 if value is None:return True
 if type(value) is not dict or value.get('error') not in (None,False) or value.get('failed_part') is not None:return False
 return value.get('phase') in ('part1-complete','part2-complete') and value.get('php_phase') in (None,'complete')
def plan(snapshot,checkpoint=None):
 """Pure deterministic next action. Only sequential LTS hops; no downgrade."""
 release=snapshot.get('release')
 if release not in (*HOPS,TARGET):return dict(action='hold',reason='unsupported_Ubuntu_release',release=release)
 if snapshot.get('ubuntu') is not True:return dict(action='hold',reason='Ubuntu_identity_required')
 if not old_progress_allowed(snapshot.get('old_progress')):return dict(action='hold',reason='prior_failed_or_partial_workflow_preserved')
 if checkpoint:
  need(checkpoint.get('stage')=='ubuntu-global-os' and checkpoint.get('machine_id')==snapshot.get('machine_id'),'OS_checkpoint_identity_mismatch')
  need(checkpoint.get('from_release') in HOPS and checkpoint.get('to_release')==HOPS[checkpoint['from_release']][0] and bool(checkpoint.get('boot_id')),'OS_checkpoint_path_invalid')
  status=checkpoint.get('status')
  if status=='installed-pending-reboot':
   need(release==checkpoint['to_release'],'OS_pending_target_release_changed')
   if snapshot.get('boot_id')==checkpoint.get('boot_id'):return dict(action='reboot',from_release=checkpoint['from_release'],to_release=checkpoint['to_release'],reason='completed_hop_requires_new_boot')
   return dict(action='verify-hop',from_release=checkpoint['from_release'],to_release=checkpoint['to_release'],reason='new_boot_requires_acceptance')
  if status!='boot-verified':return dict(action='hold',reason='existing_OS_job_no_blind_retry',status=status)
  need(release==checkpoint['to_release'] and snapshot.get('boot_id')==checkpoint['accepted_boot_id'],'accepted_OS_boot_drift')
 if snapshot.get('active_package_work') is not False:return dict(action='hold',reason='active_or_unknown_installer')
 if snapshot.get('dpkg_clean') is not True or snapshot.get('holds')!=[]:return dict(action='hold',reason='unclean_or_held_packages')
 if snapshot.get('reboot_required') is not False:return dict(action='reboot',to_release=release,reason='prerequisite_reboot_required')
 if release==TARGET:return dict(action='complete',release=TARGET,OS_only=True)
 to_release,source,target=HOPS[release]
 need(bool(snapshot.get('machine_id')) and bool(snapshot.get('boot_id')),'OS_identity_or_boot_missing')
 return dict(stage='ubuntu-global-os',action='upgrade',from_release=release,to_release=to_release,from_codename=source,to_codename=target,machine_id=snapshot['machine_id'],boot_id=snapshot['boot_id'],snapshot_sha256=snapshot_hash(snapshot))
def checked_proof(value,keys,code):
 need(type(value) is dict and all(value.get(k) is True for k in keys),code);return value
def guard_files(proof):
 for pathkey,hashkey,mode in [('path','sha256',False),('configpath','configsha256',False),('baselinepath','baselinesha256',True)]:
  p=Path(proof[pathkey]);need(p.is_absolute(),'absolute_guard_path_required')
  if mode:raw=private_read(p)
  else:
   i=p.lstat();need(stat.S_ISREG(i.st_mode) and i.st_uid==0 and not i.st_mode&0o022 and i.st_nlink==1 and i.st_size<=8388608,'unsafe_OS_guard_file');raw=p.read_bytes()
  need(digest(raw)==proof[hashkey],'OS_guard_hash_changed')
 return True
def execute(decision,workdir,backend,guard_proof):
 """Foreground one-use apply, to be invoked in parent's durable no-timeout unit.

Returns pending-reboot only after native exit, exact target, clean dpkg AND all
parent postconditions. Failed proof records failure/holds, never retries/reboots.
"""
 need(decision.get('action')=='upgrade','OS_upgrade_decision_required')
 current=backend.snapshot();need(snapshot_hash(current)==decision['snapshot_sha256'] and plan(current)==decision,'OS_preflight_baseline_changed')
 checked_proof(backend.preflight_checks(decision),REQUIRED_CHECKS,'OS_parent_preflight_proof_required')
 guard_files(guard_proof)
 job=Path(workdir);need(job.is_absolute() and not job.exists(),'new_private_OS_job_required')
 parent=job.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==0 and not parent.st_mode&0o077 and job.parent.resolve()==job.parent,'private_OS_job_parent_required')
 job.mkdir(mode=0o700)
 spec=dict(decision=decision,guard=guard_proof,module_sha256=digest(Path(__file__).read_bytes()))
 save_new(job/'spec.json',spec)
 receipt=dict(stage='ubuntu-global-os',status='installing',machine_id=decision['machine_id'],from_release=decision['from_release'],to_release=decision['to_release'],boot_id=decision['boot_id'],spec_sha256=digest((job/'spec.json').read_bytes()),automatic_reboot=False)
 save_new(job/'installing.json',receipt)
 try:
  backend.upgrade(decision,job,guard_proof)
  after=backend.snapshot();need(after.get('machine_id')==decision['machine_id'] and after.get('boot_id')==decision['boot_id'] and after.get('release')==decision['to_release'] and after.get('dpkg_clean') is True and after.get('active_package_work') is False,'native_OS_exit_not_verified')
  post=checked_proof(backend.postinstall_checks(decision),POST_CHECKS,'OS_parent_postinstall_hold')
  receipt.update(status='installed-pending-reboot',postconditions=post);save_new(job/'installed-pending-reboot.json',receipt);return receipt
 except BaseException as error:
  receipt.update(status='failed-preserve-no-retry',error_code=str(error) if isinstance(error,OSHold) else 'native_OS_failure_requires_diagnosis')
  save_new(job/'failed.json',receipt);raise
def read_checkpoint(workdir):
 """Read immutable receipts with failure precedence; never adopt/retry a job."""
 job=Path(workdir);info=job.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and not info.st_mode&0o077 and job.resolve()==job,'unsafe_OS_checkpoint_directory')
 specraw=private_read(job/'spec.json');spec=json.loads(specraw)
 for name in ('failed.json','installed-pending-reboot.json','installing.json'):
  path=job/name
  if path.exists() or path.is_symlink():
   value=json.loads(private_read(path));need(value.get('spec_sha256')==digest(specraw) and value.get('machine_id')==spec['decision']['machine_id'],'OS_receipt_binding_changed');return value
 raise OSHold('OS_checkpoint_missing_requires_diagnosis')
def accept_boot(checkpoint,snapshot,proof):
 need(checkpoint.get('status')=='installed-pending-reboot','OS_reboot_checkpoint_required')
 need(checkpoint.get('from_release') in HOPS and checkpoint.get('to_release')==HOPS[checkpoint['from_release']][0],'OS_checkpoint_path_invalid')
 need(snapshot.get('release')==checkpoint['to_release'] and snapshot.get('machine_id')==checkpoint['machine_id'] and snapshot.get('boot_id') and snapshot['boot_id']!=checkpoint['boot_id'],'OS_new_target_boot_required')
 need(snapshot.get('dpkg_clean') is True and snapshot.get('active_package_work') is False and snapshot.get('reboot_required') is False,'OS_postboot_not_clean')
 checked_proof(proof,('configuration_preserved','services','boot_targets','target_kernel','vendor_sources_restored'),'OS_postboot_proof_required')
 return dict(checkpoint,status='boot-verified',accepted_boot_id=snapshot['boot_id'],boot_checks=proof)

def installed_versions():
 result=subprocess.run(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${db:Status-Abbrev}\n'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=30,env=ENV)
 need(result.returncode==0,'OS_package_metadata_unavailable');rows={}
 for line in result.stdout.decode().splitlines():
  name,version,status=line.split('\t');name=name.split(':',1)[0]
  if status.strip() in ('rc','un','pn'):continue
  need(name not in rows,'OS_multiarch_inventory_requires_review');rows[name]=version
 return rows
def cache_actions(packages,installed):
 actions=[]
 for pkg in packages:
  name=pkg.name.split(':',1)[0];old=installed.get(name)
  if pkg.marked_delete:
   need(old is not None,'OS_removal_unknown_package');actions.append(dict(name=name,old=old,new=None,action='remove'));continue
  candidate=getattr(pkg,'candidate',None);need(candidate is not None,'OS_candidate_missing');new=candidate.version
  if new==old:continue
  actions.append(dict(name=name,old=old,new=new,action='install' if old is None else 'upgrade'))
 need(len(actions)<=10000,'OS_transaction_bound');return actions
def load_guard(proof):
 guard_files(proof);spec=importlib.util.spec_from_file_location('visionline_global_OS_guard',proof['path']);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 baseline=json.loads(private_read(proof['baselinepath']));need(Path('/etc/machine-id').read_text().strip()==baseline['machine_id'],'OS_guard_machine_identity_changed')
 return module,baseline
def preserve_conffile_options(config):
 options=list(config.value_list('DPkg::Options'))
 need(not any(option in ('--force-confnew','--force-confmiss') for option in options),'conflicting_native_conffile_policy')
 if '--force-confold' not in options:config.set('DPkg::Options::','--force-confold')
def install_frontend(decision,guard_proof,event):
 """Guard native confirmChanges AND every real/simulated cache commit."""
 import apt,apt_pkg
 from DistUpgrade.DistUpgradeViewNonInteractive import DistUpgradeViewNonInteractive,NonInteractiveInstallProgress
 from DistUpgrade.DistUpgradeView import InstallProgress
 from DistUpgrade.DistUpgradeCache import MyCache
 from DistUpgrade.DistUpgradeController import DistUpgradeController
 from aptsources.sourceslist import SourcesList
 marker=dict(confirmed=False,committing=False,package_error=False,commits=0)
 def check(packages,refresh=False):
  module,baseline=load_guard(guard_proof);rows=installed_versions();actions=cache_actions(packages,rows)
  baseline=copy.deepcopy(baseline);baseline['packages']=rows
  for action in actions:
   need(action['old'] is None or action['new'] is None or apt_pkg.version_compare(action['new'],action['old'])>=0,'OS_package_downgrade_forbidden')
  need(module.validate_actions(actions,baseline,phase='os') is not False,'OS_policy_refused')
  if refresh:
   guard_proof['baselinesha256']=replace_bound_private(guard_proof['baselinepath'],baseline,guard_proof['baselinesha256'])
   event(dict(stage='native-APT-baseline-refreshed',sha256=guard_proof['baselinesha256']))
  event(dict(stage='native-transaction-validated',actions=len(actions),sha256=digest(canonical(actions))))
  return actions
 class SafeProgress(NonInteractiveInstallProgress):
  def error(self,pkg,message):marker['package_error']=True;event(dict(stage='native-dpkg-error'))
  def conffile(self,current,new):os.write(self.master_fd,b'n\n')
  def update_interface(self):
   InstallProgress.update_interface(self)
   if self.statusfd is None:return
   while select.select([self.master_fd],[],[],.1)[0]:
    try:data=os.read(self.master_fd,65536)
    except OSError:return
    if not data:return
    sys.stdout.buffer.write(data);sys.stdout.buffer.flush()
 class NoRepair:
  def call(self,*a,**k):raise OSHold('native_automatic_repair_forbidden')
 class DistUpgradeViewVisionLineGlobal(DistUpgradeViewNonInteractive):
  def __init__(self,datadir=None,logdir=None):
   super().__init__(datadir,logdir);self._installProgress=SafeProgress(logdir)
  def confirmChanges(self,summary,changes,demotions,downloadSize,actions=None,removal_bold=True):
   need(not marker['confirmed'],'additional_native_transaction_requires_review');check(changes);marker['confirmed']=True;return True
  def getTerminal(self):return NoRepair()
  def askYesNoQuestion(self,*a,**k):raise OSHold('unknown_native_prompt')
  def askCancelContinueQuestion(self,*a,**k):raise OSHold('unknown_native_prompt')
  def confirmRestart(self):event(dict(stage='normal_reboot_deferred'));return False
 original_init=DistUpgradeController.__init__
 def init(controller,*a,**k):
  original_init(controller,*a,**k)
  need(controller.fromDist==decision['from_codename'] and controller.toDist==decision['to_codename'],'native_target_release_mismatch')
  for section,values in {'Distro':{'RemoveObsoletes':'False'},'NonInteractive':{'ForceOverwrite':'True','RealReboot':'False','DebugBrokenScripts':'False','TerminalTimeout':'2147483647'}}.items():
   for key,value in values.items():controller.config.set(section,key,value)
  for key,value in {'Acquire::Retries':'0','Acquire::http::Timeout':'30','Acquire::https::Timeout':'30','APT::Get::AllowUnauthenticated':'false','Acquire::AllowInsecureRepositories':'false','Acquire::AllowWeakRepositories':'false','Acquire::AllowDowngradeToInsecureRepositories':'false','Acquire::Check-Valid-Until':'true'}.items():apt_pkg.config.set(key,value)
  preserve_conffile_options(apt_pkg.config)
 DistUpgradeController.__init__=init
 original_commit=MyCache.commit;original_base=apt.Cache.commit
 def base_commit(cache,*a,**k):
  need(marker['committing'],'unguarded_native_APT_commit_forbidden');result=original_base(cache,*a,**k);need(result is True,'native_APT_commit_failed');return result
 def commit(cache,*a,**k):
  need(marker['confirmed'],'native_commit_before_confirmation');check(cache.get_changes(),refresh=True);marker['committing']=True;marker['commits']+=1
  try:result=original_commit(cache,*a,**k)
  finally:marker['committing']=False
  need(result is None and not marker['package_error'],'native_dpkg_failure_no_retry');return result
 apt.Cache.commit=base_commit;MyCache.commit=commit
 # Native source backups may contain credentials; parent owns private backups.
 SourcesList.backup=lambda *a,**k:None
 SourcesList.restore_backup=lambda *a,**k:(_ for _ in ()).throw(OSHold('native_source_rollback_requires_diagnosis'))
 module=types.ModuleType('DistUpgrade.DistUpgradeViewVisionLineGlobal');module.DistUpgradeViewVisionLineGlobal=DistUpgradeViewVisionLineGlobal;sys.modules[module.__name__]=module
 return marker

class NativeBackend:
 """Real foreground adapter. Parent MUST run execute in a retained no-timeout unit.

Callbacks preflight_checks/postinstall_checks perform actual config/boot/service
acceptance and vendor-source restoration. No default callback asserts success.
"""
 def __init__(self,snapshot_reader,preflight_checks,postinstall_checks):self.snapshot=snapshot_reader;self.preflight_checks=preflight_checks;self.postinstall_checks=postinstall_checks
 def upgrade(self,decision,job,guard_proof):
  target=decision['to_codename'];base='https://archive.ubuntu.com/ubuntu/dists/'+target+'-updates/main/dist-upgrader-all/current/'
  class NoRedirect(urllib.request.HTTPRedirectHandler):
   def redirect_request(self,*a,**k):raise OSHold('upgrader_redirect_forbidden')
  opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
  for suffix in ('.tar.gz','.tar.gz.gpg'):
   url=base+target+suffix
   with opener.open(url,timeout=30) as response:
    need(response.status==200 and response.geturl()==url,'official_upgrader_origin_changed');raw=response.read(16777217)
   need(len(raw)<=16777216,'official_upgrader_download_bound')
   fd=os.open(str(job/(target+suffix)),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
   with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
  result=subprocess.run(['/usr/bin/gpgv','--status-fd','1','--keyring','/usr/share/keyrings/ubuntu-archive-keyring.gpg',str(job/(target+'.tar.gz.gpg')),str(job/(target+'.tar.gz'))],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,env=ENV)
  need(result.returncode==0 and b'[GNUPG:] VALIDSIG ' in result.stdout,'official_upgrader_signature_failed')
  save_new(job/'archive-proof.json',dict(url=base,archive_sha256=digest((job/(target+'.tar.gz')).read_bytes()),signature_sha256=digest((job/(target+'.tar.gz.gpg')).read_bytes())))
  data=job/'upgrader';unpack(job/(target+'.tar.gz'),data)
  config=data/('DistUpgrade.cfg.'+decision['from_codename']);parser=configparser.ConfigParser(interpolation=None);parser.read(str(config))
  need(parser.get('Sources','From')==decision['from_codename'] and parser.get('Sources','To')==target,'signed_upgrader_release_path_mismatch')
  for section,items in {'Files':{'LogDir':str(job/'native-logs')},'Distro':{'RemoveObsoletes':'False'},'View':{'View':'DistUpgradeViewVisionLineGlobal'},'NonInteractive':{'ForceOverwrite':'True','RealReboot':'False','DebugBrokenScripts':'False','TerminalTimeout':'2147483647'}}.items():
   if not parser.has_section(section):parser.add_section(section)
   for key,value in items.items():parser.set(section,key,value)
  with config.open('w') as stream:parser.write(stream);stream.flush();os.fsync(stream.fileno())
  (job/'native-logs').mkdir(mode=0o700)
  guard_files(guard_proof)
  # No timeout and no signal on package child. Durable parent owns lifetime.
  with (job/'native-console.log').open('xb') as stream:
   os.chmod(stream.name,0o600)
   child=subprocess.Popen(['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'_worker',str(job)],stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,env=ENV)
   while True:
    try:child_code=child.wait();break
    except KeyboardInterrupt:
     # No subprocess.run exception path that kills a live package child.
     continue
  if (job/'guard-proof-after.json').exists():
   updated=json.loads(private_read(job/'guard-proof-after.json'));guard_files(updated)
   need(all(updated.get(k)==v for k,v in guard_proof.items() if k!='baselinesha256'),'OS_static_guard_proof_changed')
   guard_proof.update(updated)
  need(child_code==0,'native_upgrader_failed_preserve_no_retry')
def unpack(archive,destination):
 destination.mkdir(mode=0o700);seen={};total=0
 with tarfile.open(archive,'r:gz') as stream:
  for index,item in enumerate(stream):
   name=item.name[2:] if item.name.startswith('./') else item.name;p=PurePosixPath(name)
   need(index<3000 and not p.is_absolute() and '..' not in p.parts and '\\' not in name,'unsafe_upgrader_archive_path')
   if name in ('','.'):continue
   if item.isdir():
    (destination/name).mkdir(mode=0o700,parents=True,exist_ok=True);continue
   if item.issym() or item.islnk():continue
   need(item.isfile() and 0<=item.size<=16777216,'unsafe_upgrader_archive_type');total+=item.size;need(total<=100663296,'upgrader_archive_expansion_bound')
   raw=stream.extractfile(item).read(item.size+1);need(len(raw)==item.size,'upgrader_archive_member_size')
   if name in seen:need(digest(raw)==seen[name],'conflicting_upgrader_archive_duplicate');continue
   seen[name]=digest(raw)
   if '__pycache__' in p.parts or name.endswith(('.pyc','.pyo')):continue
   output=destination/name;output.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
   fd=os.open(str(output),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700 if item.mode&0o111 else 0o600)
   with os.fdopen(fd,'wb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
 need((destination/'DistUpgradeMain.py').is_file(),'signed_upgrader_main_missing')
def worker(job):
 job=Path(job);i=job.lstat();need(stat.S_ISDIR(i.st_mode) and i.st_uid==0 and not i.st_mode&0o077 and job.resolve()==job,'unsafe_OS_worker_directory')
 spec=json.loads(private_read(job/'spec.json'));decision=spec['decision'];proof=spec['guard'];guard_files(proof)
 need(digest(Path(__file__).read_bytes())==spec['module_sha256'],'OS_worker_module_changed')
 need(decision['from_release'] in HOPS and HOPS[decision['from_release']]==(decision['to_release'],decision['from_codename'],decision['to_codename']),'OS_worker_path_changed')
 need(Path('/etc/machine-id').read_text().strip()==decision['machine_id'],'OS_worker_machine_changed')
 release={}
 for line in Path('/etc/os-release').read_text().splitlines():
  if '=' in line:
   key,value=line.split('=',1);release[key]=value.strip('"')
 need(release.get('ID')=='ubuntu' and release.get('VERSION_ID')==decision['from_release'] and release.get('VERSION_CODENAME')==decision['from_codename'],'OS_worker_source_release_changed')
 need(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==decision['boot_id'],'OS_worker_boot_changed')
 data=job/'upgrader';os.chdir(data);sys.path.insert(0,str(data))
 package=types.ModuleType('DistUpgrade');package.__path__=[str(data)];package.__package__='DistUpgrade';sys.modules['DistUpgrade']=package
 def event(value):
  fd=os.open(str(job/'native-events.jsonl'),os.O_WRONLY|os.O_CREAT|os.O_APPEND|os.O_NOFOLLOW,0o600)
  try:os.write(fd,canonical(value)+b'\n');os.fsync(fd)
  finally:os.close(fd)
 marker=install_frontend(decision,proof,event)
 sys.argv=[str(data/'dist-upgrade.py'),'--frontend','DistUpgradeViewVisionLineGlobal','--disable-gnu-screen','--have-prerequists','--with-network','--datadir',str(data)]
 main=importlib.import_module('DistUpgrade.DistUpgradeMain')
 try:
  try:result=main.main()
  except SystemExit as exit:result=exit.code
 finally:save_new(job/'guard-proof-after.json',proof)
 need(result in (None,0) and marker['confirmed'] and marker['commits']>0 and not marker['package_error'],'native_OS_completion_not_proven')
if __name__=='__main__':
 if len(sys.argv)==3 and sys.argv[1]=='_worker':
  try:worker(sys.argv[2])
  except BaseException as error:
   print(str(error) if isinstance(error,OSHold) else 'native_OS_worker_failed',file=sys.stderr);raise SystemExit(1)
 else:print(json.dumps(dict(component='ubuntu_global_os',default='offline_plan_only',production_changes=0,apply='parent retained worker calls execute with mandatory proofs')))
