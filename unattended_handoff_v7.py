"""Narrow unattended-upgrade handoff; default plan, never delete lock files."""
import argparse,json,os,re,select,signal,stat,subprocess,time
from datetime import datetime,timezone
from pathlib import Path
TIMERS=('apt-daily.timer','apt-daily-upgrade.timer')
LOCKS=('/var/lib/dpkg/lock-frontend','/var/lib/dpkg/lock','/var/lib/apt/lists/lock','/var/cache/apt/archives/lock')
UPDATER='/usr/bin/unattended-upgrade'
class HandoffError(Exception):pass
def require(value,code):
    if not value:raise HandoffError(code)
def proc_stat(raw):
    head,tail=raw.rsplit(')',1);v=tail.split()
    return dict(pid=int(head.split('(',1)[0]),state=v[0],ppid=int(v[1]),ticks=int(v[11])+int(v[12]),start=int(v[19]))
def lock_rows(raw,targets):
    rows=[]
    for line in raw.splitlines():
        v=line.split()
        if '->' in v:continue
        require(len(v)>=8,'malformed_kernel_lock_row')
        major,minor,inode=v[5].split(':');key=(int(major,16),int(minor,16),int(inode))
        if key in targets:rows.append(dict(path=targets[key],pid=int(v[4]),kind=v[1]))
    return rows
def script_argument(args):
    if not args:return ''
    if re.fullmatch(r'python3(?:\.[0-9]+)?',os.path.basename(args[0])):
        for value in args[1:]:
            if value in ('-c','-m'):return ''
            if not value.startswith('-'):return value
        return ''
    return args[0]

class System:
    clock=staticmethod(time.monotonic)
    sleep=staticmethod(time.sleep)
    def timer(self,name):
        require(name in TIMERS,'unknown_timer')
        p=subprocess.run(['/bin/systemctl','show',name,'--property=LoadState','--property=ActiveState','--property=UnitFileState'],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=10)
        require(p.returncode==0,'timer_query_failed')
        d=dict(line.split('=',1) for line in p.stdout.decode().splitlines() if '=' in line)
        require(d.get('ActiveState') in ('active','inactive','failed') and d.get('LoadState') in ('loaded','not-found'),'timer_state_unsettled')
        return dict(active=d['ActiveState']=='active',enabled=d.get('UnitFileState',''))
    def timer_action(self,action,name):
        require(name in TIMERS and action in ('stop','start'),'invalid_timer_action')
        p=subprocess.run(['/bin/systemctl',action,name],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
        require(p.returncode==0,'timer_action_failed')
    def locks(self):
        targets={};saved={}
        for name in LOCKS:
            try:
                info=os.lstat(name);require(stat.S_ISREG(info.st_mode) and info.st_uid==0,'unsafe_package_lock_path')
                key=(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino);targets[key]=name;saved[name]=(info.st_dev,info.st_ino)
            except FileNotFoundError:saved[name]=None
        result=lock_rows(Path('/proc/locks').read_text(),targets)
        for name,key in saved.items():
            try:
                i=os.lstat(name);require(stat.S_ISREG(i.st_mode) and (i.st_dev,i.st_ino)==key,'package_lock_path_changed')
            except FileNotFoundError:require(key is None,'package_lock_path_changed')
        return result
    def process(self,pid):
        root=Path('/proc')/str(pid);first=proc_stat((root/'stat').read_text())
        with (root/'cmdline').open('rb') as stream:raw=stream.read(65537)
        require(len(raw)<=65536,'process_arguments_unverifiable')
        args=[x.decode('utf-8','strict') for x in raw.split(b'\0') if x]
        uid=next(line.split()[1:3] for line in (root/'status').read_text().splitlines() if line.startswith('Uid:'))
        executable=os.readlink(root/'exe');disk=os.path.realpath('/usr/bin/python3')
        loaded=(root/'exe').stat();installed=os.stat(disk)
        script=script_argument(args)
        canonical=(script==UPDATER and uid==['0','0'] and executable==disk and (loaded.st_dev,loaded.st_ino)==(installed.st_dev,installed.st_ino))
        if canonical:
            for name in (UPDATER,disk):
                i=os.lstat(name);require(stat.S_ISREG(i.st_mode) and i.st_uid==0 and not i.st_mode&0o022,'unsafe_native_updater_file')
        counters=dict(line.split(':',1) for line in (root/'io').read_text().splitlines())
        after=proc_stat((root/'stat').read_text());require(first['start']==after['start'],'updater_pid_reused')
        return dict(after,canonical=canonical,shutdown_waiter=script.endswith('/unattended-upgrade-shutdown') and '--wait-for-signal' in args,writes=(int(counters['write_bytes']),int(counters['syscw'])))
    def children(self,pid):
        found=[]
        for directory in Path('/proc').iterdir():
            if directory.name.isdecimal():
                try:
                    if proc_stat((directory/'stat').read_text())['ppid']==pid:found.append(int(directory.name))
                except (FileNotFoundError,ProcessLookupError):pass
        return found
    def writers(self,exclude):
        found=[]
        for directory in Path('/proc').iterdir():
            if not directory.name.isdecimal() or int(directory.name)==exclude:continue
            try:
                with (directory/'cmdline').open('rb') as stream:raw=stream.read(65537)
                require(len(raw)<=65536,'package_process_arguments_unverifiable')
                args=[x.decode('utf-8','strict') for x in raw.split(b'\0') if x]
                executable=os.readlink(directory/'exe').removesuffix(' (deleted)')
                if executable in ('/usr/bin/dpkg','/usr/bin/apt','/usr/bin/apt-get') or script_argument(args) in (UPDATER,'/usr/bin/do-release-upgrade'):found.append(int(directory.name))
            except (FileNotFoundError,ProcessLookupError):pass
        return found
    def pidfd(self,pid):
        require(hasattr(os,'pidfd_open') and hasattr(signal,'pidfd_send_signal'),'pidfd_required_no_PID_signal_fallback')
        return os.pidfd_open(pid,0)
    def exited(self,fd):
        poll=select.poll();poll.register(fd,select.POLLIN);return bool(poll.poll(0))
    def send(self,fd,value):signal.pidfd_send_signal(fd,value,None,0)
    def close(self,fd):os.close(fd)

def restore_timers(system,saved):
    require(set(saved)==set(TIMERS),'timer_state_names_changed')
    for name in TIMERS:
        require(type(saved[name]) is dict and type(saved[name].get('active')) is bool and set(saved[name])=={'active','enabled'} and type(saved[name]['enabled']) is str,'invalid_saved_timer_state')
    failures=[]
    for name in TIMERS:
        try:
            if saved[name]['active'] and not system.timer(name)['active']:system.timer_action('start',name)
        except Exception:failures.append(name)
    require(not failures,'timer_restore_failed')

def pinned_process(system,pid,initial,fd):
    require(not system.exited(fd),'updater_exited')
    p=system.process(pid)
    require(p['pid']==pid and p['start']==initial['start'] and p['canonical'] and not p['shutdown_waiter'],'canonical_updater_identity_changed')
    return p
def force_loop(system,pid,initial,fd,events):
    # Explicit option only. CPU progress + no writes is a bounded loop indicator,
    # not proof of a globally safe termination. Never touch children or services.
    before=pinned_process(system,pid,initial,fd);system.sleep(2);after=pinned_process(system,pid,initial,fd)
    require(after['state'] in ('R','S') and after['ticks']>before['ticks'] and after['writes']==before['writes'],'no_safe_cpu_loop_evidence')
    require(not system.children(pid) and not system.writers(pid),'package_writer_or_child_present')
    frozen=False;killed=False
    try:
        frozen=True;system.send(fd,signal.SIGSTOP)
        deadline=system.clock()+3
        while system.clock()<deadline:
            p=pinned_process(system,pid,initial,fd)
            if p['state'] in ('T','t'):break
            system.sleep(.1)
        require(p['state'] in ('T','t') and p['writes']==after['writes'],'updater_did_not_freeze_without_writes')
        require(not system.children(pid) and not system.writers(pid),'frozen_updater_child_or_writer_present')
        rows=system.locks();require(any(x['pid']==pid and x['path'] in LOCKS[:2] for x in rows) and all(x['pid']==pid for x in rows),'frozen_lock_ownership_changed')
        pinned_process(system,pid,initial,fd)
        system.send(fd,signal.SIGKILL);killed=True;events.append(dict(event='explicit_force_killed_pinned_loop',pid=pid))
        deadline=system.clock()+5
        while not system.exited(fd) and system.clock()<deadline:system.sleep(.1)
        require(system.exited(fd),'targeted_kill_exit_unconfirmed')
    finally:
        if frozen and not killed and not system.exited(fd):system.send(fd,signal.SIGCONT)

def handoff(system,timeout=60,force=False,events=None):
    require(type(timeout) is int and 1<=timeout<=60,'grace_timeout_out_of_range')
    events=[] if events is None else events;rows=system.locks()
    events.append(dict(event="handoff_started",force_requested=force,lock_owners=rows))
    if not rows:return events
    require(all(x['pid']>0 for x in rows),'unidentified_advisory_lock_owner')
    candidates=[]
    for pid in sorted({x['pid'] for x in rows if x['path'] in LOCKS[:2]}):
        try:p=system.process(pid)
        except (FileNotFoundError,ProcessLookupError):raise HandoffError('lock_owner_raced_recheck_required')
        if p['canonical'] and not p['shutdown_waiter']:candidates.append(p)
    require(len(candidates)==1,'busy_lock_not_one_canonical_unattended_updater')
    initial=candidates[0];pid=initial['pid'];fd=system.pidfd(pid)
    try:
        pinned_process(system,pid,initial,fd)
        rows=system.locks();require(any(x['pid']==pid and x['path'] in LOCKS[:2] for x in rows),'updater_no_longer_owns_frontend_or_dpkg_lock')
        system.send(fd,signal.SIGTERM);events.append(dict(event='sent_sigterm_to_pinned_native_updater',pid=pid))
        deadline=system.clock()+timeout
        while system.clock()<deadline:
            if system.exited(fd):break
            system.sleep(min(.5,max(0,deadline-system.clock())))
        if not system.exited(fd):
            events.append(dict(event='grace_window_expired',pid=pid,target_exited=False,lock_owners=system.locks()))
            if force:force_loop(system,pid,initial,fd,events)
        require(system.exited(fd),'updater_still_running_no_main_APT')
        # Re-read kernel locks for at most five seconds after confirmed exit.
        # Never re-signal or adopt another owner; require an empty lock set.
        settle_deadline=system.clock()+5
        rows=system.locks()
        while rows and system.clock()<settle_deadline:
            system.sleep(min(.25,max(0,settle_deadline-system.clock())))
            rows=system.locks()
        events.append(dict(event='post_exit_lock_check',pid=pid,target_exited=True,lock_owners=rows))
        require(not rows,'remaining_lock_owners_after_updater_exit_no_main_APT')
        return events
    finally:system.close(fd)

def state_path(path):
    require(path.is_absolute() and path.name=='unattended-state.json' and path==path.resolve(),'absolute_private_state_path_required')
    info=path.parent.lstat();require(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,'root_private_state_parent_required')
def sync_parent(path):
    fd=os.open(str(path.parent),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def save_state(path,saved):
    state_path(path);fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),0o600);stream.write((json.dumps(dict(schema='unattended-handoff-v7',timers=saved,created_at=datetime.now(timezone.utc).isoformat()),sort_keys=True)+'\n').encode());stream.flush();os.fsync(stream.fileno())
    sync_parent(path)
def load_state(path):
    state_path(path);fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno());require(stat.S_ISREG(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o600 and info.st_size<=4096,'invalid_private_timer_state')
        raw=stream.read(4097)
    value=json.loads(raw);require(set(value)=={'schema','timers','created_at'} and value['schema']=='unattended-handoff-v7','unknown_timer_state_schema')
    return value['timers']
def prepare(system,path,timeout,force,events=None):
    events=[] if events is None else events
    saved={name:system.timer(name) for name in TIMERS};save_state(path,saved)
    try:
        for name in TIMERS:
            if saved[name]['active']:system.timer_action('stop',name)
        require(all(not system.timer(name)['active'] for name in TIMERS),'timers_still_active')
        handoff(system,timeout,force,events)
        require(not system.locks(),'locks_reappeared_before_main_APT')
        return events
    except BaseException:
        try:events.append(dict(event='failure_before_timer_restore',lock_owners=system.locks()))
        except Exception:events.append(dict(event='failure_lock_snapshot_unavailable'))
        restore_timers(system,saved)
        events.append(dict(event='previous_timer_states_restored'))
        raise
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('mode',choices=('plan','prepare','restore'),nargs='?',default='plan');p.add_argument('--state',type=Path);p.add_argument('--timeout',type=int,default=60);p.add_argument('--force-stuck-updater',action='store_true');a=p.parse_args()
    if a.mode=='plan':print(json.dumps(dict(mode='plan',production_changes=0,force_default=False)));return
    require(os.geteuid()==0 and a.state is not None,'root_and_private_state_required');system=System()
    def interrupted(signum,frame):raise HandoffError('handoff_interrupted')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    events=[]
    try:
        if a.mode=='restore':restore_timers(system,load_state(a.state));events=[]
        else:prepare(system,a.state,a.timeout,a.force_stuck_updater,events)
        print(json.dumps(dict(status='timers_restored' if a.mode=='restore' else 'handoff_ready_timers_paused',events=events)))
    except Exception as error:
        print(json.dumps(dict(status='handoff_failed_closed',force_requested=a.force_stuck_updater,events=events,error_type=type(error).__name__,error_code=str(error) if isinstance(error,HandoffError) else 'local_metadata_or_system_error')))
        raise SystemExit(1)
if __name__=='__main__':main()
