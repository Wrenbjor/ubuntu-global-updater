"""Old-Python/kernel handoff: v7 pidfd path, otherwise wait-only/no PID signals.

PID/start-ticks observations cannot make os.kill race-free. Where pidfd is not
available this adapter pauses only timers, waits <=60s for the canonical updater
to finish, then requires empty locks. It never force-kills or adopts a new owner.
"""
import os,signal
from pathlib import Path
import unattended_handoff_v7 as native
TIMERS=native.TIMERS;LOCKS=native.LOCKS;UPDATER=native.UPDATER
HandoffError=native.HandoffError;require=native.require;proc_stat=native.proc_stat
restore_timers=native.restore_timers;load_state=native.load_state
class PidfdUnavailable(HandoffError):pass
class System(native.System):
 def pidfd(self,pid):
  try:return super().pidfd(pid)
  except OSError as error:
   if getattr(error,'errno',None) in (22,38):raise PidfdUnavailable('kernel_pidfd_unavailable_no_signals')
   raise
 def writers(self,exclude):
  found=[]
  for directory in Path('/proc').iterdir():
   if not directory.name.isdecimal() or int(directory.name)==exclude:continue
   try:
    with (directory/'cmdline').open('rb') as stream:raw=stream.read(65537)
    require(len(raw)<=65536,'package_process_arguments_unverifiable')
    args=[x.decode('utf-8','strict') for x in raw.split(b'\0') if x]
    executable=os.readlink(str(directory/'exe'))
    if executable.endswith(' (deleted)'):executable=executable[:-10]
    if executable in ('/usr/bin/dpkg','/usr/bin/apt','/usr/bin/apt-get') or native.script_argument(args) in (UPDATER,'/usr/bin/do-release-upgrade'):found.append(int(directory.name))
   except (FileNotFoundError,ProcessLookupError):pass
  return found
def pidfd_available():return callable(getattr(os,'pidfd_open',None)) and callable(getattr(signal,'pidfd_send_signal',None))
def wait_without_pidfd(system,timeout,force,events):
 require(type(timeout) is int and 1<=timeout<=60,'grace_timeout_out_of_range')
 rows=system.locks();events.append(dict(event='pidfd_unavailable_wait_only_no_signals',force_requested=force,lock_owners=rows))
 if not rows:return events
 require(all(row['pid']>0 for row in rows),'unidentified_advisory_lock_owner')
 candidates=[]
 for pid in sorted({row['pid'] for row in rows if row['path'] in LOCKS[:2]}):
  try:process=system.process(pid)
  except (FileNotFoundError,ProcessLookupError):raise HandoffError('lock_owner_raced_recheck_required')
  if process['canonical'] and not process['shutdown_waiter']:candidates.append(process)
 require(len(candidates)==1,'busy_lock_not_one_canonical_unattended_updater')
 first=candidates[0];pid=first['pid']
 require(all(row['pid']==pid for row in rows),'foreign_lock_owner_no_wait_adoption')
 require(not system.children(pid) and not system.writers(pid),'active_package_writer_no_signal_or_adoption')
 deadline=system.clock()+timeout;exited=False
 while system.clock()<deadline:
  try:
   current=system.process(pid)
   require(current['start']==first['start'] and current['canonical'] and not current['shutdown_waiter'],'updater_identity_changed_no_signals')
  except (FileNotFoundError,ProcessLookupError):exited=True;break
  rows=system.locks();require(all(row['pid']==pid for row in rows),'foreign_lock_owner_no_wait_adoption')
  require(not system.children(pid) and not system.writers(pid),'active_package_writer_no_signal_or_adoption')
  system.sleep(min(.5,max(0,deadline-system.clock())))
 rows=system.locks();events.append(dict(event='pidfd_free_wait_finished',target_exited=exited,lock_owners=rows))
 require(exited and not rows,'pidfd_unavailable_updater_busy_requires_manual_completion')
 return events
def handoff(system,timeout=60,force=False,events=None):
 events=[] if events is None else events
 if not pidfd_available():return wait_without_pidfd(system,timeout,force,events)
 try:return native.handoff(system,timeout,force,events)
 except PidfdUnavailable:
  # Python may expose pidfd while the running kernel lacks it. No signal has
  # been sent when pidfd_open itself reports ENOSYS/EINVAL.
  return wait_without_pidfd(system,timeout,force,events)
def prepare(system,path,timeout,force,events=None):
 events=[] if events is None else events;saved={name:system.timer(name) for name in TIMERS};native.save_state(path,saved)
 try:
  for name in TIMERS:
   if saved[name]['active']:system.timer_action('stop',name)
  require(all(not system.timer(name)['active'] for name in TIMERS),'timers_still_active')
  handoff(system,timeout,force,events);require(not system.locks(),'locks_reappeared_before_main_APT');return events
 except BaseException:
  try:events.append(dict(event='failure_before_timer_restore',lock_owners=system.locks()))
  except Exception:events.append(dict(event='failure_lock_snapshot_unavailable'))
  restore_timers(system,saved);events.append(dict(event='previous_timer_states_restored'));raise
