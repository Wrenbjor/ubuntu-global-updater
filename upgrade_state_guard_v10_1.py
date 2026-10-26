"""Read-only handoff from the old OS/PHP workflow; never alter its checkpoint."""
import json,os,stat
from pathlib import Path

def allowed(state):
    if not isinstance(state,dict):return False
    if state.get('error') is not None or state.get('failed_part') is not None:return False
    phase=state.get('phase');php=state.get('php_phase')
    if phase not in (None,'part1-complete','part2-complete'):return False
    if php not in (None,'complete'):return False
    return phase=='part1-complete' or php=='complete'

def read_state(path):
    first=path.lstat()
    if not stat.S_ISREG(first.st_mode) or first.st_uid!=0 or first.st_mode&0o022 or first.st_nlink!=1 or first.st_size>65536:
        raise ValueError('unsafe_upgrade_state_file')
    def identity(value):
        return (value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_uid,value.st_gid,stat.S_IMODE(value.st_mode),value.st_nlink)
    try:fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
    except FileNotFoundError:raise ValueError('observed_upgrade_state_disappeared')
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno());data=stream.read(65537)
    if identity(opened)!=identity(first) or len(data)>65536:
        raise ValueError('upgrade_state_changed_while_reading')
    try:last=path.lstat()
    except FileNotFoundError:raise ValueError('observed_upgrade_state_disappeared')
    if identity(last)!=identity(first):
        raise ValueError('upgrade_state_changed_while_reading')
    def unique(pairs):
        result={}
        for key,value in pairs:
            if key in result:raise ValueError('duplicate_upgrade_state_key')
            result[key]=value
        return result
    return json.loads(data,object_pairs_hook=unique)

def main():
    path=Path('/var/lib/ubuntu-php-upgrade/progress.json')
    try:state=read_state(path)
    except FileNotFoundError:
        # A dangling symlink is not equivalent to an absent checkpoint.
        if path.is_symlink():return 1
        return 0
    except Exception:
        print('{"status":"upgrade_state_requires_review","reason":"unreadable_or_unsafe_checkpoint"}')
        return 1
    if not allowed(state):
        print('{"status":"upgrade_state_requires_review","reason":"unfinished_or_failed_workflow"}')
        return 1
    print('{"status":"upgrade_state_handoff_accepted","checkpoint_preserved":true}')
    return 0

if __name__=='__main__':raise SystemExit(main())
