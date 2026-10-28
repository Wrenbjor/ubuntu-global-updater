"""Exact, local, host-bound exclusions from HTTP health probes (Python3.6)."""
import hashlib,json,os,re,stat
from pathlib import Path
import host_identity
FILE='/etc/ubuntu-global-updater/health-exclusions.json'
_BOUND_POLICY=None
class HealthPolicyError(ValueError):pass
def need(value,code):
 if not value:raise HealthPolicyError(code)
def same(info):
 return (info.st_dev,info.st_ino,info.st_uid,info.st_gid,info.st_mode,info.st_nlink,info.st_size,info.st_mtime_ns)
def unique(pairs):
 result={}
 for key,value in pairs:
  need(key not in result,'duplicate_health_policy_key');result[key]=value
 return result
def hostname(value):
 if type(value) is not str or value!=value.lower() or not 1<=len(value)<=253:return False
 labels=value.split('.')
 return len(labels)>=2 and re.fullmatch(r'[a-z]{2,63}',labels[-1]) is not None and all(
  re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',label) is not None for label in labels)
def receipt(root='/',owner_uid=0):
 root=Path(root).resolve();path=root/FILE.lstrip('/')
 try:before=path.lstat()
 except FileNotFoundError:return dict(sha256=None,excluded_hosts=[])
 current=root
 for part in Path(FILE).parts[1:-1]:
  current=current/part;info=current.lstat()
  need(stat.S_ISDIR(info.st_mode) and info.st_uid==owner_uid and not info.st_mode&0o022,'unsafe_health_policy_parent')
 need(stat.S_ISREG(before.st_mode) and before.st_uid==owner_uid and stat.S_IMODE(before.st_mode)==0o600
      and before.st_nlink==1 and before.st_size<=8192,'unsafe_health_policy_file')
 fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd,'rb') as stream:opened=os.fstat(stream.fileno());raw=stream.read(8193)
 need(same(before)==same(opened)==same(path.lstat()) and len(raw)<=8192,'health_policy_read_race')
 try:value=json.loads(raw.decode('utf-8'),object_pairs_hook=unique)
 except (UnicodeError,json.JSONDecodeError):raise HealthPolicyError('invalid_health_policy_json')
 need(type(value) is dict and set(value)=={'schema','host_binding','excluded_hosts'} and type(value['schema']) is int
      and value['schema']==1,'invalid_health_policy_schema')
 try:host_identity.verify(value['host_binding'],root)
 except (host_identity.IdentityError,OSError):raise HealthPolicyError('health_policy_host_binding_mismatch')
 hosts=value['excluded_hosts']
 need(type(hosts) is list and 0<len(hosts)<=16 and all(hostname(host) for host in hosts),
      'exact_health_exclusion_hosts_required')
 need(len(hosts)==len(set(hosts)),'duplicate_health_exclusion_host')
 return dict(sha256=hashlib.sha256(raw).hexdigest(),excluded_hosts=sorted(hosts))
class BoundSpecs(list):
 def __init__(self,specs,policy,root='/',owner_uid=0):
  super().__init__(specs);self.policy=policy;self.root=root;self.owner_uid=owner_uid
def verify(policy,root='/',owner_uid=0):
 need(receipt(root,owner_uid)==policy,'health_exclusion_policy_changed')
 if _BOUND_POLICY is not None:need(policy==_BOUND_POLICY,'job_health_exclusion_policy_changed')
def bind_job(policy,root='/',owner_uid=0):
 global _BOUND_POLICY
 need(type(policy) is dict and set(policy)=={'sha256','excluded_hosts'},'job_health_policy_receipt_required')
 verify(policy,root,owner_uid)
 _BOUND_POLICY=json.loads(json.dumps(policy))
def filter_specs(specs,root='/',owner_uid=0):
 policy=receipt(root,owner_uid);excluded=set(policy['excluded_hosts'])
 if _BOUND_POLICY is not None:need(policy==_BOUND_POLICY,'job_health_exclusion_policy_changed')
 known={s['host'].lower() for s in specs}
 need(excluded<=known,'unknown_health_exclusion_host')
 kept=[s for s in specs if s['host'].lower() not in excluded]
 need(bool(kept),'health_exclusions_remove_all_probes')
 return BoundSpecs(kept,policy,root,owner_uid)
def verify_specs(specs):
 if isinstance(specs,BoundSpecs):verify(specs.policy,specs.root,specs.owner_uid)
