"""Jammy/Noble authenticated PHP8 migration, plus separate exact PHP7.4 removal.

Install path never removes packages. Separate retirement is remove-only, never
purge/autoremove. No repository edits, compilation, routing edits or service starts.
The caller must keep APT timers paused and hold its maintenance worker lock.
"""
import argparse,hashlib,json,os,re,stat,subprocess,sys,time
from pathlib import Path

class PackageError(Exception):pass
def need(value,code):
    if not value:raise PackageError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def module_digest():
    embedded=globals().get('__embedded_source_bytes__')
    need(embedded is None or type(embedded) is bytes and 0<len(embedded)<=1048576,'invalid_embedded_module_source')
    try:actual=Path(__file__).read_bytes()
    except FileNotFoundError:
        need(embedded is not None,'module_source_unavailable');return sha(embedded)
    if embedded is not None:need(actual==embedded,'embedded_and_materialized_module_differ')
    return sha(actual)
NAME=re.compile(r'^[a-z0-9][a-z0-9+.-]*$')
CORE=set('bcmath bz2 cli common curl dba dbg dev enchant fpm gd gmp imap interbase intl ldap mbstring mysql odbc opcache pgsql phpdbg pspell readline snmp soap sqlite3 sybase tidy xml xsl zip'.split())
UNBUNDLED_84={'imap':'php-imap','pspell':'php-pspell'}
PROTECTED=re.compile(r'^(?:php7\.4(?:-|$)|mysql|mariadb|percona|nginx|libnginx|redis|openssh|ssh$|nodejs|node-|libnode|apache2|libapache2)')
FLOOR='8.3.6-0ubuntu0.24.04.13'
FLOORS={'8.2':'8.2.35','8.3':'8.3.36','8.4':'8.4.27','8.5':'8.5.12'}
DISTROS={'22.04':'jammy','24.04':'noble'}
EXPIRY={'8.2':'2026-12-31','8.3':'2027-12-31','8.4':'2028-12-31','8.5':'2029-12-31'}
SECURITY_EVIDENCE={'PHP_advisory':'https://www.php.net/index.php','supported_versions':'https://www.php.net/supported-versions.php','Ubuntu_backport':'https://ubuntu.com/security/notices/USN-8948-1','PHP84_unbundled_extensions':'https://www.php.net/manual/en/migration84.removed-extensions.php','floors':FLOORS,'security_support_through':EXPIRY,'CVEs':['CVE-2026-109618','CVE-2026-109619']}
def supported(branch):return branch in EXPIRY and time.strftime('%Y-%m-%d',time.gmtime())<=EXPIRY[branch]
def validate_release(current):
    release=current['os'];need(release.get('ID')=='ubuntu' and release.get('VERSION_ID') in DISTROS and release.get('VERSION_CODENAME')==DISTROS[release['VERSION_ID']],'supported_Ubuntu_release_required')
def target_policy(branch):
    need(branch in FLOORS,'unsupported_target_branch')
    return ('#!/bin/sh\n[ "${1:-}" != --quiet ] || shift\ncase "${1:-}" in php'+branch+'-fpm|php'+branch+'-fpm.service) exit 101;; ""|-*) exit 102;; *) exit 0;; esac\n').encode()

def protected(name):return bool(PROTECTED.match(name))
def inspect_current(backend,allow_existing_target=False):
    current=backend.snapshot();rows=current['packages']
    validate_release(current)
    need(not current['container'],'container_migration_forbidden')
    need(not current['dirty'],'dpkg_not_clean')
    names=set(rows)
    need(not any(n.startswith(('apache2','libapache2-mod-php')) or re.match(r'php[0-9.]+-cgi$',n) for n in names),'Apache_or_CGI_migration_forbidden')
    branches={m.group(1) for n in names if (m:=re.match(r'^(?:php|libapache2-mod-php)([0-9]+\.[0-9]+)(?:-|$)',n))}
    need('7.4' in branches and (branches=={'7.4'} or allow_existing_target and len(branches)==2 and branches-{'7.4'}<=set(FLOORS)),'single_PHP74_or_explicit_dormant74_target_required')
    if not allow_existing_target:need(all('php7.4-'+s in rows for s in ('cli','common','fpm')),'CLI_common_FPM_required')
    need(all(r['status']=='ii' and r['architecture'] in (current['architecture'],'all') for r in rows.values()),'unsupported_package_state_or_multiarch')
    return current

def map_targets(current,target_branch='8.3'):
    need(target_branch in FLOORS,'unsupported_target_branch')
    old=sorted(n for n in current['packages'] if n=='php7.4' or n.startswith('php7.4-'))
    need(1<=len(old)<=100,'invalid_PHP74_inventory')
    targets=[];mapping={}
    for name in old:
        need(NAME.fullmatch(name) is not None,'invalid_package_name')
        suffix=name[len('php7.4'):]
        if suffix=='-json':mapping[name]='builtin:json';continue
        need(not suffix or suffix.startswith('-'),'unsupported_PHP_meta_package')
        target='php'+target_branch+suffix;mapping[name]=target;targets.append(target)
    return dict(mapping=mapping,targets=sorted(set(targets)))

def trusted(record,current):
    suite=current['os']['VERSION_CODENAME']
    return any(o['trusted'] is True and (
        o['origin']=='Ubuntu' and o['archive'] in (suite,suite+'-updates',suite+'-security',suite+'-backports') or
        o['origin']=='LP-PPA-ondrej-php' and o['archive']==suite and o['site'] in ('ppa.launchpad.net','ppa.launchpadcontent.net','ppa.setup-php.com')) for o in record['origins'])

def fixed_core(record,backend,current,target_branch):
    if target_branch not in FLOORS or record['source']!='php'+target_branch:return False
    def fixed(version):
        upstream=version.split(':')[-1].split('-')[0]
        modern=re.fullmatch(re.escape(target_branch)+r'\.[0-9]+(?:\+dfsg[0-9.]*)?',upstream) is not None and backend.compare(upstream,FLOORS[target_branch])>=0
        official=target_branch=='8.3' and current['os']['VERSION_CODENAME']=='noble' and any(o['trusted'] is True and o['origin']=='Ubuntu' and o['archive'] in ('noble','noble-updates','noble-security','noble-backports') for o in record['origins'])
        return modern or official and backend.compare(version,FLOOR)>=0 and re.fullmatch(r'(?:[0-9]+:)?8\.3\.6-0ubuntu0\.24\.04\.[0-9]+',version) is not None
    return fixed(record['version']) and fixed(record['source_version'])

def validate_candidate(name,record,current,backend,php=False,target_branch='8.3'):
    need(record is not None and NAME.fullmatch(name) is not None,'missing_candidate')
    need(record['architecture'] in (current['architecture'],'all') and trusted(record,current),'authenticated_same_release_candidate_required')
    need(re.fullmatch(r'[0-9a-f]{64}',record['sha256']) is not None,'authenticated_archive_SHA_required')
    need(record['filename'].startswith('pool/') and '..' not in record['filename'].split('/'),'invalid_archive_index_filename')
    if php:
        prefix='php'+target_branch;suffix=name.removeprefix(prefix+'-')
        need(name==prefix or name.startswith(prefix+'-'),'target_package_branch_mismatch')
        if target_branch in ('8.4','8.5') and suffix in UNBUNDLED_84:
            need(record['source']==UNBUNDLED_84[suffix],'unbundled_extension_source_mismatch')
        else:need(name!=prefix and suffix not in CORE or record['source']==prefix,'core_source_mismatch')
        release=current['os']['VERSION_ID'];foreign=({'20.04','22.04','24.04'}-{release})
        need(not any('ubuntu'+r in value for value in (record['version'],record['source_version']) for r in foreign),'foreign_release_PHP_binary')
        if any(o['origin']=='LP-PPA-ondrej-php' for o in record['origins']):need('ubuntu'+release in record['version'],'matching_release_PPA_build_required')
        need(record['source']==prefix or record['source'].startswith('php-'),'unexpected_extension_source')
        if record['source']==prefix:need(fixed_core(record,backend,current,target_branch),'unfixed_target_PHP_candidate')
    return record

def parse_simulation(text,current,candidates,backend,targets,target_branch='8.3'):
    changes={}
    for line in text.splitlines():
        need(not line.startswith(('Remv ','Purg ')),'package_removal_forbidden')
        if not line.startswith('Inst '):continue
        match=re.match(r'^Inst ([a-z0-9][a-z0-9+.-]*)(?::([a-z0-9]+))?(?: \[([^\]]+)\])? \(([^ ]+)',line)
        need(match is not None,'unrecognized_APT_simulation')
        name,arch,old,new=match.groups();need(name not in changes and not protected(name),'protected_package_change')
        need(name in targets or name in ('php-common','php-pear') or name.startswith('lib') and not name.startswith(('libphp','libapache2')),'unrelated_dependency_change')
        rec=candidates(name);validate_candidate(name,rec,current,backend,php=name in targets,target_branch=target_branch)
        need(rec['version']==new and (arch is None or arch==rec['architecture']),'candidate_or_architecture_drift')
        previous=current['packages'].get(name)
        need((old is None and previous is None) or previous is not None and previous['version']==old and previous['architecture']==rec['architecture'],'simulation_baseline_mismatch')
        need(old is None or backend.compare(new,old)>=0,'package_downgrade_forbidden')
        changes[name]=dict(old=old or '-',new=new,architecture=rec['architecture'],sha256=rec['sha256'],filename=rec['filename'])
    for name in set(targets)-set(changes):
        rec=candidates(name);need(current['packages'].get(name)==dict(version=rec['version'],architecture=rec['architecture'],status='ii'),'unchanged_target_not_exact_authenticated_candidate')
    need(len(changes)<=200,'transaction_too_large')
    # Admit only dependency changes reachable through real Depends/PreDepends.
    reached=set(targets);todo=list(targets)
    while todo:
        name=todo.pop()
        for group in candidates(name)['dependencies']:
            for dep in group:
                d=dep['name'].removesuffix(':any').removesuffix(':'+current['architecture'])
                if d not in changes or d in reached:continue
                if dep['version'] and not backend.satisfies(changes[d]['new'],dep['relation'],dep['version']):continue
                reached.add(d);todo.append(d)
    need(set(changes)<=reached,'unreachable_dependency_change')
    return changes

def select_target(backend,current,target_branch=None):
    choices=(target_branch,) if target_branch is not None else ('8.3','8.2','8.4','8.5')
    for branch in choices:
        need(branch in FLOORS,'unsupported_target_branch')
        if not supported(branch):
            if target_branch is not None:raise PackageError('target_branch_security_support_expired')
            continue
        mapped=map_targets(current,branch)
        try:
            for name in mapped['targets']:validate_candidate(name,backend.candidate(name),current,backend,True,branch)
            return branch
        except PackageError:
            if target_branch is not None:raise
    raise PackageError('no_secure_configured_same_release_extension_complete_target')

def prepare_plan(backend,target_branch=None):
    current=inspect_current(backend);branch=select_target(backend,current,target_branch);mapped=map_targets(current,branch)
    records={n:validate_candidate(n,backend.candidate(n),current,backend,True,branch) for n in mapped['targets']}
    pins={n:r['version'] for n,r in records.items()}
    simulated=backend.simulate(pins)
    changes=parse_simulation(simulated,current,backend.candidate,backend,set(pins),branch)
    records.update({n:backend.candidate(n) for n in changes})
    need(backend.snapshot()==current,'baseline_changed_during_prepare')
    return dict(schema='php74-to8-v10',target_branch=branch,distro=current['os']['VERSION_CODENAME'],baseline=current,**mapped,pins=pins,candidates=records,changes=changes,module_sha256=module_digest(),security_evidence=SECURITY_EVIDENCE,latest_definition='8.3 then8.2 then8.4 then8.5: supported configured authenticated same-release candidate; no repository edits')

def prepare_existing_patch(backend,branch,dormant_assertion):
    current=inspect_current(backend,allow_existing_target=True)
    branches={m.group(1) for n in current['packages'] if (m:=re.match(r'^php([0-9]+\.[0-9]+)(?:-|$)',n))}
    need(branches=={'7.4',branch} and supported(branch),'existing_target_branch_required_no_downgrade')
    validate_health(dormant_assertion,current,branch)
    need(all('php'+branch+'-'+s in current['packages'] for s in ('cli','common','fpm')),'existing_target_core_required')
    mapped=map_targets(current,branch);targets=sorted(set(mapped['targets'])|{n for n in current['packages'] if n=='php'+branch or n.startswith('php'+branch+'-')})
    records={n:validate_candidate(n,backend.candidate(n),current,backend,True,branch) for n in targets}
    for name,record in records.items():
        row=current['packages'].get(name)
        need(row is None or backend.compare(record['version'],row['version'])>=0,'existing_target_downgrade_forbidden')
    pins={n:r['version'] for n,r in records.items()};changes=parse_simulation(backend.simulate(pins),current,backend.candidate,backend,set(pins),branch)
    records.update({n:backend.candidate(n) for n in changes});need(backend.snapshot()==current,'existing_patch_baseline_changed_during_prepare')
    return dict(schema='php74-to8-v10',mode='existing-target-patch',target_branch=branch,distro=current['os']['VERSION_CODENAME'],baseline=current,mapping=mapped['mapping'],targets=targets,pins=pins,candidates=records,changes=changes,dormant_assertion=dormant_assertion,module_sha256=module_digest(),security_evidence=SECURITY_EVIDENCE,latest_definition='preserve existing higher branch; patch exact configured authenticated same-release candidate')

def recheck(backend,plan):
    need(plan['schema']=='php74-to8-v10' and plan['module_sha256']==module_digest(),'plan_or_module_changed')
    need(supported(plan['target_branch']),'target_branch_security_support_expired')
    need(backend.snapshot()==plan['baseline'],'baseline_changed_before_install')
    if plan.get('mode')=='existing-target-patch':validate_health(plan['dormant_assertion'],plan['baseline'],plan['target_branch'])
    for name,record in plan['candidates'].items():need(backend.candidate(name)==record,'configured_candidate_changed')
    actual=parse_simulation(backend.simulate(plan['pins']),plan['baseline'],backend.candidate,backend,set(plan['pins']),plan['target_branch'])
    need(actual==plan['changes'],'simulated_transaction_changed')

def validate_hook(text,plan,backend):
    need(supported(plan['target_branch']),'target_branch_security_support_expired')
    header,sep,body=text.partition('\n\n');need(sep and header.splitlines()[0]=='VERSION 2','APT_v2_required')
    current=backend.snapshot();need(current['sources']==plan['baseline']['sources'] and current['os']==plan['baseline']['os'] and current['architecture']==plan['baseline']['architecture'] and not current['container'],'APT_sources_or_host_changed_under_lock')
    before=plan['baseline']['packages'];changes=plan['changes'];now=current['packages']
    need(set(now)<=set(before)|set(changes),'unplanned_package_appeared')
    for name,row in before.items():
        if name not in changes:need(now.get(name)==row,'unplanned_package_or_status_changed')
    for name in changes:
        row=now.get(name)
        need(row is None and changes[name]['old']=='-' or row is not None and row['version'] in (changes[name]['old'],changes[name]['new']) and row['architecture']==changes[name]['architecture'] and row['status'] in ('ii','iU','iF','iH','iW','it'),'planned_package_state_changed')
    archive_names=set();configure_names=set();count=0
    for line in body.splitlines():
        if not line:continue
        fields=line.split();need(len(fields)==5,'malformed_APT_action')
        name,old,direction,new,action=fields;need(name in changes and not protected(name),'unplanned_APT_package')
        c=changes[name];need(old==c['old'] and new==c['new'] and direction in ('<','='),'APT_version_or_downgrade_drift')
        need(action!='**REMOVE**','APT_removal_forbidden')
        if action=='**CONFIGURE**':configure_names.add(name)
        else:
            need(re.fullmatch(r'/var/cache/apt/archives/[A-Za-z0-9%+_.:~=-]+\.deb',action) is not None,'unsafe_APT_archive_path')
            need(name not in archive_names,'duplicate_APT_archive');archive_names.add(name)
            need(backend.archive(action)==dict(package=name,version=new,architecture=c['architecture'],sha256=c['sha256']),'archive_payload_or_identity_changed')
        count+=1;need(count<=1000,'excess_APT_actions')
    need(archive_names==set(changes) and configure_names<=set(changes),'actual_APT_transaction_not_exact')
    return True

def install_plan(backend,plan,plan_path):
    recheck(backend,plan)
    if not plan['changes']:return dict(status='authenticated_target_packages_already_current',target_branch=plan['target_branch'],targets=plan['pins'],old_PHP74_preserved=True,service_start_claim=False,APT_transaction_executed=False)
    backend.download(plan['pins'])
    recheck(backend,plan)
    token=backend.suppress_target_fpm(plan['target_branch'])
    try:
        backend.install(plan['pins'],plan_path)
        current=backend.snapshot();before=plan['baseline']['packages'];changes=plan['changes']
        need(current['sources']==plan['baseline']['sources'],'repository_changed_after_install')
        need(not current['dirty'] and set(current['packages'])==set(before)|set(changes),'unexpected_final_package_set')
        for name,row in current['packages'].items():
            expected=dict(version=changes[name]['new'],architecture=changes[name]['architecture'],status='ii') if name in changes else before[name]
            need(row==expected,'final_package_or_status_mismatch')
        return dict(status='PHP8_packages_installed_routing_not_changed',target_branch=plan['target_branch'],targets=plan['pins'],old_PHP74_preserved=True,service_start_claim=False)
    finally:backend.restore_policy(token)

def snapshot_digest(current):return sha(json.dumps(current,sort_keys=True,separators=(',',':')).encode())

def verify_installed_target(backend,branch,current=None):
    need(supported(branch),'target_branch_security_support_expired')
    current=backend.snapshot() if current is None else current;prefix='php'+branch
    validate_release(current)
    need(all(prefix+'-'+s in current['packages'] for s in ('cli','common','fpm')),'installed_target_core_required')
    names=sorted(n for n in current['packages'] if n==prefix or n.startswith(prefix+'-'));records={}
    for name in names:
        row=current['packages'][name];record=validate_candidate(name,backend.candidate(name),current,backend,True,branch)
        need(row==dict(version=record['version'],architecture=record['architecture'],status='ii'),'installed_target_not_exact_authenticated_candidate')
        records[name]=record
    return records

HEALTH_FLAGS=('target_fpm_active','target_cli_selected','target_runtime_verified','health_verified','old_fpm_inactive','no_old_php_processes','no_old_php_routes')
def validate_health(assertion,current,branch):
    need(type(assertion) is dict and assertion.get('target_branch')==branch and all(assertion.get(k) is True for k in HEALTH_FLAGS),'retirement_requires_verified_target_and_no_old_runtime')
    need(assertion.get('baseline_sha256')==snapshot_digest(current),'retirement_health_baseline_changed')
    observed=assertion.get('observed_at');need(type(observed) in (int,float) and 0<=time.time()-observed<=300,'retirement_health_proof_stale')

def parse_retirement(text,current,names):
    seen=set()
    for line in text.splitlines():
        need(not line.startswith(('Inst ','Conf ','Purg ')),'retirement_must_not_install_configure_or_purge')
        if not line.startswith('Remv '):continue
        match=re.match(r'^Remv ([a-z0-9][a-z0-9+.-]*)(?::([a-z0-9]+))? \[([^\]]+)\]',line)
        need(match is not None,'unrecognized_retirement_simulation')
        name,arch,version=match.groups();need(name in names and name not in seen,'collateral_or_duplicate_removal')
        row=current['packages'][name];need(version==row['version'] and (arch is None or arch==row['architecture']),'retirement_simulation_version_drift');seen.add(name)
    need(seen==set(names),'retirement_removal_set_not_exact');return sorted(seen)

def prepare_retirement(backend,target_branch,health_assertion):
    current=inspect_current(backend,allow_existing_target=True)
    branches={m.group(1) for n in current['packages'] if (m:=re.match(r'^php([0-9]+\.[0-9]+)(?:-|$)',n))}
    need(branches=={'7.4',target_branch},'retirement_target_branch_or_mixed_inventory_changed')
    validate_health(health_assertion,current,target_branch);records=verify_installed_target(backend,target_branch,current)
    mapped=map_targets(current,target_branch);need(set(mapped['targets'])<=set(records),'replacement_extensions_missing_before_retirement')
    names=sorted(mapped['mapping']);parse_retirement(backend.simulate_remove(names),current,names)
    need(backend.snapshot()==current,'retirement_baseline_changed_during_prepare')
    return dict(schema='php74-retirement-v10',target_branch=target_branch,distro=current['os']['VERSION_CODENAME'],baseline=current,remove=names,target_candidates=records,health_assertion=health_assertion,module_sha256=module_digest(),security_evidence=SECURITY_EVIDENCE,purge=False,autoremove=False,restore_or_rollback_claim=False)

def recheck_retirement(backend,plan):
    need(plan['schema']=='php74-retirement-v10' and plan['module_sha256']==module_digest() and plan['purge'] is False and plan['autoremove'] is False,'retirement_plan_changed')
    current=inspect_current(backend,allow_existing_target=True);need(current==plan['baseline'],'retirement_baseline_changed')
    validate_health(plan['health_assertion'],current,plan['target_branch'])
    need(verify_installed_target(backend,plan['target_branch'],current)==plan['target_candidates'],'retirement_target_candidate_changed')
    names=sorted(n for n in current['packages'] if n=='php7.4' or n.startswith('php7.4-'));need(names==plan['remove'],'retirement_only_exact_installed74_allowed')
    parse_retirement(backend.simulate_remove(names),current,names)

def validate_retirement_hook(text,plan,backend):
    header,sep,body=text.partition('\n\n');need(sep and header.splitlines()[0]=='VERSION 2','APT_v2_required')
    current=backend.snapshot();before=plan['baseline'];names=set(plan['remove']);need(current['sources']==before['sources'] and current['os']==before['os'] and current['architecture']==before['architecture'] and not current['container'],'retirement_host_or_sources_changed_under_lock')
    need(names=={n for n in before['packages'] if n=='php7.4' or n.startswith('php7.4-')},'retirement_exact74_set_changed')
    need(set(current['packages'])<=set(before['packages']),'retirement_package_appeared')
    for name,row in before['packages'].items():
        if name not in names:need(current['packages'].get(name)==row,'retirement_non74_package_changed')
        elif name in current['packages']:
            now=current['packages'][name];need(now['version']==row['version'] and now['architecture']==row['architecture'] and now['status'] in ('ii','iF','iH','iU'),'retirement74_package_changed')
    seen=set()
    for line in body.splitlines():
        if not line:continue
        fields=line.split();need(len(fields)==5,'malformed_retirement_APT_action')
        name,old,direction,new,action=fields
        need(name in names and name not in seen and old==before['packages'][name]['version'] and direction=='>' and new=='-' and action=='**REMOVE**','retirement_unapproved_APT_action');seen.add(name)
    need(seen==names,'retirement_actual_APT_set_not_exact');return True

def remove_plan(backend,plan,plan_path):
    recheck_retirement(backend,plan);backend.remove(plan['remove'],plan_path)
    current=backend.snapshot();expected={n:r for n,r in plan['baseline']['packages'].items() if n not in plan['remove']}
    need(current['packages']==expected and current['sources']==plan['baseline']['sources'] and not current['dirty'],'retirement_final_table_or_source_drift')
    verify_installed_target(backend,plan['target_branch'],current)
    return dict(status='only_PHP74_packages_removed_without_purge_or_autoremove',removed=plan['remove'],target_branch=plan['target_branch'],post_removal_runtime_and_web_reverification_required=True,application_or_database_commands=0)

def private_path(path,absent=False):
    need(path.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(path)) is not None and path.resolve()==path,'unsafe_private_path')
    info=path.parent.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o700,'private_plan_parent_required')
    if not absent:
        i=path.lstat();need(stat.S_ISREG(i.st_mode) and i.st_uid==0 and stat.S_IMODE(i.st_mode)==0o600 and i.st_size<=4194304,'private_plan_required')
def save_plan(path,plan):
    private_path(path,True);fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write((json.dumps(plan,sort_keys=True)+'\n').encode());f.flush();os.fsync(f.fileno())
def read_plan(path):
    private_path(path);return json.loads(path.read_bytes())

class Backend:
    def __init__(self):
        import apt,apt_pkg
        self.apt_pkg=apt_pkg;self.cache=apt.Cache()
    def run(self,args,timeout=None):
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=timeout,env=dict(os.environ,LC_ALL='C',DEBIAN_FRONTEND='noninteractive',NEEDRESTART_MODE='l',UCF_FORCE_CONFFOLD='1',APT_LISTCHANGES_FRONTEND='none'))
        need(result.returncode==0,'native_package_command_failed');return result.stdout.decode()
    def compare(self,a,b):return self.apt_pkg.version_compare(a,b)
    def satisfies(self,v,r,w):return self.apt_pkg.check_dep(v,r,w)
    def snapshot(self):
        release={}
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                k,v=line.split('=',1)
                if k in ('ID','VERSION_ID','VERSION_CODENAME'):release[k]=v.strip('"')
        rows={}
        for line in self.run(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'],30).splitlines():
            name,version,arch,status=line.split('\t');status=status.strip()
            if status.startswith('rc') or status in ('un','pn'):continue
            need(name not in rows,'multiarch_inventory_not_supported');rows[name]=dict(version=version,architecture=arch,status=status)
        sources={}
        paths=[Path('/etc/apt/sources.list')]+sorted(Path('/etc/apt/sources.list.d').glob('*'))
        for path in paths:
            if not path.exists() or path.suffix not in ('.list','.sources'):continue
            i=path.lstat();need(stat.S_ISREG(i.st_mode) and i.st_uid==0 and not i.st_mode&0o022,'unsafe_APT_source_file')
            raw=path.read_bytes();active='\n'.join(x for x in raw.decode().splitlines() if not x.lstrip().startswith('#'))
            need(not re.search(r'(?i)(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)\s*(?:=|:)\s*(yes|true|1)',active),'APT_authentication_override_forbidden')
            sources[str(path)]=sha(raw)
        for option in ('APT::Get::AllowUnauthenticated','Acquire::AllowInsecureRepositories','Acquire::AllowWeakRepositories','Acquire::AllowDowngradeToInsecureRepositories'):
            need(not self.apt_pkg.config.find_b(option,False),'APT_authentication_override_forbidden')
        need(sources,'APT_sources_missing')
        cgroup=Path('/proc/1/cgroup').read_text()
        container=Path('/.dockerenv').exists() or Path('/run/.containerenv').exists() or Path('/run/systemd/container').exists() or bool(re.search(r'docker|lxc|kubepods|containerd',cgroup))
        return dict(os=release,architecture=self.run(['/usr/bin/dpkg','--print-architecture'],10).strip(),packages=rows,sources=sources,container=container,dirty=bool(self.run(['/usr/bin/dpkg','--audit'],30).strip()))
    def candidate(self,name):
        if name not in self.cache or self.cache[name].candidate is None:return None
        c=self.cache[name].candidate;r=c.record
        return dict(version=c.version,architecture=c.architecture,source=c.source_name,source_version=c.source_version,sha256=r.get('SHA256',''),filename=r.get('Filename',''),origins=[dict(trusted=o.trusted,origin=o.origin,archive=o.archive,site=o.site) for o in c.origins],dependencies=[[dict(name=d.name,relation=d.relation,version=d.version) for d in group.or_dependencies] for group in c.get_dependencies('Depends','PreDepends')])
    def args(self,pins):return [n+'='+v for n,v in sorted(pins.items())]
    def acquisition_options(self):return ['-o','Acquire::Retries=0','-o','Acquire::http::Timeout=15','-o','Acquire::https::Timeout=15','-o','DPkg::Lock::Timeout=60']
    def simulate(self,pins):return self.run(['/usr/bin/apt-get','--simulate','--no-remove','--no-install-recommends','install']+self.args(pins),120)
    def simulate_remove(self,names):return self.run(['/usr/bin/apt-get','--simulate','-o','APT::Get::AutomaticRemove=false','-o','APT::Get::Purge=false','remove']+sorted(names),120)
    def download(self,pins):self.run(['/usr/bin/apt-get','--yes','--download-only','--no-remove','--no-install-recommends']+self.acquisition_options()+['install']+self.args(pins))
    def archive(self,path):
        p=Path(path);i=p.lstat();need(stat.S_ISREG(i.st_mode) and i.st_uid==0 and not i.st_mode&0o022 and 0<i.st_size<=536870912,'unsafe_DEB')
        with p.open('rb') as stream:content=hashlib.file_digest(stream,'sha256').hexdigest() if hasattr(hashlib,'file_digest') else sha(stream.read())
        fields=self.run(['/usr/bin/dpkg-deb','-f',str(p),'Package','Version','Architecture'],15)
        values=dict(x.split(': ',1) for x in fields.splitlines());return dict(package=values['Package'],version=values['Version'],architecture=values['Architecture'],sha256=content)
    def suppress_target_fpm(self,branch):
        path=Path('/usr/sbin/policy-rc.d');fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o700)
        raw=target_policy(branch)
        with os.fdopen(fd,'wb') as f:os.fchmod(f.fileno(),0o700);f.write(raw);f.flush();os.fsync(f.fileno())
        i=path.lstat();return (i.st_dev,i.st_ino,sha(raw))
    def restore_policy(self,token):
        p=Path('/usr/sbin/policy-rc.d');i=p.lstat();need((i.st_dev,i.st_ino)==token[:2] and i.st_uid==0 and sha(p.read_bytes())==token[2],'owned_service_policy_changed');p.unlink()
    def install(self,pins,plan_path):
        module=Path(__file__).resolve();need(module.is_file() and not module.stat().st_mode&0o022 and module.stat().st_uid==0,'private_hook_module_required')
        need(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(module)) is not None,'unsafe_hook_module_path')
        command='/usr/bin/python3 -I '+str(module)+' hook --plan '+str(plan_path)
        receipt=plan_path.with_name('packages-hook-accepted.json');need(not receipt.exists(),'hook_receipt_already_exists_no_retry')
        self.run(['/usr/bin/apt-get','--yes','--no-remove','--no-download','--no-install-recommends']+self.acquisition_options()+['-o','Dpkg::Options::=--force-confold','-o','DPkg::Pre-Install-Pkgs::='+command,'-o','DPkg::Tools::Options::'+command+'::Version=2','-o','DPkg::Tools::Options::'+command+'::InfoFD=0','install']+self.args(pins))
        proof=read_plan(receipt);need(proof==dict(plan_sha256=sha(plan_path.read_bytes()),module_sha256=module_digest(),accepted=True),'actual_APT_hook_receipt_missing_or_changed')
    def remove(self,names,plan_path):
        module=Path(__file__).resolve();need(module.is_file() and module.stat().st_uid==0 and not module.stat().st_mode&0o022,'private_hook_module_required')
        need(re.fullmatch(r'/[A-Za-z0-9_./-]+',str(module)) is not None,'unsafe_hook_module_path')
        command='/usr/bin/python3 -I '+str(module)+' retire-hook --plan '+str(plan_path)
        receipt=plan_path.with_name('retirement-hook-accepted.json');need(not receipt.exists(),'retirement_receipt_already_exists_no_retry')
        self.run(['/usr/bin/apt-get','--yes','-o','APT::Get::AutomaticRemove=false','-o','APT::Get::Purge=false']+self.acquisition_options()+['-o','Dpkg::Options::=--force-confold','-o','DPkg::Pre-Install-Pkgs::='+command,'-o','DPkg::Tools::Options::'+command+'::Version=2','-o','DPkg::Tools::Options::'+command+'::InfoFD=0','remove']+sorted(names))
        proof=read_plan(receipt);need(proof==dict(plan_sha256=sha(plan_path.read_bytes()),module_sha256=module_digest(),accepted=True),'actual_retirement_hook_receipt_missing_or_changed')

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('mode',choices=('plan','prepare','prepare-existing','install','hook','prepare-retire','remove','retire-hook'),default='plan',nargs='?');parser.add_argument('--plan',type=Path);parser.add_argument('--target-branch',choices=tuple(FLOORS));parser.add_argument('--health',type=Path);a=parser.parse_args()
    if a.mode=='plan':print(json.dumps(dict(production_changes=0,module='php74_to8_packages_v10')));return
    need(os.geteuid()==0 and a.plan is not None,'root_and_private_plan_required');backend=Backend()
    if a.mode=='prepare':save_plan(a.plan,prepare_plan(backend,a.target_branch));result=dict(status='exact_package_plan_prepared')
    elif a.mode=='prepare-existing':
        need(a.target_branch is not None and a.health is not None,'target_and_dormant_proof_required');save_plan(a.plan,prepare_existing_patch(backend,a.target_branch,read_plan(a.health)));result=dict(status='exact_existing_target_patch_prepared')
    elif a.mode=='prepare-retire':
        need(a.target_branch is not None and a.health is not None,'target_and_health_proof_required');save_plan(a.plan,prepare_retirement(backend,a.target_branch,read_plan(a.health)));result=dict(status='exact_retirement_plan_prepared')
    elif a.mode in ('hook','retire-hook'):
        plan=read_plan(a.plan);need(plan['module_sha256']==module_digest(),'hook_module_changed');raw=sys.stdin.read(2097153);need(len(raw)<=2097152,'APT_protocol_too_large')
        if a.mode=='retire-hook':need(plan['schema']=='php74-retirement-v10','wrong_retirement_schema');validate_retirement_hook(raw,plan,backend)
        else:need(plan['schema']=='php74-to8-v10','wrong_install_schema');validate_hook(raw,plan,backend)
        receipt=a.plan.with_name('retirement-hook-accepted.json' if a.mode=='retire-hook' else 'packages-hook-accepted.json');proof=dict(plan_sha256=sha(a.plan.read_bytes()),module_sha256=module_digest(),accepted=True)
        if receipt.exists():need(read_plan(receipt)==proof,'hook_receipt_changed')
        else:save_plan(receipt,proof)
        return
    elif a.mode=='remove':result=remove_plan(backend,read_plan(a.plan),a.plan)
    else:result=install_plan(backend,read_plan(a.plan),a.plan)
    print(json.dumps(result,sort_keys=True))
if __name__=='__main__':
    try:main()
    except Exception as e:
        print(json.dumps(dict(status='stopped',error_code=str(e) if isinstance(e,PackageError) else 'local_package_metadata_error')),file=sys.stderr);raise SystemExit(1)
