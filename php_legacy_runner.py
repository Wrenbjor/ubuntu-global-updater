"""Current-host Noble-only inventoried legacy PHP retirement and supported PHP8 migration."""
import hashlib,ipaddress,json,os,re,signal,stat,subprocess,time
from pathlib import Path
import php_legacy_packages as pkg
import php_legacy_routing as route
class MigrationError(Exception):pass
ENV=dict(PATH="/usr/sbin:/usr/bin:/sbin:/bin",LANG="C",LC_ALL="C",HOME="/nonexistent",DEBIAN_FRONTEND="noninteractive",NEEDRESTART_MODE="l",UCF_FORCE_CONFFOLD="1")

def need(ok,code):
    if not ok:raise MigrationError(code)

def save(path,value):
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write((json.dumps(value,sort_keys=True)+'\n').encode());stream.flush();os.fsync(stream.fileno())

def phase(job,name,**extra):
    print(json.dumps(dict(stage=name,**extra)),flush=True)
    save(job/(name+'.json'),dict(stage=name,**extra))

def active(name):return run(['/bin/systemctl','is-active',name],allow=True)[1].decode().strip()

def php_processes():
    rows=[]
    for p in Path('/proc').iterdir():
        if not p.name.isdecimal():continue
        php_seen=False
        try:
            comm=(p/'comm').read_text().strip()
            php_seen=bool(re.match(r'^(?:(?:php(?:-fpm|-cgi|dbg)?|lsphp)(?:[0-9]+(?:\.[0-9]+)*)?|litespeed|frankenphp|apache2|httpd)(?:$|[:\s])',comm))
            executable=os.readlink(p/'exe')
            php_seen=php_seen or bool(re.search(r'(?:php|php-fpm|lsphp)',Path(executable).name))
            if php_seen:rows.append(dict(pid=int(p.name),executable=executable))
        except (FileNotFoundError,ProcessLookupError):
            if php_seen and p.exists():rows.append(dict(pid=int(p.name),executable='<unverifiable_php_process>'))
    return rows

def legacy_cli_refs(source_branch):
    paths=[]
    for base in ('/etc/cron.d','/etc/cron.hourly','/etc/cron.daily','/etc/cron.weekly','/etc/cron.monthly','/etc/supervisor','/var/spool/cron/crontabs','/etc/systemd/system'):
        p=Path(base)
        if p.exists():paths.extend(p.rglob('*'))
    paths.append(Path('/etc/crontab'));found=[]
    for p in paths:
        try:
            i=p.lstat()
            if not stat.S_ISREG(i.st_mode) or p.name.startswith('php'+source_branch+'-fpm.service'):continue
            need(i.st_size<=1048576,'oversized_job_configuration')
            raw=p.read_bytes()
            if re.search(rb'(?m)^[^#\r\n]*\b(?:php|phpize|php-config)'+re.escape(source_branch.encode())+rb'\b',raw):found.append(dict(path=str(p),sha256=hashlib.sha256(raw).hexdigest()))
        except FileNotFoundError:pass
    return found

def templates(source_branch):
    base=Path('/usr/lib/php')/source_branch;standard=base/'php.ini-production';cli=base/'php.ini-production.cli'
    need(standard.is_file(),'shipped_LEGACY_PHP_ini_template_missing')
    return dict(fpm=standard.read_bytes(),cli=(cli if cli.is_file() else standard).read_bytes())

def extension_ownership(current,source_branch,directory):
    checked=set()
    for sapi in ('fpm','cli'):
        for path in Path('/etc/php',source_branch,sapi,'conf.d').glob('*.ini'):
            # PHP permits repeated extension directives; validate every declaration.
            declarations=[item for line in path.read_bytes().splitlines() for item in route.ini_values(line).items()]
            for key,value in declarations:
                if key not in ('extension','zend_extension'):continue
                name=value.strip('"\'')
                need(re.fullmatch(r'[A-Za-z0-9_-]+(?:\.so)?',name) is not None,'custom_extension_path_requires_manual_review')
                if not name.endswith('.so'):name+='.so'
                module=Path(directory)/name
                need(module.is_file() and not module.is_symlink(),'legacy_extension_file_missing_or_custom')
                info=module.lstat();need(info.st_uid==0 and not info.st_mode&0o022,'unsafe_source_extension_permissions')
                if module in checked:continue
                code,raw=run(['/usr/bin/dpkg-query','-S',str(module)],allow=True)
                owners=[line.split(': ',1)[0].split(':',1)[0] for line in raw.decode().splitlines() if ': ' in line]
                need(code==0 and len(owners)==1 and owners[0].startswith('php'+source_branch+'-') and owners[0] in current['packages'],'unpackaged_legacy_extension_requires_manual_review')
                checked.add(module)

def local_addresses():
    values={'127.0.0.1'}
    _,raw=run(['/usr/sbin/ip','-j','address','show'])
    for item in json.loads(raw):
        for address in item.get('addr_info',[]):
            if address.get('family')=='inet':values.add(address['local'])
    return values

def health_specs(discovery):
    addresses=local_addresses();specs=[]
    for server in discovery.servers:
        if not server.get('php',server.get('php74')):continue
        names=[n for n in server['server_names'] if re.fullmatch(r'(?=.{1,253}$)[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,63}',n)]
        if not names:continue
        endpoints=[]
        for listen in server['listeners'] or ['80']:
            parts=listen.split();address=parts[0];tls='ssl' in parts
            if address.isdecimal():ip='127.0.0.1';port=int(address)
            elif re.fullmatch(r'[0-9.]+:[0-9]+',address):ip,port=address.rsplit(':',1);port=int(port);ip='127.0.0.1' if ip=='0.0.0.0' else ip
            else:continue
            if ip in addresses and port in (80,443):endpoints.append((tls or port==443,ip,port))
        need(endpoints,'supported_local_health_listener_missing')
        # Prefer a TLS endpoint for each public virtual host. Never follow redirects.
        chosen=next((e for e in endpoints if e[0]),endpoints[0])
        for name in names:
            for path in ('/','/wp-login.php'):
                specs.append(dict(host=name,ip=chosen[1],port=chosen[2],tls=chosen[0],path=path))
    unique={tuple(sorted(s.items())):s for s in specs}
    need(0<len(unique)<=80,'health_probe_set_missing_or_too_large')
    return list(unique.values())

def health(specs):
    results=[]
    for spec in specs:
        scheme='https' if spec['tls'] else 'http';host=spec['host'];port=spec['port']
        args=['/usr/bin/curl','--disable','--silent','--show-error','--noproxy','*','--connect-timeout','3','--max-time','8','--resolve',host+':'+str(port)+':'+spec['ip'],'--output','/dev/null','--write-out','%{http_code}',scheme+'://'+host+':'+str(port)+spec['path']]
        code,raw=run(args,timeout=10,allow=True);status=raw.decode().strip()
        need(code==0 and re.fullmatch(r'[23][0-9]{2}',status),'application_health_failed')
        results.append(dict(**spec,status=status))
    return results

def comparable_health(before,after):
    need(len(before)==len(after),'health_probe_set_changed')
    for a,b in zip(before,after):
        need({k:v for k,v in a.items() if k!='status'}=={k:v for k,v in b.items() if k!='status'} and a['status']==b['status'],'application_health_changed')

def modules(binary):
    _,raw=run([binary,'-m']);text=raw.decode()
    need('Warning:' not in text and 'Fatal error:' not in text,'PHP_module_startup_error')
    return sorted({line.strip().lower() for line in text.splitlines() if line.strip() and not line.startswith('[')})

def removed_module_requirements(current,source_branch,observed):
    """No implicit loss of extensions removed from the PHP8 core distribution.

    A separately packaged legacy module must have its like-named authenticated
    target candidate. An embedded module (notably WDDX in older xml packages)
    requires a separately reviewed migration and stops before package writes.
    """
    removed={'mcrypt','recode','wddx','xmlrpc'};result={}
    for module in sorted(set().union(*(set(v) for v in observed.values()))&removed):
        package='php'+source_branch+'-'+module
        need(package in current['packages'],'embedded_removed_module_requires_review:'+module)
        result[module]=dict(source_package=package,target_suffix=module,disposition='authenticated_target_candidate_and_loaded_module_required')
    return result

def restore_nginx(plan,job):
    restored=[]
    for edit in plan.edits:
        if edit.kind!='nginx':continue
        p=plan.discovery.fs.physical(edit.path)
        need(p.read_bytes()==edit.content,'nginx_recovery_conflict_requires_manual_review')
        original=edit.original;temporary=p.with_name(p.name+'.v8-recover-'+plan.sha256[:12])
        fd=os.open(str(temporary),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,original.mode)
        with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),original.mode);os.fchown(stream.fileno(),original.uid,original.gid);stream.write(original.content);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,p);directory=os.open(str(p.parent),os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(directory)
        finally:os.close(directory)
        restored.append(edit.path)
    run(['/usr/sbin/nginx','-t']);run(['/bin/systemctl','reload','nginx'])
    save(job/'routing-recovery.json',dict(restored_paths=restored,status='old_routing_restored_host_remains_unpatched',database_rollback=False,package_removals=0))

# Combined with reviewed utility definitions by build_php_patch_only_v10.py.
BRANCHES=('8.3','8.2','8.4','8.5')
WP_FLOORS={'8.2':(6,1),'8.3':(6,4),'8.4':(6,7),'8.5':(6,9)}

def run(args,timeout=20,allow=False):
    result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=timeout)
    if not allow:need(result.returncode==0,'native_command_failed:'+Path(args[0]).name)
    return result.returncode,result.stdout

def target_unit(branch,preinstall=False):
    need(branch in BRANCHES or branch in pkg.LEGACY_BRANCHES,'invalid_unit_branch')
    unit='php'+branch+'-fpm.service'
    for base in ('/etc/systemd/system','/run/systemd/system','/usr/local/lib/systemd/system'):
        for suffix in (unit,unit+'.d'):
            p=Path(base)/suffix
            need(not p.exists() and not p.is_symlink(),'custom_target_FPM_unit_requires_review')
    code,raw=run(['/bin/systemctl','show',unit,'-p','LoadState','-p','FragmentPath','-p','DropInPaths','-p','Environment','-p','EnvironmentFiles','-p','ExecStart'],allow=True)
    need(code==0,'target_unit_query_failed')
    props=dict(line.split('=',1) for line in raw.decode().splitlines() if '=' in line)
    need(not props.get('DropInPaths') and not props.get('Environment') and not props.get('EnvironmentFiles'),'custom_target_unit_environment_or_dropin')
    if preinstall and props.get('LoadState')=='not-found':return
    fragment=props.get('FragmentPath')
    need(props.get('LoadState')=='loaded' and fragment in ('/lib/systemd/system/'+unit,'/usr/lib/systemd/system/'+unit),'nonstandard_target_unit')
    info=Path(fragment).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022,'unsafe_target_unit')
    paths=re.findall(r'\bpath=([^ ;}]+)',props.get('ExecStart',''));argv=re.findall(r'argv\[\]=([^;]+)',props.get('ExecStart',''))
    expected=['/usr/sbin/php-fpm'+branch,'--nodaemonize','--fpm-config','/etc/php/'+branch+'/fpm/php-fpm.conf']
    need(paths==[expected[0]] and len(argv)==1 and argv[0].split()==expected,'noncanonical_target_ExecStart')

def source_engine(current,source_branch):
    need(source_branch in pkg.LEGACY_BRANCHES,'unsupported_source_branch')
    binary=Path('/usr/bin/php'+source_branch);info=binary.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022 and binary.resolve()==binary,'unsafe_source_engine_binary')
    code,raw=run(['/usr/bin/dpkg-query','-S',str(binary)],allow=True)
    owners=[line.split(': ',1)[0].split(':',1)[0] for line in raw.decode().splitlines() if ': ' in line]
    need(code==0 and owners==['php'+source_branch+'-cli'] and owners[0] in current['packages'],'source_engine_not_owned_by_installed_CLI')
    _,raw=run([str(binary),'-n','-r','echo PHP_EXTENSION_DIR;'])
    directory=raw.decode().strip();need(re.fullmatch(r'/usr/lib/php/[0-9]{8}',directory) is not None,'invalid_discovered_source_extension_directory')
    path=Path(directory);need(path.resolve()==path,'custom_source_extension_directory')
    for parent in (path,Path('/usr/lib/php'),Path('/usr/lib'),Path('/usr')):
        item=parent.lstat();need(stat.S_ISDIR(item.st_mode) and item.st_uid==0 and not item.st_mode&0o022,'unsafe_source_extension_directory')
    code,raw=run(['/usr/bin/dpkg-query','-S',directory],allow=True)
    owners=[part.strip().split(':',1)[0] for line in raw.decode().splitlines() if ': ' in line for part in line.split(': ',1)[0].split(',')]
    need(code==0 and bool(owners) and all(n.startswith('php'+source_branch+'-') and n in current['packages'] for n in owners),'source_API_directory_not_package_owned')
    return dict(branch=source_branch,php_api=path.name,extension_dir=directory)

def facts(current,branch,source_branch,legacy=True):
    processes=php_processes()
    need(not any(p['executable'].startswith('/usr/bin/php'+source_branch) for p in processes),'live_LEGACY_PHP_CLI_job_requires_review')
    containers=current['container'] or any(active(n)=='active' for n in ('docker','podman','containerd','kubelet'))
    code,_=run(['/usr/sbin/nginx','-t'],allow=True)
    engine=source_engine(current,source_branch) if legacy else dict(php_api='',extension_dir='')
    result=dict(source_branch=source_branch,source_php_api=engine['php_api'],source_extension_dir=engine['extension_dir'],distroversion=current['os']['VERSION_ID'],target_branch=branch,package_rows=current['packages'],active_services={n:active(n) for n in ('nginx','php'+source_branch+'-fpm','php'+branch+'-fpm','apache2')},active_php_executables=sorted({p['executable'] for p in processes}),containers=containers,old_cli=str(Path('/usr/bin/php').resolve()),hardcoded_cli_refs=legacy_cli_refs(source_branch),nginx_configtest_exit=code)
    need(not result['hardcoded_cli_refs'],'hardcoded_LEGACY_PHP_job_requires_review')
    if legacy:
        target_unit(source_branch)
        info=run(['/bin/systemctl','show','php'+source_branch+'-fpm','-p','FragmentPath','-p','DropInPaths','-p','Restart'])[1].decode()
        props=dict(line.split('=',1) for line in info.splitlines() if '=' in line)
        need(not props.get('DropInPaths') and props.get('Restart') in ('no','on-failure'),'custom_legacy_FPM_unit')
        need(props.get('FragmentPath') in ('/lib/systemd/system/php'+source_branch+'-fpm.service','/usr/lib/systemd/system/php'+source_branch+'-fpm.service'),'nonstandard_legacy_FPM_unit')
    return result

def compatibility(discovery,branch):
    need(bool(discovery.wordpress),'WordPress_layout_required_for_major_migration')
    need(set(discovery.document_roots)<=set(item['root'] for item in discovery.wordpress),'unknown_PHP_application_requires_review')
    for item in discovery.wordpress:
        match=re.fullmatch(r'(\d+)\.(\d+)(?:\.\d+)?',item.get('version') or '')
        need(match is not None and tuple(map(int,match.groups()))>=WP_FLOORS[branch],'WordPress_core_incompatible_with_target_branch')
    for root in discovery.document_roots:
        p=Path(root)
        for directory in [p]+list(p.parents)[:2]:
            need(not (directory/'composer.json').exists() and not (directory/'composer.lock').exists(),'Composer_application_requires_review')

def current_mode(backend):
    current=backend.snapshot();pkg.validate_release(current)
    sources=pkg.legacy_sources(current)
    if not sources:
        branches={m.group(1) for n in current['packages'] if (m:=re.match(r'^php([0-9]+\.[0-9]+)(?:-|$)',n))}
        need(branches<=set(BRANCHES),'unsupported_legacy_branch_requires_review')
        return dict(mode='no-legacy',current=current)
    need(len(sources)==1,'multiple_legacy_branches_require_review')
    source_branch=sources[0]
    versions={m.group(1) for n in current['packages'] if (m:=re.match(r'^php([0-9]+\.[0-9]+)(?:-|$)',n)) and m.group(1)!=source_branch}
    legacy_active=active('php'+source_branch+'-fpm')=='active' or str(Path('/usr/bin/php').resolve())=='/usr/bin/php'+source_branch
    if legacy_active:
        need(not versions,'mixed_active_legacy_and_target_requires_review')
        return dict(mode='migrate',current=current,source_branch=source_branch)
    need(len(versions)==1,'dormant_legacy_requires_one_supported_active_target')
    branch=next(iter(versions));need(branch in BRANCHES,'existing_target_branch_unsupported')
    return dict(mode='retire-dormant',current=current,source_branch=source_branch,target_branch=branch)

def preflight(probe_only=False):
    backend=pkg.Backend();state=current_mode(backend)
    if state['mode']=='no-legacy':return state
    current=state['current'];source_branch=state['source_branch']
    if state['mode']=='retire-dormant':
        branch=state['target_branch'];target_unit(branch)
        evidence=facts(current,branch,source_branch,legacy=False)
        need(not evidence['containers'] and evidence['nginx_configtest_exit']==0,'existing_target_container_or_nginx_failure')
        need(evidence['old_cli']=='/usr/bin/php'+branch and active('php'+branch+'-fpm')=='active','existing_target_not_active_or_default')
        need(not any(source_branch in p['executable'] for p in php_processes()),'legacy_runtime_still_active')
        discovery=route.audit_existing_target_nginx('/',branch)
        specs=health_specs(discovery);before=health(specs)
        proof=make_health_proof(current,branch,specs,before,source_branch)
        patch_plan=None if probe_only else pkg.prepare_existing_patch(backend,branch,proof)
        state.update(discovery=discovery,health_specs=specs,health_before=before,package_plan=patch_plan)
        state['candidates_pending_refresh']=probe_only
        return state
    pkg.inspect_current(backend)
    engine=source_engine(current,source_branch);extension_ownership(current,source_branch,engine['extension_dir'])
    failures=[]
    for branch in BRANCHES:
        try:
            package_plan=None if probe_only else pkg.prepare_plan(backend,target_branch=branch)
            target_unit(branch,preinstall=True)
            evidence=facts(current,branch,source_branch)
            discovery=route.preflight('/',evidence,legacy_ini_templates=templates(source_branch))
            compatibility(discovery,branch)
            observed={s:modules('/usr/bin/php'+source_branch if s=='cli' else '/usr/sbin/php-fpm'+source_branch) for s in ('cli','fpm')}
            removed=removed_module_requirements(current,source_branch,observed)
        except (pkg.PackageError,route.RoutingError,MigrationError) as error:
            failures.append(dict(branch=branch,error_code=str(error)));continue
        specs=health_specs(discovery);before=health(specs)
        state.update(target_branch=branch,package_plan=package_plan,discovery=discovery,health_specs=specs,health_before=before,source_modules=observed,removed_module_requirements=removed)
        state['candidates_pending_refresh']=probe_only
        return state
    print(json.dumps(dict(status='NO_SAFE_PHP8_MIGRATION_TARGET',branches=failures)),flush=True)
    raise MigrationError('no_supported_secure_compatible_target_in_configured_sources')

def preflight_report(state):
    result=dict(status='LEGACY_PHP_TO8_PREFLIGHT_OK',mode=state['mode'],source_branch=state.get('source_branch'),target_branch=state.get('target_branch'),os=state['current']['os']['VERSION_ID'],candidates_pending_refresh=state.get('candidates_pending_refresh',False),production_changes=0)
    if state['mode']!='no-legacy':
        result.update(WordPress=state['discovery'].wordpress,pools=len(state['discovery'].pools),health_checks=len(state['health_before']))
    return result

def alternatives_before(job,current,branch,source_branch):
    saved={}
    for name,prefix in (('php','php'),('phpize','phpize'),('php-config','php-config')):
        if name!='php' and 'php'+source_branch+'-dev' not in current['packages']:continue
        old='/usr/bin/'+prefix+source_branch;target='/usr/bin/'+prefix+branch
        _,raw=run(['/usr/bin/update-alternatives','--query',name])
        props=dict(x.split(': ',1) for x in raw.decode().splitlines() if ': ' in x)
        need(props.get('Value')==old and props.get('Status') in ('auto','manual'),'custom_CLI_alternative')
        saved[name]=dict(status=props['Status'],old=old,new=target)
    save(job/'cli-alternatives-before.json',saved)
    for name,item in saved.items():run(['/usr/bin/update-alternatives','--set',name,item['old']])
    return saved

def extension_directory(branch):
    _,raw=run(['/usr/bin/php'+branch,'-n','-r','echo PHP_EXTENSION_DIR;'])
    value=raw.decode().strip()
    need(re.fullmatch(r'/usr/lib/php/[0-9]{8}',value) is not None and Path(value).is_dir(),'invalid_target_extension_directory')
    return value+'/'

def verify_runtime(branch,allow_source=None):
    directory=extension_directory(branch);seen=[]
    permitted={'/usr/sbin/php-fpm'+branch,'/usr/bin/php'+branch}
    if allow_source:permitted.add('/usr/sbin/php-fpm'+allow_source)
    for item in php_processes():
        executable=item['executable'];need(executable in permitted,'unknown_stale_or_legacy_PHP_runtime')
        if allow_source and executable=='/usr/sbin/php-fpm'+allow_source:continue
        root=Path('/proc')/str(item['pid'])
        try:
            live=(root/'exe').stat();disk=Path(executable).stat()
            need((live.st_dev,live.st_ino)==(disk.st_dev,disk.st_ino),'stale_target_PHP_executable')
            count=0
            for line in (root/'maps').read_text().splitlines():
                fields=line.split(None,5)
                if len(fields)!=6 or not fields[5].startswith('/usr/lib/php/'):continue
                path=fields[5];need(path.startswith(directory) and not path.endswith(' (deleted)'),'old_or_deleted_extension')
                mapped=Path(path).stat();major,minor=fields[3].split(':')
                need((int(major,16),int(minor,16),int(fields[4]))==(os.major(mapped.st_dev),os.minor(mapped.st_dev),mapped.st_ino),'stale_extension_inode');count+=1
            need(count>0,'target_module_mappings_missing')
            if executable=='/usr/sbin/php-fpm'+branch:seen.append(item['pid'])
        except (FileNotFoundError,ProcessLookupError):need(not root.exists(),'live_target_runtime_metadata_unverifiable')
    need(bool(seen),'target_FPM_runtime_not_observed')
    return seen

def wait_reloaded_runtime(branch):
    deadline=time.monotonic()+60
    while True:
        try:return verify_runtime(branch)
        except MigrationError as error:
            need(str(error) in ('unknown_stale_or_legacy_PHP_runtime','stale_target_PHP_executable','old_or_deleted_extension','stale_extension_inode','live_target_runtime_metadata_unverifiable'),'runtime_verification_failed_after_reload')
            allowed={'/usr/sbin/php-fpm'+branch,'/usr/sbin/php-fpm'+branch+' (deleted)','/usr/bin/php'+branch,'/usr/bin/php'+branch+' (deleted)'}
            need(all(p['executable'] in allowed for p in php_processes()),'unknown_runtime_after_reload')
            need(time.monotonic()<deadline,'old_workers_did_not_drain_after_reload_no_force_kill')
            time.sleep(.5)

def ini_effective(branch,sapi,keys,staged_root=None):
    root=Path(staged_root) if staged_root is not None else Path('/etc/php')/branch
    config=root/sapi/'php.ini';scan=root/sapi/'conf.d'
    code='echo json_encode((object)array_intersect_key(ini_get_all(null,false),array_flip('+json.dumps(sorted(keys))+')),JSON_THROW_ON_ERROR);'
    _,raw=run(['/usr/bin/env','PHP_INI_SCAN_DIR='+str(scan),'/usr/bin/php'+branch,'-c',str(config),'-r',code])
    value=json.loads(raw)
    need(type(value) is dict,'invalid_effective_INI_evidence')
    return value

def registry(discovery):
    values={}
    for sapi,args in route.registry_commands(discovery).items():
        _,raw=run(args);values[sapi]=json.loads(raw)
    route.validate_target_ini_registry(discovery,values)
    return {sapi:dict(branch=v['branch'],keys=len(v['keys']),modules=v['modules']) for sapi,v in values.items()}

def exact_installed_after(plan):
    final=pkg.Backend().snapshot();need(not final['dirty'],'final_dpkg_not_clean')
    expected=dict(plan['baseline']['packages'])
    for name,change in plan['changes'].items():expected[name]=dict(version=change['new'],architecture=change['architecture'],status='ii')
    need(final['packages']==expected and final['sources']==plan['baseline']['sources'],'unplanned_package_or_source_change')

def retire(job,branch,specs,before,source_branch):
    need(str(Path('/usr/bin/php').resolve())=='/usr/bin/php'+branch,'CLI_target_not_selected')
    need(not legacy_cli_refs(source_branch),'LEGACY_PHP_job_reference_remains')
    need(not any(source_branch in row['executable'] for row in php_processes()),'LEGACY_PHP_process_remains_no_removal')
    audit=route.audit_existing_target_nginx('/',branch)
    comparable_health(before,health(specs));runtime=verify_runtime(branch)
    need(active('php'+branch+'-fpm')=='active','target_FPM_inactive_before_retirement')
    need(active('php'+source_branch+'-fpm') not in ('active','activating','deactivating'),'old_FPM_service_not_inactive')
    ensure_target_boot(branch)
    check_dev_alternatives(branch)
    phase(job,'PHP8-accepted-before-legacy-removal',target_branch=branch,runtime_pids=runtime,routing=audit.public_manifest())
    backup_legacy_configs(job,source_branch)
    backend=pkg.Backend();baseline=backend.snapshot()
    assertion=make_health_proof(baseline,branch,specs,before,source_branch)
    removal=pkg.prepare_retirement(backend,branch,assertion)
    pkg.save_plan(job/'retirement-plan.json',removal)
    phase(job,'removing-legacy-LEGACY_PHP',target_branch=branch,packages=removal['remove'])
    result=pkg.remove_plan(backend,removal,job/'retirement-plan.json');save(job/'retirement-result.json',result)
    phase(job,'LEGACY_PHP-removed-awaiting-final-checks',target_branch=branch)
    need(not any(n=='php'+source_branch or n.startswith('php'+source_branch+'-') for n in pkg.Backend().snapshot()['packages']),'installed_LEGACY_PHP_packages_remain')
    route.audit_existing_target_nginx('/',branch);comparable_health(before,health(specs));verify_runtime(branch)
    need(not legacy_cli_refs(source_branch) and str(Path('/usr/bin/php').resolve())=='/usr/bin/php'+branch,'legacy_reference_or_CLI_drift_after_removal')
    check_dev_alternatives(branch)
    phase(job,'migration-complete',status='LEGACY_PHP_REPLACED_WITH_SECURE_PHP8',target_branch=branch,old_packages_installed=False,configuration_backups_preserved=True,WordPress_changes=0,database_schema_changes=0,pool_verification='Supported keys, exact preserved directives and native FPM configuration tests; no per-request effective INI probe')
    return dict(status='LEGACY_PHP_REPLACED_WITH_SECURE_PHP8',source_branch=source_branch,target_branch=branch,migration_job=str(job))

def check_dev_alternatives(branch):
    current=pkg.Backend().snapshot()
    if 'php'+branch+'-dev' not in current['packages']:return
    for name in ('phpize','php-config'):
        need(str(Path('/usr/bin/'+name).resolve())=='/usr/bin/'+name+branch,'dev_alternative_not_selected_to_target')

def make_health_proof(current,branch,specs,before,source_branch):
    need(active('php'+branch+'-fpm')=='active' and str(Path('/usr/bin/php').resolve())=='/usr/bin/php'+branch,'target_runtime_or_CLI_not_selected')
    need(active('php'+source_branch+'-fpm') not in ('active','activating','deactivating'),'legacy_FPM_still_active')
    need(not legacy_cli_refs(source_branch) and not any(source_branch in p['executable'] for p in php_processes()),'legacy_job_or_process_present')
    route.audit_existing_target_nginx('/',branch);comparable_health(before,health(specs));verify_runtime(branch)
    need(pkg.Backend().snapshot()==current,'health_package_baseline_changed')
    return dict(source_branch=source_branch,target_branch=branch,target_fpm_active=True,target_cli_selected=True,target_runtime_verified=True,health_verified=True,old_fpm_inactive=True,no_old_php_processes=True,no_old_php_routes=True,https_verified=all(s['tls'] for s in specs),baseline_sha256=pkg.snapshot_digest(current),observed_at=time.time())

def select_dormant_dev_alternatives(job,branch,source_branch):
    current=pkg.Backend().snapshot()
    if 'php'+branch+'-dev' not in current['packages']:return
    saved={}
    for name in ('phpize','php-config'):
        code,raw=run(['/usr/bin/update-alternatives','--query',name],allow=True)
        props=dict(x.split(': ',1) for x in raw.decode().splitlines() if ': ' in x)
        old='/usr/bin/'+name+source_branch;target='/usr/bin/'+name+branch
        need(code==0 and props.get('Value') in (old,target),'custom_dev_alternative_requires_review')
        saved[name]=dict(before=props['Value'],after=target)
    save(job/'dormant-dev-alternatives.json',saved)
    for name,item in saved.items():
        if item['before']!=item['after']:run(['/usr/bin/update-alternatives','--set',name,item['after']])

def ensure_target_boot(branch):
    enabled,raw=run(['/bin/systemctl','is-enabled','php'+branch+'-fpm'],allow=True)
    if enabled==0 and raw.decode().strip()=='enabled':return
    target_unit(branch)
    run(['/bin/systemctl','enable','php'+branch+'-fpm'])
    enabled,raw=run(['/bin/systemctl','is-enabled','php'+branch+'-fpm'],allow=True)
    need(enabled==0 and raw.decode().strip()=='enabled','target_not_enabled_for_boot')

def backup_legacy_configs(job,source_branch):
    if not (Path('/etc/php')/source_branch).exists():return
    path=job/('legacy-php'+source_branch+'-configuration.tar')
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:
        result=subprocess.run(['/bin/tar','--create','--directory=/etc/php',source_branch],stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.DEVNULL,env=ENV,timeout=30)
        stream.flush();os.fsync(stream.fileno())
    need(result.returncode==0,'legacy_configuration_backup_failed_no_removal')

def migrate(job):
    job=Path(job);need(job.is_absolute() and job.is_dir() and job.stat().st_uid==0 and stat.S_IMODE(job.stat().st_mode)==0o700,'private_job_required')
    need(not (job/'migration-started.json').exists(),'no_blind_retry_of_partial_migration')
    state=preflight();need(state['mode']!='no-legacy','no_installed_LEGACY_PHP_migration_required')
    source_branch=state['source_branch'];branch=state['target_branch'];discovery=state['discovery'];specs=state['health_specs'];before=state['health_before']
    save(job/'migration-started.json',dict(mode=state['mode'],source_branch=source_branch,target_branch=branch,baseline=discovery.public_manifest(),health=before))
    if state['mode']=='retire-dormant':
        plan=state['package_plan'];pkg.save_plan(job/'packages-plan.json',plan)
        phase(job,'patching-existing-PHP8',target_branch=branch,packages=plan['pins'])
        save(job/'packages-result.json',pkg.install_plan(pkg.Backend(),plan,job/'packages-plan.json'))
        run(['/usr/sbin/php-fpm'+branch,'-t']);target_unit(branch);run(['/bin/systemctl','reload','php'+branch+'-fpm'])
        wait_reloaded_runtime(branch);comparable_health(before,health(specs))
        select_dormant_dev_alternatives(job,branch,source_branch)
        pkg.verify_installed_target(pkg.Backend(),branch)
        return retire(job,branch,specs,before,source_branch)
    current=state['current'];plan=state['package_plan']
    old_modules={s:modules('/usr/bin/php'+source_branch if s=='cli' else '/usr/sbin/php-fpm'+source_branch) for s in ('cli','fpm')}
    configured_keys={s:set(discovery.ini_overrides[s])|set(discovery.extra_ini[s]) for s in ('cli','fpm')}
    old_extra={s:ini_effective(source_branch,s,configured_keys[s]) for s in ('cli','fpm')}
    aliases=alternatives_before(job,current,branch,source_branch)
    pkg.save_plan(job/'packages-plan.json',plan)
    phase(job,'installing-PHP8',target_branch=branch,packages=plan['pins'])
    save(job/'packages-result.json',pkg.install_plan(pkg.Backend(),plan,job/'packages-plan.json'))
    save(job/'target-INI-registry.json',registry(discovery))
    migration=route.build_plan(discovery);staged=route.stage(migration,job/'routing-stage')
    exits={name:run(args,allow=True)[0] for name,args in route.test_commands(staged).items()}
    need(exits==dict(fpm=0,nginx=0),'staged_native_configuration_test_failed')
    staged_values={s:ini_effective(branch,s,configured_keys[s],staged.php_root) for s in ('cli','fpm')}
    for sapi in ('cli','fpm'):
        need(all(staged_values[sapi].get(k)==v for k,v in old_extra[sapi].items()),'extension_setting_effective_value_changed_before_cutover')
    save(job/'extension-effective-values-private.json',dict(old=old_extra,staged=staged_values))
    route.apply(migration,staged,exits,kind='fpm')
    for sapi in ('cli','fpm'):need(ini_effective(branch,sapi,configured_keys[sapi])==staged_values[sapi],'applied_extension_setting_drift')
    run(['/usr/sbin/php-fpm'+branch,'-t']);target_unit(branch);run(['/bin/systemctl','start','php'+branch+'-fpm'],timeout=60)
    need(active('php'+branch+'-fpm')=='active','target_FPM_not_active')
    for pool in discovery.pools.values():
        p=Path(pool['target_socket']);need(p.exists() and stat.S_ISSOCK(p.stat().st_mode),'target_pool_socket_missing')
    need(set(old_modules['cli'])<=set(modules('/usr/bin/php'+branch)) and set(old_modules['fpm'])<=set(modules('/usr/sbin/php-fpm'+branch)),'required_extension_missing')
    phase(job,'PHP8-ready-before-web-cutover',target_branch=branch,runtime_pids=verify_runtime(branch,allow_source=source_branch))
    route.apply(migration,staged,exits,kind='nginx')
    try:
        run(['/usr/sbin/nginx','-t']);run(['/bin/systemctl','reload','nginx']);comparable_health(before,health(specs));verify_runtime(branch,allow_source=source_branch)
    except Exception:
        restore_nginx(migration,job)
        raise MigrationError('web_cutover_failed_old_routing_restored')
    phase(job,'web-cutover-validated',target_branch=branch)
    for name,item in aliases.items():run(['/usr/bin/update-alternatives','--set',name,item['new']])
    ensure_target_boot(branch)
    phase(job,'retiring-legacy-FPM')
    run(['/bin/systemctl','disable','php'+source_branch+'-fpm']);run(['/bin/systemctl','kill','--kill-whom=main','--signal=QUIT','php'+source_branch+'-fpm'])
    deadline=time.monotonic()+60
    while active('php'+source_branch+'-fpm') in ('active','activating','deactivating') and time.monotonic()<deadline:time.sleep(.5)
    need(not any(source_branch in p['executable'] for p in php_processes()),'legacy_workers_still_draining_no_force_kill')
    exact_installed_after(plan)
    for edit in migration.edits:need(migration.discovery.fs.physical(edit.path).read_bytes()==edit.content,'configuration_changed_after_activation')
    return retire(job,branch,specs,before,source_branch)
