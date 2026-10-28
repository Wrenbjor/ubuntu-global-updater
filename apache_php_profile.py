"""Read-only standard Ubuntu Apache/PHP discovery, planning and verification.

No package, configuration or service mutation is implemented here. Patch plans
retain the active SAPI and MPM. Major migrations require an explicit same-SAPI
compatibility plan; this module never silently converts mod_php to FPM.
Public results contain hashes/metadata, never configuration contents or INI values.
"""
import glob,hashlib,json,os,re,shlex,stat,subprocess
from pathlib import Path,PurePosixPath

LEGACY={'7.2','7.3','7.4','8.0','8.1'}
TARGETS={'8.2','8.3','8.4','8.5'}
ENV=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/nonexistent',LANG='C',LC_ALL='C')

class ApacheProfileError(ValueError):pass
def need(value,code):
    if not value:raise ApacheProfileError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()

class ConfigReader:
    def __init__(self,root='/',owner_uid=0):
        self.root=Path(root).resolve();self.owner_uid=owner_uid;self.files={};self.aliases={}
    def physical(self,path):
        need(str(path).startswith('/') and '..' not in PurePosixPath(str(path)).parts,'unsafe_Apache_configuration_path')
        return self.root/str(path).lstrip('/')
    def read(self,path):
        path=str(path);p=self.physical(path);resolved=p.resolve()
        need(self.root in resolved.parents,'Apache_configuration_link_escapes_root')
        virtual='/'+resolved.relative_to(self.root).as_posix()
        need(virtual.startswith(('/etc/apache2/','/etc/php/')) or virtual=='/etc/letsencrypt/options-ssl-apache.conf','out_of_tree_Apache_configuration')
        for part in p.parents:
            if part==self.root:break
            info=part.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==self.owner_uid and not info.st_mode&0o022,'unsafe_Apache_configuration_parent')
        if p.is_symlink():
            link=p.lstat();need(link.st_uid==self.owner_uid,'unsafe_Apache_configuration_link')
            self.aliases[path]=dict(target=virtual,device=link.st_dev,inode=link.st_ino,mtime_ns=link.st_mtime_ns)
        for part in resolved.parents:
            if part==self.root:break
            info=part.lstat();need(stat.S_ISDIR(info.st_mode) and info.st_uid==self.owner_uid and not info.st_mode&0o022,'unsafe_Apache_configuration_parent')
        info=resolved.lstat();need(stat.S_ISREG(info.st_mode) and info.st_uid==self.owner_uid and not info.st_mode&0o022 and info.st_nlink==1 and info.st_size<=1048576,'unsafe_Apache_configuration_file')
        descriptor=os.open(str(resolved),os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(descriptor,'rb') as stream:
            opened=os.fstat(stream.fileno());raw=stream.read(1048577)
        need((opened.st_dev,opened.st_ino)==(info.st_dev,info.st_ino) and len(raw)<=1048576,'Apache_configuration_read_race')
        self.files[virtual]=dict(sha256=sha(raw),uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode),device=info.st_dev,inode=info.st_ino,mtime_ns=info.st_mtime_ns)
        return raw
    def matches(self,pattern):return sorted('/'+Path(p).relative_to(self.root).as_posix() for p in glob.glob(str(self.physical(pattern))))

def _tokens(line):
    try:return shlex.split(line,comments=True,posix=True)
    except ValueError:raise ApacheProfileError('unsupported_Apache_quoted_syntax')

def _graph(reader):
    output=dict(loads=[],handlers=[],vhosts=[],listeners=[],overrides=[],limitations=[],includes={})
    count=[0];size=[0]
    def visit(path,stack=(),server=None,contexts=()):
        raw=reader.read(path);canonical='/'+reader.physical(path).resolve().relative_to(reader.root).as_posix()
        need(canonical not in stack,'recursive_Apache_include');count[0]+=1;size[0]+=len(raw)
        need(count[0]<=256 and size[0]<=8388608,'Apache_configuration_graph_too_large')
        stack=stack+(canonical,);local=[];current=server
        text=re.sub(r'\\\r?\n',' ',raw.decode('utf-8'))
        for number,line in enumerate(text.splitlines(),1):
            line=line.strip()
            if not line or line.startswith('#'):continue
            if line.startswith('</'):
                match=re.fullmatch(r'</([A-Za-z]+)\s*>',line);need(match is not None and local,'unsupported_Apache_block')
                tag,previous=local.pop();need(tag.lower()==match.group(1).lower(),'unbalanced_Apache_block');current=previous;continue
            if line.startswith('<'):
                match=re.fullmatch(r'<([A-Za-z]+)\s*(.*?)>',line);need(match is not None,'unsupported_Apache_block')
                tag,args=match.groups();local.append((tag,current))
                if tag.lower()=='virtualhost':
                    current=dict(addresses=_tokens(args),server_names=[],document_roots=[],tls=False,path=canonical,line=number,php=False)
                    output['vhosts'].append(current)
                continue
            values=_tokens(line)
            if not values:continue
            name=values[0].lower();args=values[1:];context=contexts+tuple(t.lower() for t,_ in local)
            if name in ('include','includeoptional'):
                need(len(args)==1 and '$' not in args[0],'dynamic_Apache_include_requires_compatibility_plan')
                pattern=args[0] if args[0].startswith('/') else '/etc/apache2/'+args[0]
                need(pattern.startswith('/etc/apache2/') or pattern=='/etc/letsencrypt/options-ssl-apache.conf','out_of_tree_Apache_include')
                matches=reader.matches(pattern);need(matches or name=='includeoptional','missing_Apache_include')
                output['includes'][pattern]=matches
                for item in matches:visit(item,stack,current,context)
            elif name=='serverroot':need(args==['/etc/apache2'],'custom_Apache_ServerRoot_requires_compatibility_plan')
            elif name=='loadmodule':
                need(len(args)==2,'invalid_Apache_LoadModule');output['loads'].append(dict(identifier=args[0],path=args[1],config=canonical))
            elif name=='listen':output['listeners']+=args[:1]
            elif name in ('servername','serveralias') and current is not None:
                for value in args:
                    value=re.sub(r'^https?://','',value).split(':',1)[0]
                    need(re.fullmatch(r'[A-Za-z0-9_.-]+',value) is not None,'dynamic_Apache_server_name_requires_compatibility_plan');current['server_names'].append(value)
            elif name=='documentroot' and current is not None:
                need(len(args)==1 and args[0].startswith('/') and '$' not in args[0],'dynamic_Apache_document_root_requires_compatibility_plan');current['document_roots'].append(args[0])
            elif name=='sslengine' and current is not None:current['tls']=args==['on'] or args==['On']
            elif name in ('php_value','php_flag','php_admin_value','php_admin_flag'):
                need(len(args)>=2,'invalid_Apache_PHP_directive');output['overrides'].append(dict(key=args[0],kind=name,path=canonical,value_sha256=sha(' '.join(args[1:]).encode())))
            elif name in ('sethandler','addhandler','addtype','proxypassmatch','proxypass','action'):
                joined=' '.join(args)
                if not re.search(r'php|fcgi|fastcgi',joined,re.I):continue
                if 'proxy:unix:' in joined or 'unix:' in joined and '|fcgi://' in joined:
                    match=re.search(r'(?:proxy:)?unix:(/[^|\s]+)\|fcgi://localhost(?:/[^\s]*)?',joined)
                    if match:handler=dict(kind='fpm-fcgi',socket=match.group(1),path=canonical,line=number)
                    else:output['limitations'].append('nonstandard_FastCGI_backend_requires_compatibility_plan');continue
                elif 'application/x-httpd-php' in joined:handler=dict(kind='apache2handler',path=canonical,line=number)
                else:output['limitations'].append('custom_PHP_CGI_or_handler_requires_compatibility_plan');continue
                if any(t in ('if','elseif','else','ifdefine') for t in context):output['limitations'].append('conditional_PHP_handler_requires_compatibility_plan')
                handler['vhost']=output['vhosts'].index(current) if current is not None else None
                output['handlers'].append(handler)
        need(not local,'unbalanced_Apache_block')
    visit('/etc/apache2/apache2.conf')
    return output

def _ini(reader,branch,sapi):
    prefix='/etc/php/'+branch+'/'+sapi;patterns=[prefix+'/php.ini',prefix+'/conf.d/*.ini'];keys=[]
    for pattern in patterns:
        matches=reader.matches(pattern)
        need(matches or '*' in pattern,'Apache_PHP_ini_missing')
        for path in matches:
            for line in reader.read(path).decode().splitlines():
                match=re.match(r'^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)',line)
                if not match:continue
                key,value=match.groups();keys.append(key)
                if key in ('opcache.preload','opcache.preload_user'):
                    clean=value.split(';',1)[0].strip().strip('"\'')
                    need(clean in ('','0'),'custom_PHP_preload_requires_compatibility_plan_before_native_configtest')
    return dict(keys=sorted(set(keys)),patterns={p:reader.matches(p) for p in patterns})

def configured(root='/',owner_uid=0):
    """Does the active Apache include graph contain a PHP module/handler?"""
    if not (Path(root)/'etc/apache2/apache2.conf').exists():return False
    graph=_graph(ConfigReader(root,owner_uid))
    return bool(graph['handlers'] or any('libphp' in item['path'] for item in graph['loads']) or graph['limitations'])

def _native(backend,args,code):
    status,raw=backend.run(args);need(status==0,code);need(isinstance(raw,bytes) and len(raw)<=2097152,'invalid_Apache_native_evidence');return raw

def _health_specs(vhosts,listeners,addresses):
    specs=[]
    for vhost in vhosts:
        if not vhost.get('php'):continue
        names=vhost['server_names'] or ['localhost']
        for address in vhost['addresses'] or listeners:
            match=re.fullmatch(r'(?:(\*|_default_|[0-9.]+):)?([0-9]+)',address)
            if not match:continue
            ip,port=match.groups();port=int(port);ip='127.0.0.1' if ip in (None,'*','_default_','0.0.0.0') else ip
            if ip not in addresses or not 1<=port<=65535:continue
            for host in names:specs.append(dict(host=host,ip=ip,port=port,tls=bool(vhost['tls']),path='/'))
    return list({tuple(sorted(s.items())):s for s in specs}.values())

def discover(backend,current=None,root='/',owner_uid=0,capture_health=True):
    current=backend.snapshot() if current is None else current;reader=ConfigReader(root,owner_uid);graph=_graph(reader)
    limitations=list(graph['limitations']);loads=graph['loads']
    branches={m.group(1) for item in loads for m in [re.fullmatch(r'/usr/lib/apache2/modules/libphp([0-9]+\.[0-9]+)\.so',item['path'])] if m}
    sockets={h['socket'] for h in graph['handlers'] if h['kind']=='fpm-fcgi'}
    fpm_branches={m.group(1) for path in sockets for m in [re.search(r'php([0-9]+\.[0-9]+)',Path(path).name)] if m}
    need(not (branches and fpm_branches),'mixed_mod_php_and_FPM_handlers_require_compatibility_plan')
    need(len(branches|fpm_branches)==1,'unambiguous_Apache_PHP_branch_required')
    branch=next(iter(branches|fpm_branches));sapi='apache2handler' if branches else 'fpm-fcgi'
    ini=_ini(reader,branch,'apache2' if branches else 'fpm')
    configtest=_native(backend,['/usr/sbin/apache2ctl','-t'],'Apache_configtest_failed')
    raw_modules=_native(backend,['/usr/sbin/apache2ctl','-M'],'Apache_module_map_failed')
    modules=sorted(set(re.findall(r'^\s*([a-zA-Z0-9_]+_module)\s+\((?:shared|static)\)',raw_modules.decode(),re.M)))
    mpms=[m for m in modules if m in ('mpm_prefork_module','mpm_event_module','mpm_worker_module')]
    need(len(mpms)==1,'unambiguous_Apache_MPM_required');mpm=mpms[0]
    if sapi=='apache2handler':
        need(any(m in modules for m in ('php_module','php7_module','php8_module')),'configured_mod_php_not_loaded')
        if mpm!='mpm_prefork_module':limitations.append('nonstandard_mod_php_threaded_MPM_requires_explicit_ZTS_compatibility_plan')
        need('libapache2-mod-php'+branch in current['packages'],'package_owned_Ubuntu_mod_php_required')
    else:
        need({'proxy_module','proxy_fcgi_module'}<=set(modules),'Apache_proxy_fcgi_modules_required')
        need('php'+branch+'-fpm' in current['packages'],'package_owned_Ubuntu_FPM_required')
        # Every declared backend must identify an actual pool of the same branch.
        from fpm_pool_parser import parse_pools
        pool_sockets=set()
        global_path='/etc/php/'+branch+'/fpm/php-fpm.conf';global_raw=reader.read(global_path)
        includes=[m.group(1).strip().strip('"\'') for m in re.finditer(r'(?mi)^\s*include\s*=\s*([^\r\n;]+)',global_raw.decode())]
        need(includes==['/etc/php/'+branch+'/fpm/pool.d/*.conf'],'custom_FPM_include_requires_compatibility_plan')
        for path in reader.matches('/etc/php/'+branch+'/fpm/pool.d/*.conf'):
            for name,pool in parse_pools(reader.read(path),ApacheProfileError).items():
                for key,value in pool.all_items():
                    php=re.fullmatch(r'php_(?:admin_)?(?:value|flag)\[([^\]]+)\]',key)
                    if php and php.group(1).lower() in ('extension','zend_extension','extension_dir','opcache.preload','opcache.preload_user'):
                        need(value.strip().strip('"\'') in ('','0'),'custom_FPM_pool_loader_or_preload_requires_compatibility_plan')
                pool_sockets.add(pool.get('listen','').strip('"\'').replace('$pool',name))
        aliases=set(pool_sockets)
        for path in pool_sockets:
            if path.startswith('/run/'):aliases.add('/var'+path)
            if path.startswith('/var/run/'):aliases.add(path[4:])
        need(sockets<=aliases,'Apache_FastCGI_socket_not_owned_by_discovered_pool')
    raw_vhosts=_native(backend,['/usr/sbin/apache2ctl','-S'],'Apache_vhost_map_failed')
    for handler in graph['handlers']:
        if handler['vhost'] is None:
            for site in graph['vhosts']:site['php']=True
        else:graph['vhosts'][handler['vhost']]['php']=True
    need(graph['handlers'],'Apache_PHP_handler_configuration_required')
    runtime=backend.runtime()
    if sapi=='apache2handler' and any(row.get('php_branches')!=[branch] for row in runtime.get('apache',[])):
        limitations.append('live_Apache_PHP_branch_differs_from_configured_branch_requires_compatibility_plan')
    if any(row.get('branch')!=branch for row in runtime.get('fpm',[])):limitations.append('other_or_unverifiable_active_PHP_branch_requires_explicit_profile')
    if sapi=='apache2handler' and runtime.get('fpm'):limitations.append('additional_active_FPM_runtime_requires_explicit_profile')
    all_specs=_health_specs(graph['vhosts'],graph['listeners'],set(backend.local_addresses()))
    import health_policy
    specs=health_policy.filter_specs(all_specs,root,owner_uid) if all_specs else []
    policy=specs.policy if hasattr(specs,'policy') else health_policy.receipt(root,owner_uid)
    if runtime.get('apache_active') and not all_specs:limitations.append('local_Apache_PHP_health_endpoint_missing')
    health=backend.health(specs) if capture_health and runtime.get('apache_active') and specs else []
    profile=dict(schema='ubuntu-apache-php-profile-v1',sapi=sapi,mpm=mpm,source_branch=branch,modules=modules,vhosts=graph['vhosts'],handlers=graph['handlers'],config_files=reader.files,aliases=reader.aliases,include_graph=graph['includes'],ini_graph=ini['patterns'],php_ini_keys=ini['keys'],php_override_keys=sorted({i['key'] for i in graph['overrides']}),health_specs=specs,health_policy=policy,health_baseline=health,runtime=runtime,limitations=sorted(set(limitations)),os=current['os'],package_rows={n:r for n,r in current['packages'].items() if re.match(r'^(?:php'+re.escape(branch)+r'(?:-|$)|libapache2-mod-php'+re.escape(branch)+r'$)',n)},native_evidence=dict(configtest_sha256=sha(configtest),module_map_sha256=sha(raw_modules),vhost_map_sha256=sha(raw_vhosts)))
    profile['profile_sha256']=sha(encoded(profile));return profile

def prepare_plan(profile,target_branch=None):
    source=profile['source_branch'];target=target_branch or ('8.3' if source in LEGACY else source)
    need(target in TARGETS,'supported_PHP8_target_required')
    migration=source!=target;limitations=list(profile['limitations']);mapping={}
    for name in profile['package_rows']:
        if name=='libapache2-mod-php'+source:mapping[name]='libapache2-mod-php'+target
        elif name=='php'+source+'-json':mapping[name]='builtin:json' if migration else name
        elif name=='php'+source or name.startswith('php'+source+'-'):mapping[name]='php'+target+name[len('php'+source):]
    required=sorted({n for n in mapping.values() if not n.startswith('builtin:')})
    actions=[];sequence=['authenticated_same_release_package_plan_and_exact_no_remove_simulation','preserve_all_existing_Apache_and_PHP_configuration','native_Apache_configtest_and_module_vhost_maps','graceful_same_topology_service_reload_by_caller','wait_for_old_code_and_extension_mappings_to_drain','repeat_identical_local_TLS_HTTP_health_baseline']
    if migration:
        limitations.append('major_migration_requires_explicit_application_and_INI_compatibility_evidence')
        actions=[dict(kind='preserve-SAPI-and-MPM',sapi=profile['sapi'],mpm=profile['mpm']),dict(kind='port-explicit-supported-settings-to-fresh-target-SAPI-ini',source_sapi='apache2' if profile['sapi']=='apache2handler' else 'fpm'),dict(kind='retain-source-packages-and-configs-until-target-acceptance')]
        if profile['sapi']=='apache2handler':actions.append(dict(kind='stage-native-target-module-configtest-before-atomic-module-symlink-cutover',source_module='php'+source,target_module='php'+target))
        else:actions.append(dict(kind='stage-target-FPM-pools-and-rewrite-only-exact-owned-Unix-backend-sockets',sockets=sorted({h['socket'] for h in profile['handlers'] if 'socket' in h})))
        sequence.insert(2,'prove_WordPress_or_application_compatibility_and_target_extension_registry_coverage')
    supported=not limitations and not migration
    return dict(schema='ubuntu-apache-php-plan-v1',mode='patch' if supported else 'compatibility-plan',supported=supported,source_branch=source,target_branch=target,sapi=profile['sapi'],mpm=profile['mpm'],package_mapping=mapping,required_targets=required,configuration_actions=actions,activation_sequence=sequence,limitations=sorted(set(limitations)),baseline=profile,production_changes=0,automatic_SAPI_switch=False,automatic_MPM_switch=False)

def verify(backend,plan,current=None,root='/',owner_uid=0,expected_packages=None):
    need(plan.get('schema')=='ubuntu-apache-php-plan-v1','invalid_Apache_profile_plan')
    before=plan['baseline'];after=discover(backend,current,root,owner_uid);target=plan['target_branch']
    comparable=lambda files:{path:{k:item[k] for k in ('sha256','uid','gid','mode')} for path,item in files.items()}
    aliases=lambda files:{path:item['target'] for path,item in files.items()}
    checks=dict(sapi_preserved=after['sapi']==plan['sapi'],mpm_preserved=after['mpm']==plan['mpm'],target_branch=after['source_branch']==target,native_configuration_valid=True,module_map_preserved=after['modules']==before['modules'] if target==plan['source_branch'] else True,configurations_preserved=comparable(after['config_files'])==comparable(before['config_files']) and aliases(after['aliases'])==aliases(before['aliases']),vhost_routes_preserved=after['vhosts']==before['vhosts'] and after['handlers']==before['handlers'],no_profile_limitations=not after['limitations'],service_activity_preserved=after['runtime'].get('apache_active')==before['runtime'].get('apache_active'),health_preserved=after['health_baseline']==before['health_baseline'])
    rows=backend.snapshot()['packages'] if current is None else current['packages']
    checks['exact_expected_package_targets']=bool(expected_packages) and set(plan['required_targets'])<=set(expected_packages) and all(rows.get(n)==r for n,r in (expected_packages or {}).items())
    runtime=after['runtime'];active=runtime.get('apache_active') is True
    checks['Apache_executables_current']=bool(runtime.get('apache')) and all(w.get('executable_current',w.get('maps_current')) is True for w in runtime.get('apache',[])) if active else True
    workers=runtime.get('apache',[]) if plan['sapi']=='apache2handler' else [r for r in runtime.get('fpm',[]) if r.get('branch')==target]
    checks['live_PHP_code_and_extensions_current']=bool(active and workers) and all(w.get('maps_current') is True and (w.get('php_branches')==[target] if plan['sapi']=='apache2handler' else w.get('branch')==target) and w.get('api_directories') for w in workers)
    old_modules={m for w in (before['runtime'].get('apache',[]) if plan['sapi']=='apache2handler' else before['runtime'].get('fpm',[])) for m in w.get('extension_modules',[])}
    new_modules={m for w in workers for m in w.get('extension_modules',[])}
    checks['runtime_extension_coverage_preserved']=old_modules<=new_modules if active else not before['runtime'].get('apache_active')
    old_apis={p for w in (before['runtime'].get('apache',[]) if plan['sapi']=='apache2handler' else before['runtime'].get('fpm',[])) for p in w.get('api_directories',[])}
    checks['PHP_API_directory_preserved']=not active or (len(old_apis)==1 and all(set(w.get('api_directories',[]))==old_apis for w in workers))
    acceptance={k:v for k,v in checks.items() if k!='live_PHP_code_and_extensions_current' or active}
    status='apache_php_patch_verified' if all(acceptance.values()) else 'apache_php_verification_failed_or_pending'
    if status=='apache_php_patch_verified' and not active:status='apache_php_configured_patch_verified_inactive_runtime_not_claimed'
    observed=lambda rows:any(w.get('stale_maps_observed') is True or w.get('stale_executable_observed') is True for w in rows)
    stale_services=[]
    if observed(runtime.get('apache',[])):stale_services.append('apache2.service')
    if plan['sapi']=='fpm-fcgi' and observed(workers):stale_services.append('php'+target+'-fpm.service')
    return dict(status=status,checks=checks,stale_runtime_mapping_or_executable_observed=bool(stale_services),stale_services=stale_services,source_branch=plan['source_branch'],target_branch=target,sapi=plan['sapi'],mpm=plan['mpm'],profile_sha256=after['profile_sha256'],package_authentication_and_CVE_floor='caller_must_validate_signed_candidate_plan; this profile matches exact expected installed rows only',production_changes=0)

def authenticated_installed(backend,profile):
    """Post-Noble read-only signed same-release/core-floor verification."""
    import php_legacy_packages as pkg
    current=backend.snapshot();pkg.validate_release(current);branch=profile['source_branch']
    need(pkg.supported(branch),'Apache_PHP_branch_security_support_expired')
    prefix='php'+branch;module='libapache2-mod-php'+branch
    names=sorted(n for n in current['packages'] if n==module or n==prefix or n.startswith(prefix+'-'))
    need(prefix+'-common' in names and (module in names if profile['sapi']=='apache2handler' else prefix+'-fpm' in names),'Apache_PHP_core_packages_missing')
    records={};rows={}
    for name in names:
        record=backend.candidate(name);row=current['packages'][name]
        pkg.validate_candidate(name,record,current,backend,php=name!=module,target_branch=branch)
        if name==module:
            need(pkg.fixed_core(record,backend,current,branch),'unfixed_Apache_PHP_module_candidate')
            for value in (record['version'],record['source_version']):need(not any('ubuntu'+v in value for v in ('18.04','20.04','22.04')),'foreign_release_Apache_PHP_module_candidate')
            if any(o['origin']=='LP-PPA-ondrej-php' for o in record['origins']):need('ubuntu24.04' in record['version'],'matching_Noble_Apache_PHP_PPA_build_required')
        need(row==dict(version=record['version'],architecture=record['architecture'],status='ii'),'installed_Apache_PHP_not_exact_authenticated_candidate')
        rows[name]=row;records[name]=record
    return dict(status='exact_authenticated_fixed_Apache_PHP_packages_verified',expected_packages=rows,candidates_sha256=sha(encoded(records)),branch=branch,sapi=profile['sapi'])

class NativeBackend:
    """Read-only commands. The caller supplies authenticated package planning."""
    def snapshot(self):
        release={}
        for line in Path('/etc/os-release').read_text().splitlines():
            if '=' in line:
                key,value=line.split('=',1)
                if key in ('ID','VERSION_ID','VERSION_CODENAME'):release[key]=value.strip('"')
        status,raw=self.run(['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n'])
        need(status==0,'Apache_package_inventory_failed');rows={}
        for line in raw.decode().splitlines():
            name,version,architecture,state=line.split('\t');state=state.strip()
            if state.startswith('rc') or state in ('un','pn'):continue
            need(name not in rows,'multiarch_Apache_inventory_requires_compatibility_plan');rows[name]=dict(version=version,architecture=architecture,status=state)
        return dict(os=release,packages=rows)
    def run(self,args):
        curl=args[:1]==['/usr/bin/curl'] and all(flag in args for flag in ('--disable','--noproxy','--resolve','--output','--write-out')) and not any(flag in args for flag in ('--data','--data-raw','--form','--upload-file','--request','-X','-d','-F','-T')) and len(args)>1 and re.match(r'^https?://[A-Za-z0-9_.-]+:[0-9]+/',args[-1]) is not None and args[args.index('--output')+1]=='/dev/null'
        package_query=args==['/usr/bin/dpkg-query','-W','-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Abbrev}\n']
        owner_query=len(args)==3 and args[:2]==['/usr/bin/dpkg-query','-S'] and re.fullmatch(r'/usr/(?:sbin/(?:apache2|php-fpm[0-9]+\.[0-9]+)|lib/apache2/modules/libphp[0-9]+\.[0-9]+\.so|lib/php/[0-9]{8}/[A-Za-z0-9_.-]+\.so)',args[2]) is not None
        allowed=(args[:1]==['/usr/sbin/apache2ctl'] and args[1:] in (['-t'],['-M'],['-S'])) or args==['/usr/sbin/ip','-j','address','show'] or package_query or owner_query or curl
        need(allowed,'mutating_or_unknown_Apache_backend_command_forbidden')
        result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20,env=ENV)
        raw=result.stdout+(result.stderr if args[:1]==['/usr/sbin/apache2ctl'] else b'')
        need(len(raw)<=2097152,'Apache_native_output_too_large');return result.returncode,raw
    def local_addresses(self):
        code,raw=self.run(['/usr/sbin/ip','-j','address','show']);need(code==0,'local_address_inventory_failed')
        return {'127.0.0.1'}|{a['local'] for row in json.loads(raw) for a in row.get('addr_info',[]) if a.get('family')=='inet'}
    def health(self,specs):
        if hasattr(specs,'policy'):
            import health_policy
            health_policy.verify_specs(specs)
        results=[]
        for item in specs:
            scheme='https' if item['tls'] else 'http';host=item['host'];port=str(item['port'])
            args=['/usr/bin/curl','--disable','--silent','--show-error','--noproxy','*','--connect-timeout','3','--max-time','8','--resolve',host+':'+port+':'+item['ip'],'--output','/dev/null','--write-out','%{http_code}',scheme+'://'+host+':'+port+item['path']]
            code,raw=self.run(args);status=raw.decode().strip();need(code==0 and re.fullmatch(r'[23][0-9]{2}',status),'local_Apache_health_failed')
            results.append(dict(item,status=status))
        return results
    def runtime(self):
        apache=[];fpm=[];packages=self.snapshot()['packages'];owners={}
        def owned(path,branch=None):
            if path not in owners:
                code,raw=self.run(['/usr/bin/dpkg-query','-S',path]);names=[line.split(': ',1)[0].split(':',1)[0] for line in raw.decode().splitlines() if ': ' in line]
                owners[path]=names if code==0 else []
            names=owners[path]
            expected='apache2-bin' if path=='/usr/sbin/apache2' else ('php'+branch+'-fpm' if path.startswith('/usr/sbin/') else 'libapache2-mod-php'+branch if '/apache2/modules/' in path else None)
            return len(names)==1 and names[0] in packages and packages[names[0]]['status']=='ii' and (names[0]==expected if expected else names[0].startswith('php'+branch+'-'))
        for process in Path('/proc').iterdir():
            if not process.name.isdecimal():continue
            kind=None;branch=None
            try:
                comm=(process/'comm').read_text().strip()
                if comm!='apache2' and not comm.startswith('php-fpm'):continue
                kind='apache' if comm=='apache2' else 'fpm'
                start=(process/'stat').read_text().rsplit(')',1)[1].split()[19]
                executable=os.readlink(process/'exe');canonical=executable[:-10] if executable.endswith(' (deleted)') else executable
                branch=re.fullmatch(r'/usr/sbin/php-fpm([0-9]+\.[0-9]+)',canonical)
                if comm!='apache2' and branch is None:
                    fpm.append(dict(pid=int(process.name),branch=None,maps_current=False,executable_current=False,php_branches=[],api_directories=[],extension_modules=[]));continue
                expected='/usr/sbin/apache2' if comm=='apache2' else canonical
                live=(process/'exe').stat();disk=Path(expected).stat()
                same_inode=(live.st_dev,live.st_ino)==(disk.st_dev,disk.st_ino)
                stale_executable=executable in (expected,expected+' (deleted)') and (not same_inode or executable.endswith(' (deleted)'))
                executable_current=executable==expected and same_inode and stat.S_ISREG(disk.st_mode) and disk.st_uid==0 and not disk.st_mode&0o022 and owned(expected,branch.group(1) if branch else None)
                paths=[];valid=bool(executable_current);stale_maps=False
                for line in (process/'maps').read_text().splitlines():
                    fields=line.split(None,5)
                    if len(fields)!=6:continue
                    path=fields[5]
                    if not (re.match(r'/usr/lib/apache2/modules/libphp[0-9.]+\.so',path) or path.startswith('/usr/lib/php/')):continue
                    paths.append(path)
                    if path.endswith(' (deleted)'):valid=False;stale_maps=True;continue
                    info=Path(path).stat();major,minor=fields[3].split(':')
                    same_map=(int(major,16),int(minor,16),int(fields[4]))==(os.major(info.st_dev),os.minor(info.st_dev),info.st_ino)
                    stale_maps=stale_maps or not same_map
                    valid=valid and same_map and info.st_uid==0 and not info.st_mode&0o022
                clean_paths=[p[:-10] if p.endswith(' (deleted)') else p for p in paths]
                module_branches=sorted({m.group(1) for p in clean_paths for m in [re.fullmatch(r'/usr/lib/apache2/modules/libphp([0-9]+\.[0-9]+)\.so',p)] if m})
                map_branch=branch.group(1) if branch else module_branches[0] if len(module_branches)==1 else None
                valid=bool(valid and map_branch and all(owned(p,map_branch) for p in set(paths)))
                need((process/'stat').read_text().rsplit(')',1)[1].split()[19]==start and os.readlink(process/'exe')==executable,'Apache_process_identity_changed_during_read')
                row=dict(pid=int(process.name),start_time_ticks=start,executable=executable,executable_current=bool(executable_current),stale_executable_observed=bool(stale_executable),stale_maps_observed=bool(stale_maps),maps_current=bool(valid and paths),php_branches=module_branches,api_directories=sorted({m.group(1) for p in clean_paths for m in [re.match(r'(/usr/lib/php/[0-9]{8})/',p)] if m}),extension_modules=sorted({Path(p).name for p in clean_paths if re.match(r'/usr/lib/php/[0-9]{8}/[^/]+\.so$',p)}))
                if comm=='apache2':apache.append(row)
                else:row['branch']=branch.group(1);fpm.append(row)
            except (FileNotFoundError,ProcessLookupError):
                if kind and process.exists():
                    row=dict(pid=int(process.name),maps_current=False,executable_current=False,php_branches=[],api_directories=[],extension_modules=[])
                    if kind=='apache':apache.append(row)
                    else:row['branch']=branch.group(1) if branch else None;fpm.append(row)
            except PermissionError:raise ApacheProfileError('Apache_runtime_mapping_unreadable')
        return dict(apache_active=bool(apache),apache=apache,fpm=fpm)
