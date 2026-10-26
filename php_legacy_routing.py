"""Conservative, local Nginx/FPM configuration migration. No service or APT calls.

preflight runs before package changes; build_plan uses newly installed target
defaults. Stage/test both trees, apply FPM, activate/test the new FPM externally,
then apply Nginx. The caller owns health checks, old-FPM retirement and CLI.
"""
import base64,fnmatch,glob,hashlib,json,os,re,stat
from dataclasses import dataclass,field
from pathlib import Path,PurePosixPath

class RoutingError(ValueError):pass
def need(ok,code):
    if not ok:raise RoutingError(code)
def digest(data):return hashlib.sha256(data).hexdigest()
def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()

# Shared directives, not legacy defaults. Only changes from the shipped source
# template are ported; fresh target defaults remain for every unmodified setting.
SHARED=set('memory_limit max_execution_time max_input_time max_input_vars post_max_size upload_max_filesize max_file_uploads file_uploads default_socket_timeout date.timezone default_charset output_buffering implicit_flush precision serialize_precision realpath_cache_size realpath_cache_ttl disable_functions disable_classes open_basedir display_errors display_startup_errors log_errors error_log error_reporting expose_php allow_url_fopen allow_url_include cgi.fix_pathinfo short_open_tag html_errors ignore_user_abort report_memleaks zend.assertions zend.exception_ignore_args zend.exception_string_param_max_len variables_order request_order register_argc_argv auto_globals_jit session.save_handler session.save_path session.name session.auto_start session.use_strict_mode session.use_cookies session.use_only_cookies session.cookie_lifetime session.cookie_path session.cookie_domain session.cookie_secure session.cookie_httponly session.cookie_samesite session.gc_probability session.gc_divisor session.gc_maxlifetime session.cache_limiter session.cache_expire session.use_trans_sid session.sid_length session.sid_bits_per_character opcache.enable opcache.enable_cli opcache.memory_consumption opcache.interned_strings_buffer opcache.max_accelerated_files opcache.validate_timestamps opcache.revalidate_freq opcache.save_comments opcache.file_cache opcache.file_cache_only opcache.max_wasted_percentage'.split())
FORBIDDEN_INI={'extension','zend_extension','extension_dir','auto_prepend_file','auto_append_file','include_path','opcache.preload','opcache.preload_user'}
TARGETS={'8.2','8.3','8.4','8.5'}
SOURCES={'7.2','7.3','7.4','8.0','8.1'}
def _target(value):
    need(value in TARGETS,'explicit_supported_target_branch_required');return value
def _safe_forward(key,value):
    need(key not in FORBIDDEN_INI and not OLD_API.search(value) and not re.search(r'/usr/lib/php/[0-9]{8}(?:/|\b)',value),'unsafe_custom_extension_setting')
    need(not re.search(r'\$\{|[\r\n\x00]',value),'dynamic_custom_extension_setting')
def _settings_digest(d):
    return digest(encoded(dict(source=d.source_branch,source_php_api=d.source_php_api,target=d.target_branch,main=d.ini_overrides,extra=d.extra_ini,pool=d.pool_ini,modules=d.required_modules,ini_graph=d.source_ini_graph,sources={k:v.public() for k,v in d.snapshots.items()})))
def _source_ini_graph(d,check=False):
    graph={}
    for sapi in ('cli','fpm'):
        pattern='/etc/php/'+d.source_branch+'/'+sapi+'/conf.d/*.ini'
        graph[pattern]=d.fs.matches_glob(pattern)
        for path in graph[pattern]:
            p=d.fs.physical(path);d.fs.resolve(str(PurePosixPath(path).parent));parent=p.parent.lstat();i=p.lstat()
            need(stat.S_ISDIR(parent.st_mode) and not stat.S_ISLNK(parent.st_mode) and parent.st_uid==d.fs.owner_uid and not parent.st_mode&0o022,'unsafe_old_ini_parent')
            need(i.st_uid==d.fs.owner_uid,'unsafe_old_ini_link_owner')
            graph[path]=dict(target=str(p.resolve().relative_to(d.fs.root)),device=i.st_dev,inode=i.st_ino,mtime_ns=i.st_mtime_ns)
    if check:need(graph==d.source_ini_graph,'old_extension_configuration_graph_changed')
    return graph
def registry_commands(d):
    _target(d.target_branch);commands={}
    for sapi in ('cli','fpm'):
        code='echo json_encode(["branch"=>PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION,"configuration_sapi"=>"'+sapi+'","keys"=>array_keys(ini_get_all(null,false)),"modules"=>get_loaded_extensions()]);'
        commands[sapi]=['/usr/bin/env','PHP_INI_SCAN_DIR=/etc/php/'+d.target_branch+'/'+sapi+'/conf.d','/usr/bin/php'+d.target_branch,'-c','/etc/php/'+d.target_branch+'/'+sapi+'/php.ini','-d','auto_prepend_file=','-d','auto_append_file=','-d','opcache.preload=','-r',code]
    return commands
def _module_name(value):return re.sub(r'[^a-z0-9]','',value.lower().replace('.so','').replace('zend ',''))
def validate_target_ini_registry(d,registries):
    need(not d.audit_only,'audit_only_has_no_migration_settings');proof={}
    for sapi in ('cli','fpm'):
        item=registries.get(sapi,{})
        need(item.get('branch')==d.target_branch and item.get('configuration_sapi')==sapi,'target_ini_registry_identity_mismatch')
        keys=item.get('keys');modules=item.get('modules')
        need(isinstance(keys,list) and bool(keys) and all(isinstance(k,str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.]*',k) for k in keys) and len(keys)==len(set(keys)),'invalid_target_ini_registry')
        need(isinstance(modules,list) and bool(modules) and all(isinstance(m,str) and bool(m) for m in modules),'target_loaded_modules_required')
        wanted=set(d.ini_overrides.get(sapi,{})) | set(d.extra_ini.get(sapi,{})) | (set(d.pool_ini) if sapi=='fpm' else set())
        # CGI-only core directive is absent from a CLI binary's registry even
        # when that binary loads FPM's ini. It remains explicitly template-known.
        exceptions={'cgi.fix_pathinfo'} if sapi=='fpm' else set()
        need(wanted.issubset(set(keys)|exceptions),'unsupported_target_extension_setting')
        loaded={_module_name(m) for m in modules}
        need({_module_name(m) for m in d.required_modules.get(sapi,[]) if m!='json'}.issubset(loaded),'target_extension_module_not_loaded')
        proof[sapi]=dict(keys_sha256=digest(encoded(sorted(keys))),modules_sha256=digest(encoded(sorted(modules))),forwarded_keys=sorted(wanted))
    d.registry_validation=dict(target_branch=d.target_branch,settings_sha256=_settings_digest(d),registries=proof)
    return dict(d.registry_validation)
def _require_registry(d):
    need(d.registry_validation.get('target_branch')==d.target_branch and d.registry_validation.get('settings_sha256')==_settings_digest(d),'target_ini_registry_validation_required')
OLD_API=re.compile(r'(?:/etc/php/[0-9]+\.[0-9]+(?:/|\b)|/usr/lib/php/[0-9]{8}(?:/|\b)|php(?:7\.[234]|8\.[01])(?:[-./]|\b))')
POOL_KEYS=set('user group listen listen.backlog listen.owner listen.group listen.mode listen.acl_users listen.acl_groups listen.allowed_clients process.priority process.dumpable pm pm.max_children pm.start_servers pm.min_spare_servers pm.max_spare_servers pm.max_spawn_rate pm.process_idle_timeout pm.max_requests pm.status_path ping.path ping.response access.log access.format slowlog request_slowlog_timeout request_slowlog_trace_depth request_terminate_timeout request_terminate_timeout_track_finished rlimit_files rlimit_core chroot chdir catch_workers_output decorate_workers_output clear_env security.limit_extensions prefix'.split())
GLOBAL_KEYS=set('pid error_log syslog.facility syslog.ident log_level log_limit log_buffering emergency_restart_threshold emergency_restart_interval process_control_timeout process.max process.priority daemonize rlimit_files rlimit_core events.mechanism systemd_interval include'.split())

@dataclass
class Snapshot:
    path:str;sha256:str;uid:int;gid:int;mode:int;device:int;inode:int;mtime_ns:int
    content:bytes=field(repr=False)
    def public(self):return {k:getattr(self,k) for k in ('path','sha256','uid','gid','mode','device','inode','mtime_ns')}

class FileSystem:
    def __init__(self,root='/',owner_uid=0):self.root=Path(root).resolve();self.owner_uid=owner_uid
    def physical(self,path):
        need(str(path).startswith('/') and '..' not in PurePosixPath(str(path)).parts,'unsafe_configuration_path')
        return self.root/str(path).lstrip('/')
    def exists(self,path):return self.physical(path).exists() or self.physical(path).is_symlink()
    def resolve(self,path,allow_link=False):
        p=self.physical(path);resolved=p.resolve();need(resolved==self.root or self.root in resolved.parents,'configuration_link_escapes_root')
        current=self.root
        for part in PurePosixPath(str(path)).parts[1:-1]:
            current=current/part;i=current.lstat();need(stat.S_ISDIR(i.st_mode) and not stat.S_ISLNK(i.st_mode) and i.st_uid==self.owner_uid and not i.st_mode&0o022,'unsafe_configuration_alias_parent')
        relative=resolved.relative_to(self.root);virtual='/'+relative.as_posix()
        if p.is_symlink():need(allow_link and p.lstat().st_uid==self.owner_uid and virtual.startswith(('/etc/nginx/','/usr/share/nginx/modules-available/')),'unsupported_configuration_symlink')
        current=self.root
        for part in relative.parts[:-1]:
            current=current/part;i=current.lstat();need(stat.S_ISDIR(i.st_mode) and i.st_uid==self.owner_uid and not i.st_mode&0o022,'unsafe_configuration_parent')
        return virtual,resolved
    def capture(self,path,allow_link=False):
        virtual,p=self.resolve(path,allow_link);i=p.lstat()
        need(stat.S_ISREG(i.st_mode) and i.st_uid==self.owner_uid and not i.st_mode&0o022 and i.st_nlink==1 and i.st_size<=1048576,'unsafe_configuration_file')
        # ACL/labels require an explicit preservation policy; do not erase them.
        need(not hasattr(os,'listxattr') or not os.listxattr(p),'configuration_xattrs_require_manual_review')
        fd=os.open(str(p),os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:opened=os.fstat(stream.fileno());data=stream.read(1048577)
        need((opened.st_dev,opened.st_ino)==(i.st_dev,i.st_ino) and len(data)<=1048576,'configuration_read_race')
        return Snapshot(virtual,digest(data),i.st_uid,i.st_gid,stat.S_IMODE(i.st_mode),i.st_dev,i.st_ino,i.st_mtime_ns,data)
    def matches(self,snapshot):
        try:return self.capture(snapshot.path).public()==snapshot.public()
        except (OSError,RoutingError):return False
    def matches_glob(self,pattern):return sorted('/'+Path(p).relative_to(self.root).as_posix() for p in glob.glob(str(self.physical(pattern))))

def ini_values(data,known=False):
    result={}
    for raw in data.decode('utf-8').splitlines():
        line=raw.strip()
        if known and line.startswith(';'):line=line[1:].strip()
        if not line or line[0] in ';#':continue
        if line.startswith('['):
            if known:continue
            need(not line.upper().startswith(('[PATH=','[HOST=')),'per_directory_ini_requires_manual_review');continue
        match=re.fullmatch(r'([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)',line)
        need(match is not None or known,'unsupported_ini_syntax')
        if not match:continue
        key,value=match.groups()
        if known:result.setdefault(key,value);continue
        need(key not in result or key in ('extension','zend_extension'),'duplicate_ini_setting')
        result[key]=value
    return result

@dataclass
class Discovery:
    root:Path;fs:FileSystem;snapshots:dict=field(default_factory=dict);pools:dict=field(default_factory=dict)
    nginx_files:dict=field(default_factory=dict);socket_map:dict=field(default_factory=dict);ini_overrides:dict=field(default_factory=dict)
    server_names:list=field(default_factory=list);listeners:list=field(default_factory=list);document_roots:list=field(default_factory=list)
    include_patterns:dict=field(default_factory=dict);route_edits:dict=field(default_factory=dict);include_edits:dict=field(default_factory=dict)
    pool_contents:dict=field(default_factory=dict,repr=False);global_values:dict=field(default_factory=dict,repr=False);extra_ini:dict=field(default_factory=dict,repr=False)
    target_ini_keys:set=field(default_factory=set);servers:list=field(default_factory=list);wordpress:list=field(default_factory=list)
    source_branch:str='';target_branch:str='8.3';distroversion:str='';audit_only:bool=False
    source_php_api:str='';source_extension_dir:str=''
    pool_ini:dict=field(default_factory=dict,repr=False);registry_validation:dict=field(default_factory=dict);required_modules:dict=field(default_factory=dict)
    source_ini_graph:dict=field(default_factory=dict)
    def public_manifest(self):return dict(source_php_api=self.source_php_api,source_extension_dir=self.source_extension_dir,source_branch=self.source_branch,target_branch=self.target_branch,distroversion=self.distroversion,audit_only=self.audit_only,registry_validation=self.registry_validation,pool_ini_keys=sorted(self.pool_ini),pools={k:{n:v[n] for n in ('source_path','source_socket','target_socket','user','group')} for k,v in self.pools.items()},server_names=self.server_names,listeners=self.listeners,document_roots=self.document_roots,servers=self.servers,wordpress=self.wordpress,source_files={k:v.public() for k,v in self.snapshots.items()},ini_modified_keys={k:sorted(v) for k,v in self.ini_overrides.items()},extra_ini_keys={k:sorted(v) for k,v in self.extra_ini.items()})

def _read(d,path,link=False):
    snap=d.fs.capture(path,link);d.snapshots.setdefault(snap.path,snap);return snap

def _pool_parse(data):
    sections={};current=None
    for raw in data.decode().splitlines():
        line=raw.strip()
        if not line or line.startswith((';','#')):continue
        section=re.fullmatch(r'\[([A-Za-z0-9_.-]+)\]',line)
        if section:
            current=section.group(1);need(current not in sections,'duplicate_fpm_pool');sections[current]={};continue
        match=re.fullmatch(r'([A-Za-z0-9_.]+(?:\[[^\]\r\n]+\])?)\s*=\s*(.+)',line)
        need(current is not None and match is not None,'unsupported_pool_syntax')
        key,value=match.groups();need(key not in sections[current],'duplicate_pool_directive');sections[current][key]=value
    need(bool(sections),'empty_old_pool_file');return sections

def _tokens(text):
    # Token positions permit exact replacement without reformatting other data.
    out=[];i=0
    while i<len(text):
        if text[i].isspace():i+=1;continue
        if text[i]=='#':i=text.find('\n',i) if '\n' in text[i:] else len(text);continue
        start=i
        if text[i] in '{};':out.append((text[i],i,i+1));i+=1;continue
        quoted=text[i] in "\"'"
        if quoted:
            quote=text[i];i+=1;value=''
            while i<len(text) and text[i]!=quote:
                if text[i]=='\\':need(i+1<len(text),'nginx_unterminated_escape');i+=1
                value+=text[i];i+=1
            need(i<len(text),'nginx_unterminated_string');i+=1
        else:
            value=''
            while i<len(text) and not text[i].isspace() and text[i] not in '{};#':
                if text[i]=='\\':need(i+1<len(text),'nginx_unterminated_escape');i+=1
                value+=text[i];i+=1
        need(bool(value) or quoted,'empty_nginx_token');out.append((value,start,i))
    return out

def _nginx(d):
    calls=[0]
    def visit(logical,stack,context=(),server=None):
        snap=_read(d,logical,True);need(snap.path not in stack,'recursive_nginx_include');stack=stack+(snap.path,)
        calls[0]+=1;need(calls[0]<=256 and sum(len(s.content) for s in d.snapshots.values())<=8388608,'nginx_graph_too_large')
        d.nginx_files[logical]=snap.path;tokens=_tokens(snap.content.decode());pos=0
        if d.audit_only:need(not any(OLD_API.search(token[0]) for token in tokens),'legacy_php_reference_in_active_nginx')
        def parse(ctx,record,nested=False):
            nonlocal pos
            while pos<len(tokens):
                if tokens[pos][0]=='}':need(nested,'unbalanced_nginx_brace');pos+=1;return
                directive=[]
                while pos<len(tokens) and tokens[pos][0] not in (';','{','}'):
                    directive.append(tokens[pos]);pos+=1
                need(directive and pos<len(tokens),'unsupported_nginx_syntax');ending=tokens[pos][0];pos+=1;name=directive[0][0];args=[t[0] for t in directive[1:]]
                if ending=='{':
                    child=record
                    if name=='server' and ctx and ctx[-1]=='http':child=dict(server_names=[],listeners=[],document_roots=[]);d.servers.append(child)
                    parse(ctx+(name,),child,True);continue
                need(ending==';','unsupported_nginx_syntax')
                if name=='include':
                    need(len(args)==1 and '$' not in args[0],'dynamic_nginx_include')
                    pattern=args[0] if args[0].startswith('/') else '/etc/nginx/'+args[0]
                    need(pattern.startswith(('/etc/nginx/','/usr/share/nginx/modules-available/')) or pattern=='/etc/letsencrypt/options-ssl-nginx.conf','out_of_tree_nginx_include')
                    matches=d.fs.matches_glob(pattern);need(bool(matches) or any(x in pattern for x in '*?['),'missing_nginx_include')
                    d.include_patterns[pattern]=matches;d.include_edits.setdefault(snap.path,{})[(directive[1][1],directive[1][2])]=pattern
                    for path in matches:visit(path,stack,ctx,record)
                elif name=='fastcgi_pass':
                    need(len(args)==1 and args[0].startswith('unix:') and args[0][5:] in d.socket_map,'ambiguous_or_other_php_upstream')
                    need(record is not None,'php_route_without_server_context');record['legacy_php']=d.source_branch in SOURCES;record['php']=True;record['php_branch']=d.source_branch
                    d.route_edits.setdefault(snap.path,{})[(directive[1][1],directive[1][2])]='unix:'+d.socket_map[args[0][5:]]
                elif name=='fastcgi_param' and args and args[0] in ('PHP_VALUE','PHP_ADMIN_VALUE'):need(False,'nginx_php_value_override_requires_manual_review')
                elif record is not None and name in ('server_name','listen','root'):
                    if name=='server_name':
                        need(all(re.fullmatch(r'[A-Za-z0-9_.*-]+',a) for a in args),'dynamic_server_name');record['server_names']+=args
                    elif name=='listen':record['listeners'].append(' '.join(args))
                    else:need(len(args)==1 and args[0].startswith('/') and '$' not in args[0],'dynamic_document_root');record['document_roots'].append(args[0])
            need(not nested,'unbalanced_nginx_brace')
        parse(context,server)
    visit('/etc/nginx/nginx.conf',())
    need(bool(d.route_edits),'no_active_selected_php_nginx_route')
    for key,attribute in [('server_names','server_names'),('listeners','listeners'),('document_roots','document_roots')]:setattr(d,attribute,sorted({v for server in d.servers if server.get('php') for v in server[key]}))

def preflight(root,facts,legacy_ini_templates=None,target_ini_keys=None):
    fs=root if isinstance(root,FileSystem) else FileSystem(root);d=Discovery(fs.root,fs)
    d.target_branch=_target(facts.get('target_branch'));d.distroversion=facts.get('distroversion',facts.get('VERSION_ID'));need(d.distroversion=='24.04','Noble_required_before_legacy_migration')
    d.source_branch=facts.get('source_branch');need(d.source_branch in SOURCES,'explicit_legacy_source_branch_required')
    d.source_php_api=facts.get('source_php_api','');d.source_extension_dir=facts.get('source_extension_dir','')
    need(re.fullmatch(r'[0-9]{8}',d.source_php_api) is not None and d.source_extension_dir=='/usr/lib/php/'+d.source_php_api,'discovered_source_PHP_API_required')
    need(facts.get('containers') is False and not fs.exists('/.dockerenv') and not fs.exists('/run/.containerenv'),'container_or_unknown_container_state')
    need(facts.get('old_cli',facts.get('php_cli_target'))=='/usr/bin/php'+d.source_branch and facts.get('hardcoded_cli_refs')==[],'custom_cli_routing_requires_manual_review')
    need(facts.get('nginx_configtest_exit')==0,'old_nginx_configtest_required')
    packages=facts.get('package_rows',{});need(isinstance(packages,dict) and bool(packages),'package_inventory_required')
    branches={m.group(1) for n in packages for m in [re.match(r'^(?:php|libapache2-mod-php|libphp)([0-9]+\.[0-9]+)(?:-|$)',n)] if m}
    need(branches=={d.source_branch} and all('php'+d.source_branch+'-'+suffix in packages for suffix in ('cli','common','fpm')),'single_php74_inventory_required')
    need(not any(n.startswith(('apache2','libapache2-mod-php','libphp')) or n in ('php-cgi','php'+d.source_branch+'-cgi','php'+d.source_branch+'-phpdbg') for n in packages),'apache_or_cgi_requires_manual_review')
    executables=facts.get('active_php_executables');need(isinstance(executables,list) and '/usr/sbin/php-fpm'+d.source_branch in executables and all(p in ('/usr/bin/php'+d.source_branch,'/usr/sbin/php-fpm'+d.source_branch) for p in executables),'ambiguous_php_runtime')
    services=facts.get('active_services',{});need(services.get('nginx',services.get('nginx.service'))=='active' and services.get('php'+d.source_branch+'-fpm',services.get('php'+d.source_branch+'-fpm.service'))=='active','old_web_services_not_active')
    need(not fs.exists('/etc/php/'+d.target_branch),'preexisting_target_configuration_requires_manual_review')
    keys=set(target_ini_keys or SHARED);d.target_ini_keys=keys
    templates=legacy_ini_templates or {}
    for sapi in ('fpm','cli'):
        old=_read(d,'/etc/php/'+d.source_branch+'/'+sapi+'/php.ini')
        template=templates.get(sapi)
        if template is None:
            path='/usr/lib/php/'+d.source_branch+'/php.ini-production'+('.cli' if sapi=='cli' and fs.exists('/usr/lib/php/'+d.source_branch+'/php.ini-production.cli') else '')
            template=_read(d,path).content
        current=ini_values(old.content);stock=ini_values(template);overrides={}
        for key,value in current.items():
            if stock.get(key)==value:continue
            _safe_forward(key,value)
            overrides[key]=value
        need(not (set(stock)-set(current)),'removed_php_ini_setting_requires_manual_review');d.ini_overrides[sapi]=overrides
        extras={};required=[]
        for logical in fs.matches_glob('/etc/php/'+d.source_branch+'/'+sapi+'/conf.d/*.ini'):
            p=fs.physical(logical)
            if p.is_symlink():
                resolved=p.resolve();need(fs.root in resolved.parents,'extension_link_escapes_root');virtual='/'+resolved.relative_to(fs.root).as_posix()
                need(virtual.startswith('/etc/php/'+d.source_branch+'/mods-available/'),'custom_extension_link_requires_manual_review');snap=_read(d,virtual)
            else:snap=_read(d,logical)
            # PHP permits repeated extension= loaders in one file. Inspect all,
            # rather than treating only the last loader as module evidence.
            for loader in re.finditer(r'(?m)^\s*(?:zend_)?extension\s*=\s*([^\r\n]+)',snap.content.decode()):
                module=loader.group(1).strip().strip('"\'')
                need(re.fullmatch(r'[A-Za-z0-9_-]+(?:\.so)?',module) is not None,'legacy_extension_api_reference')
                required.append(module[:-3] if module.endswith('.so') else module)
            for key,value in ini_values(snap.content).items():
                if key in ('extension','zend_extension'):
                    need(re.fullmatch(r'[A-Za-z0-9_-]+(?:\.so)?',value.strip('"\'')) is not None,'legacy_extension_api_reference');required.append(value.strip("\"'")[:-3] if value.strip("\"'").endswith('.so') else value.strip("\"'"));continue
                _safe_forward(key,value);extras[key]=value
        d.extra_ini[sapi]=extras;d.required_modules[sapi]=sorted(set(required))
    global_file=_read(d,'/etc/php/'+d.source_branch+'/fpm/php-fpm.conf');global_text=global_file.content.decode();global_values={}
    for line in global_text.splitlines():
        line=line.strip()
        if not line or line[0] in ';#[':continue
        match=re.fullmatch(r'([A-Za-z0-9_.]+)\s*=\s*(.+)',line);need(match is not None,'unsupported_fpm_global_syntax');key,value=match.groups();need(key in GLOBAL_KEYS and key not in global_values,'unsupported_fpm_global_setting');global_values[key]=value
    need(global_values.get('include')=='/etc/php/'+d.source_branch+'/fpm/pool.d/*.conf','custom_fpm_include_requires_manual_review')
    if 'pid' in global_values:need(global_values['pid'] in ('/run/php/php'+d.source_branch+'-fpm.pid','/var/run/php/php'+d.source_branch+'-fpm.pid'),'custom_fpm_pid_requires_manual_review')
    d.global_values={k:v for k,v in global_values.items() if k not in ('pid','include','error_log')}
    if 'error_log' in global_values:d.global_values['error_log']=global_values['error_log'].replace('php'+d.source_branch+'-fpm','php'+d.target_branch+'-fpm')
    for path in fs.matches_glob('/etc/php/'+d.source_branch+'/fpm/pool.d/*.conf'):
        snap=_read(d,path);sections=_pool_parse(snap.content);text=snap.content.decode()
        for name,values in sections.items():
            need(name not in d.pools and all(k in values for k in ('user','group','listen','pm')),'invalid_or_duplicate_fpm_pool')
            for key,value in values.items():
                need(key not in ('env[PHPRC]','env[PHP_INI_SCAN_DIR]'),'custom_php_config_environment_requires_manual_review')
                php=re.fullmatch(r'php_(?:admin_)?(?:value|flag)\[([^\]]+)\]',key)
                need(key in POOL_KEYS or re.fullmatch(r'env\[[A-Za-z_][A-Za-z0-9_]*\]',key) or (php and php.group(1) not in FORBIDDEN_INI),'unsupported_fpm_pool_directive')
                if php:_safe_forward(php.group(1),value);d.pool_ini.setdefault(php.group(1),[]).append(value)
                need(not re.search(r'/usr/lib/php/[0-9]{8}|/etc/php/[0-9]+\.[0-9]+',value),'old_api_reference_in_pool')
                if key!='listen' and key not in ('access.log','slowlog','php_admin_value[error_log]','php_value[error_log]'):
                    need(not OLD_API.search(value),'old_php_executable_or_api_reference_in_pool')
            listen=values['listen'].strip('"\'').replace('$pool',name)
            need(re.fullmatch(r'/(?:var/)?run/php/[A-Za-z0-9_.-]*php'+re.escape(d.source_branch)+r'[A-Za-z0-9_.-]*\.sock',listen) is not None,'nonversioned_tcp_or_custom_pool_socket')
            target=listen.replace('php'+d.source_branch,'php'+d.target_branch);need(listen not in d.socket_map and target not in d.socket_map.values(),'duplicate_fpm_socket')
            d.socket_map[listen]=target;d.pools[name]=dict(source_path=snap.path,source_socket=listen,target_socket=target,user=values['user'],group=values['group'])
            alias=fs.physical('/var/run')
            if listen.startswith('/var/run/'):need(alias.is_symlink() and fs.physical('/run').is_dir(),'unsupported_var_run_socket_layout')
            if alias.is_symlink() and fs.physical('/run').is_dir():
                parent=alias.parent.lstat();link=alias.lstat()
                need(parent.st_uid==fs.owner_uid and not parent.st_mode&0o022 and link.st_uid==fs.owner_uid and alias.resolve()==fs.physical('/run').resolve(),'unsafe_run_socket_alias')
                alternate=('/var'+listen) if listen.startswith('/run/') else listen[4:]
                d.socket_map[alternate]=alternate.replace('php'+d.source_branch,'php'+d.target_branch)
        # Only the listen directive changes; pool environment and settings remain exact.
        text=re.sub(r'(?m)^(\s*listen\s*=\s*[^\r\n]*?)php'+re.escape(d.source_branch),lambda m:m.group(1)+'php'+d.target_branch,text)
        d.pool_contents[Path(path).name]=text.encode()
    need(bool(d.pools),'no_fpm_pools');_nginx(d)
    for root_path in d.document_roots:
        path=root_path.rstrip('/')+'/wp-includes/version.php'
        if fs.exists(path):
            p=fs.physical(path);need(p.is_file() and not p.is_symlink() and p.stat().st_size<=65536 and fs.physical(root_path).resolve() in p.resolve().parents,'unsafe_wordpress_version_file')
            before=p.lstat();descriptor=os.open(str(p),os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(descriptor,'rb') as stream:opened=os.fstat(stream.fileno());data=stream.read(65537)
            need(stat.S_ISREG(opened.st_mode) and (before.st_dev,before.st_ino)==(opened.st_dev,opened.st_ino) and len(data)<=65536,'wordpress_version_file_changed')
            match=re.search(rb"\$wp_version\s*=\s*['\"]([0-9A-Za-z.+-]+)['\"]\s*;",data)
            d.wordpress.append(dict(root=root_path,version=match.group(1).decode() if match else None,version_file_sha256=digest(data)))
    d.source_ini_graph=_source_ini_graph(d)
    return d

def audit_existing_target_nginx(root,branch):
    """Read-only route/config audit; runtime/module proof belongs to the caller.

    This never reads legacy ini values or produces configuration edits. Every
    active FastCGI route must resolve to this existing branch's safe pool map.
    """
    branch=_target(branch);fs=root if isinstance(root,FileSystem) else FileSystem(root)
    d=Discovery(fs.root,fs,source_branch=branch,target_branch=branch,audit_only=True)
    config=_read(d,'/etc/php/'+branch+'/fpm/php-fpm.conf')
    values=ini_values(config.content)
    need(values.get('include')=='/etc/php/'+branch+'/fpm/pool.d/*.conf','custom_existing_fpm_include_requires_manual_review')
    for path in fs.matches_glob('/etc/php/'+branch+'/fpm/pool.d/*.conf'):
        snap=_read(d,path)
        for name,pool in _pool_parse(snap.content).items():
            need(name not in d.pools and all(k in pool for k in ('user','group','listen','pm')),'invalid_or_duplicate_fpm_pool')
            for key,value in pool.items():
                need(key not in ('env[PHPRC]','env[PHP_INI_SCAN_DIR]'),'custom_php_config_environment_requires_manual_review')
                php=re.fullmatch(r'php_(?:admin_)?(?:value|flag)\[([^\]]+)\]',key)
                need(key in POOL_KEYS or re.fullmatch(r'env\[[A-Za-z_][A-Za-z0-9_]*\]',key) or php,'unsupported_fpm_pool_directive')
                if php:_safe_forward(php.group(1),value)
            need(not any(OLD_API.search(value) for value in pool.values()),'legacy_php_reference_in_active_pool')
            socket=pool['listen'].strip('"\'').replace('$pool',name)
            need(re.fullmatch(r'/(?:var/)?run/php/[A-Za-z0-9_.-]*php'+re.escape(branch)+r'[A-Za-z0-9_.-]*\.sock',socket) is not None,'nonversioned_tcp_or_custom_pool_socket')
            need(socket not in d.socket_map,'duplicate_fpm_socket');d.socket_map[socket]=socket
            d.pools[name]=dict(source_path=snap.path,source_socket=socket,target_socket=socket,user=pool['user'],group=pool['group'])
            alias=fs.physical('/var/run')
            if alias.is_symlink():
                need(alias.lstat().st_uid==fs.owner_uid and not alias.parent.lstat().st_mode&0o022 and alias.resolve()==fs.physical('/run').resolve(),'unsafe_run_socket_alias')
                alternate='/var'+socket if socket.startswith('/run/') else socket[4:];d.socket_map[alternate]=alternate
            elif socket.startswith('/var/run/'):need(False,'unsupported_var_run_socket_layout')
    need(bool(d.pools),'no_fpm_pools');_nginx(d)
    d.route_edits={}
    return d

@dataclass
class Edit:
    path:str;kind:str;content:bytes=field(repr=False);original:object=None;metadata:object=None
    def public(self):return dict(path=self.path,kind=self.kind,before_sha256=self.original.sha256 if self.original else None,after_sha256=digest(self.content),metadata=(self.metadata or self.original).public() if (self.metadata or self.original) else dict(uid=0,gid=0,mode=0o644))
@dataclass
class MigrationPlan:
    discovery:Discovery;edits:list;auxiliary:dict=field(default_factory=dict,repr=False);auxiliary_patterns:dict=field(default_factory=dict)
    def public_manifest(self):return dict(stage='ubuntu-legacy-php-to8-routing-v2',baseline=self.discovery.public_manifest(),edits=[e.public() for e in self.edits],target_auxiliary={k:v.public() for k,v in self.auxiliary.items()})
    @property
    def sha256(self):return digest(encoded(self.public_manifest()))
@dataclass
class Staged:
    job:Path;plan_sha256:str;nginx_conf:Path;fpm_conf:Path;manifest:dict;tree_sha256:dict=field(default_factory=dict)
    @property
    def target_branch(self):return self.manifest['baseline']['target_branch']
    @property
    def php_root(self):return self.job/'tree/etc/php'/self.target_branch

def _replace(data,changes):
    text=data.decode()
    for (start,end),value in sorted(changes.items(),reverse=True):text=text[:start]+value+text[end:]
    return text.encode()
def _port_ini(data,values):
    # Runtime registry validation, rather than a static shipped template, is
    # authoritative for registered extension/core keys omitted by the template.
    lines=data.decode().splitlines(True);remaining=dict(values)
    for i,line in enumerate(lines):
        match=re.match(r'^\s*([A-Za-z_][A-Za-z0-9_.]*)\s*=',line)
        if match and match.group(1) in remaining:lines[i]=match.group(1)+' = '+remaining.pop(match.group(1))+'\n'
    return ''.join(lines).encode()+b'\n; v2: compatible settings modified from the shipped source PHP template\n'+''.join(k+' = '+v+'\n' for k,v in sorted(remaining.items())).encode()

def build_plan(discovery,target_root=None):
    d=discovery;need(not d.audit_only,'audit_only_discovery_cannot_migrate');_require_registry(d);fs=d.fs if target_root is None else FileSystem(target_root,d.fs.owner_uid);edits=[];auxiliary={};auxiliary_patterns={}
    _source_ini_graph(d,True)
    for snap in d.snapshots.values():need(d.fs.matches(snap),'configuration_baseline_drift')
    for logical,canonical in d.nginx_files.items():need(d.fs.resolve(logical,True)[0]==canonical,'nginx_alias_target_changed')
    if any(p.startswith('/var/run/') for p in d.socket_map):need(d.fs.physical('/var/run').is_symlink() and d.fs.physical('/var/run').resolve()==d.fs.physical('/run').resolve(),'run_socket_alias_changed')
    for sapi in ('fpm','cli'):
        path='/etc/php/'+d.target_branch+'/'+sapi+'/php.ini';snap=fs.capture(path);edits.append(Edit(path,'fpm',_port_ini(snap.content,d.ini_overrides[sapi]),snap))
        extra_path='/etc/php/'+d.target_branch+'/'+sapi+'/conf.d/zzzz-v2-preserved-settings.ini';need(not fs.exists(extra_path),'target_custom_ini_collision')
        if d.extra_ini[sapi]:edits.append(Edit(extra_path,'fpm',('; v2 compatible explicit module settings\n'+''.join(k+' = '+v+'\n' for k,v in sorted(d.extra_ini[sapi].items()))).encode()))
        pattern='/etc/php/'+d.target_branch+'/'+sapi+'/conf.d/*.ini';auxiliary_patterns[pattern]=fs.matches_glob(pattern)
        need(all(Path(p).name.isascii() and Path(p).name<Path(extra_path).name for p in auxiliary_patterns[pattern]),'later_target_ini_would_override_migrated_settings')
        for path in auxiliary_patterns[pattern]:
            physical=fs.physical(path)
            if physical.is_symlink():
                resolved=physical.resolve();need(fs.root in resolved.parents,'target_extension_link_escapes_root');target='/'+resolved.relative_to(fs.root).as_posix()
                need(target.startswith('/etc/php/'+d.target_branch+'/mods-available/'),'unexpected_target_extension_link');auxiliary[path]=fs.capture(target)
            else:auxiliary[path]=fs.capture(path)
    global_path='/etc/php/'+d.target_branch+'/fpm/php-fpm.conf';global_snap=fs.capture(global_path)
    text=global_snap.content.decode();need(re.search(r'(?m)^\s*include\s*=\s*/etc/php/'+re.escape(d.target_branch)+r'/fpm/pool\.d/\*\.conf\s*$',text) is not None,'unexpected_target_fpm_include')
    for key,value in d.global_values.items():
        pattern=r'(?m)^\s*'+re.escape(key)+r'\s*=.*$'
        text=re.sub(pattern,key+' = '+value,text) if re.search(pattern,text) else text+'\n'+key+' = '+value+'\n'
    edits.append(Edit(global_path,'fpm',text.encode(),global_snap))
    target_pools=fs.matches_glob('/etc/php/'+d.target_branch+'/fpm/pool.d/*.conf');auxiliary_patterns['/etc/php/'+d.target_branch+'/fpm/pool.d/*.conf']=target_pools
    need(all(p.endswith('/www.conf') for p in target_pools),'unexpected_existing_target_pool')
    for name,data in d.pool_contents.items():
        path='/etc/php/'+d.target_branch+'/fpm/pool.d/'+name;existing=fs.capture(path) if fs.exists(path) else None
        metadata=next(s for s in d.snapshots.values() if s.path=='/etc/php/'+d.source_branch+'/fpm/pool.d/'+name)
        edits.append(Edit(path,'fpm',data,existing,metadata))
    if target_pools and 'www.conf' not in d.pool_contents:edits.append(Edit(target_pools[0],'fpm',b'; v2: unused freshly installed vendor pool disabled; migrated pools retain original identities\n',fs.capture(target_pools[0])))
    for path,changes in d.route_edits.items():
        snap=d.snapshots[path];edits.append(Edit(path,'nginx',_replace(snap.content,changes),snap))
    return MigrationPlan(d,edits,auxiliary,auxiliary_patterns)

def _private_write(path,data,mode=0o600):
    path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);fd=os.open(str(path),os.O_CREAT|os.O_EXCL|os.O_WRONLY|os.O_NOFOLLOW,mode)
    with os.fdopen(fd,'wb') as stream:os.fchmod(stream.fileno(),mode);stream.write(data);stream.flush();os.fsync(stream.fileno())
def _sync(path):
    fd=os.open(str(path),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)
def stage(plan,job):
    job=Path(job);need(job.is_absolute() and re.fullmatch(r'/[A-Za-z0-9_./-]+',str(job)) and not job.exists(),'new_private_staging_directory_required')
    parent=job.parent.lstat();need(stat.S_ISDIR(parent.st_mode) and parent.st_uid==plan.discovery.fs.owner_uid and not parent.st_mode&0o022 and job.parent.resolve()==job.parent,'unsafe_private_staging_parent')
    job.mkdir(mode=0o700);os.chmod(job,0o700)
    manifest=plan.public_manifest();_private_write(job/'plan.json',encoded(manifest))
    for path,snap in plan.discovery.snapshots.items():_private_write(job/'backup'/path.lstrip('/'),snap.content)
    for edit in plan.edits:
        if edit.original and edit.original.path not in plan.discovery.snapshots:_private_write(job/'backup'/edit.path.lstrip('/'),edit.original.content)
        _private_write(job/'payload'/edit.path.lstrip('/'),edit.content)
    d=plan.discovery;by_path={e.path:e.content for e in plan.edits};tree=job/'tree'
    for logical,canonical in d.nginx_files.items():
        changes=dict(d.route_edits.get(canonical,{}));changes.update({span:'"'+str(tree/pattern.lstrip('/')).replace('\\','\\\\').replace('"','\\"')+'"' for span,pattern in d.include_edits.get(canonical,{}).items()})
        _private_write(tree/logical.lstrip('/'),_replace(d.snapshots[canonical].content,changes))
    for edit in plan.edits:
        if edit.kind!='fpm':continue
        data=edit.content
        if edit.path.endswith('/fpm/php-fpm.conf'):data=data.replace(('/etc/php/'+d.target_branch+'/fpm/pool.d/').encode(),str(tree/('etc/php/'+d.target_branch+'/fpm/pool.d')).encode()+b'/')
        _private_write(tree/edit.path.lstrip('/'),data)
    for logical,snapshot in plan.auxiliary.items():_private_write(tree/logical.lstrip('/'),snapshot.content)
    tree_hashes={str(path.relative_to(job)):digest(path.read_bytes()) for path in tree.rglob('*') if path.is_file()}
    _private_write(job/'stage-manifest.json',encoded(dict(plan_sha256=plan.sha256,tree_sha256=tree_hashes)))
    for directory in sorted((p for p in job.rglob('*') if p.is_dir()),key=lambda p:len(p.parts),reverse=True):_sync(directory)
    _sync(job);_sync(job.parent)
    return Staged(job,plan.sha256,tree/'etc/nginx/nginx.conf',tree/('etc/php/'+d.target_branch+'/fpm/php-fpm.conf'),manifest,tree_hashes)
def test_commands(staged):return dict(fpm=['/usr/bin/env','PHP_INI_SCAN_DIR='+str(staged.php_root/'fpm/conf.d'),'/usr/sbin/php-fpm'+staged.target_branch,'-t','-y',str(staged.fpm_conf),'-c',str(staged.php_root/'fpm/php.ini')],nginx=['/usr/sbin/nginx','-t','-c',str(staged.nginx_conf)])

def apply(plan,staged,test_exit_codes,kind='all'):
    need(kind in ('fpm','nginx','all') and test_exit_codes=={'fpm':0,'nginx':0},'both_staged_native_config_tests_required')
    need(staged.plan_sha256==plan.sha256 and (staged.job/'plan.json').read_bytes()==encoded(plan.public_manifest()),'staged_plan_changed')
    need((staged.job/'stage-manifest.json').read_bytes()==encoded(dict(plan_sha256=plan.sha256,tree_sha256=staged.tree_sha256)),'staged_tree_manifest_changed')
    current_tree={str(p.relative_to(staged.job)):digest(p.read_bytes()) for p in (staged.job/'tree').rglob('*') if p.is_file()}
    need(current_tree==staged.tree_sha256,'staged_config_test_tree_changed')
    d=plan.discovery;fs=d.fs
    _source_ini_graph(d,True)
    for logical,canonical in d.nginx_files.items():need(fs.resolve(logical,True)[0]==canonical,'nginx_alias_target_changed')
    if any(p.startswith('/var/run/') for p in d.socket_map):need(fs.physical('/var/run').is_symlink() and fs.physical('/var/run').resolve()==fs.physical('/run').resolve(),'run_socket_alias_changed')
    for pattern,expected in d.include_patterns.items():need(fs.matches_glob(pattern)==expected,'nginx_include_graph_changed')
    for pattern,expected in plan.auxiliary_patterns.items():
        current=fs.matches_glob(pattern);glob_path=PurePosixPath(pattern)
        new=[e.path for e in plan.edits if PurePosixPath(e.path).parent==glob_path.parent and fnmatch.fnmatchcase(PurePosixPath(e.path).name,glob_path.name) and e.path not in expected and fs.exists(e.path)]
        need(sorted(current)==sorted(expected+new),'target_extension_configuration_graph_changed')
    for snapshot in plan.auxiliary.values():need(fs.matches(snapshot),'target_extension_configuration_changed')
    applied_file=staged.job/'applied.json';applied=json.loads(applied_file.read_text()) if applied_file.exists() else []
    chosen=[e for e in plan.edits if kind=='all' or e.kind==kind]
    need(all(e.path not in applied for e in chosen),'configuration_phase_already_applied')
    for edit in plan.edits:
        if edit.path in applied:
            actual=fs.capture(edit.path);metadata=edit.metadata or edit.original
            need(actual.sha256==digest(edit.content) and (metadata is None or (actual.uid,actual.gid,actual.mode)==(metadata.uid,metadata.gid,metadata.mode)),'previously_applied_configuration_changed')
    for snap in d.snapshots.values():need(fs.matches(snap) or (snap.path in applied and fs.capture(snap.path).sha256==digest(next(e.content for e in plan.edits if e.path==snap.path))),'configuration_baseline_drift')
    for edit in chosen:
        path=fs.physical(edit.path);payload=staged.job/'payload'/edit.path.lstrip('/')
        need(payload.read_bytes()==edit.content,'staged_payload_changed')
        if edit.original:need(fs.matches(edit.original),'target_configuration_drift')
        else:need(not fs.exists(edit.path),'new_configuration_path_collision')
    for edit in chosen:
        path=fs.physical(edit.path);need(path.parent.is_dir() and not path.parent.is_symlink(),'unsafe_target_configuration_parent')
        metadata=edit.metadata or edit.original;mode=metadata.mode if metadata else 0o644;uid=metadata.uid if metadata else fs.owner_uid;gid=metadata.gid if metadata else os.getegid()
        temporary=path.with_name(path.name+'.v2-'+plan.sha256[:12]+'.tmp')
        _private_write(temporary,edit.content,mode);os.chown(temporary,uid,gid)
        if metadata:os.utime(temporary,ns=(metadata.mtime_ns,metadata.mtime_ns))
        descriptor=os.open(str(temporary),os.O_RDONLY|os.O_NOFOLLOW)
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        if edit.original:need(fs.matches(edit.original),'target_configuration_race')
        else:need(not path.exists() and not path.is_symlink(),'target_configuration_race')
        os.replace(temporary,path);_sync(path.parent);applied.append(edit.path)
        temporary_receipt=staged.job/'applied.next.json';_private_write(temporary_receipt,encoded(applied));os.replace(temporary_receipt,applied_file);_sync(staged.job)
    return dict(plan_sha256=plan.sha256,applied_paths=[e.path for e in chosen],kind=kind,service_commands=0,APT_commands=0)
