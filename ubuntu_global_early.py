"""Python3.6-compatible read-only pre-Noble service/vhost health; no migration."""
import glob,hashlib,ipaddress,json,os,re,shutil,stat,subprocess
from pathlib import Path,PurePosixPath
from fpm_pool_parser import parse_pools
class EarlyError(Exception):pass
RoutingError=EarlyError
def need(value,code):
 if not value:raise EarlyError(code)
def digest(raw):return hashlib.sha256(raw).hexdigest()
class Snapshot:
 def __init__(self,path,sha256,uid,gid,mode,device,inode,mtime_ns,content):
  self.path=path;self.sha256=sha256;self.uid=uid;self.gid=gid;self.mode=mode;self.device=device;self.inode=inode;self.mtime_ns=mtime_ns;self.content=content
 def public(self):return {k:getattr(self,k) for k in ('path','sha256','uid','gid','mode','device','inode','mtime_ns')}
class Discovery:
 def __init__(self,root,fs):
  self.root=root;self.fs=fs;self.source_branch='existing';self.audit_only=False
  for key in ('snapshots','pools','nginx_files','socket_map','include_patterns','include_edits','route_edits'):setattr(self,key,{})
  for key in ('servers','server_names','listeners','document_roots'):setattr(self,key,[])
OLD_API=re.compile(r'/etc/php/7\.4|/usr/lib/php/20190902')
ENV=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/root',LANG='C',LC_ALL='C')
def run(args,timeout=20,allow=False):
 result=subprocess.run(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env=ENV,timeout=timeout)
 if not allow:need(result.returncode==0,'early_native_health_command_failed')
 return result.returncode,result.stdout
def ip_binary():
 value=shutil.which('ip',path=ENV['PATH']);need(value,'early_ip_command_missing');return value

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

def _read(d,path,link=False):
    snap=d.fs.capture(path,link);d.snapshots.setdefault(snap.path,snap);return snap

def _pool_parse(data):
    return parse_pools(data, EarlyError)

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
                    need(record is not None,'php_route_without_server_context');record['php74']=d.source_branch=='7.4';record['php']=True;record['php_branch']=d.source_branch
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

def local_addresses():
    values={'127.0.0.1'}
    _,raw=run([ip_binary(),'-j','address','show'])
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


def health_baseline(root='/',owner_uid=0):
 code,status=run(['/bin/systemctl','is-active','nginx'],allow=True)
 if code or status.decode().strip()!='active':return dict(scope='service-state-only',specs=[],results=[])
 fs=FileSystem(root,owner_uid);d=Discovery(fs.root,fs)
 for path in fs.physical('/etc/php').glob('*/fpm/pool.d/*.conf'):
  logical='/'+str(path.relative_to(fs.root));snap=fs.capture(logical)
  for pool in _pool_parse(snap.content).values():
   socket=pool.get('listen','').strip('"'+"'")
   if socket.startswith(('/run/','/var/run/')):
    d.socket_map[socket]=socket
    alternate='/var'+socket if socket.startswith('/run/') else socket[4:];d.socket_map[alternate]=alternate
 _nginx(d);specs=health_specs(d)
 return dict(scope='discovered-local-PHP-Nginx-vhosts',specs=specs,results=health(specs))
def check_health(before):
 if before['specs']:comparable_health(before['results'],health(before['specs']))
 return True
