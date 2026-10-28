"""Align only an existing, independently trusted Ondrej PHP source to this OS.

No key download, new repository, package installation or broad source rewrite.
Plans preserve unrelated stanza bytes and are revalidated before atomic apply.
Python3.6 compatible. Callers hold their installer/package-operation locks.
"""
import hashlib,os,re,stat,subprocess,tempfile
from pathlib import Path
from urllib.parse import urlsplit

FINGERPRINT='B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6'
SUITES={'18.04':'bionic','20.04':'focal','22.04':'jammy','24.04':'noble'}
class RepositoryError(Exception):pass
def need(value,code):
    if not value:raise RepositoryError(code)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def at(root,name):return Path(root)/name.lstrip('/')
def safe(path,root,uid):
    root=Path(root).absolute();path=Path(path).absolute()
    need(root==path or root in path.parents,'repository_path_outside_root')
    for parent in reversed(path.parents):
        if parent==root or root in parent.parents:
            info=parent.lstat()
            need(stat.S_ISDIR(info.st_mode) and info.st_uid==uid and not info.st_mode&0o022,'unsafe_repository_parent')
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid==uid and not info.st_mode&0o022 and info.st_nlink==1 and info.st_size<=1048576,'unsafe_repository_file')
        raw=stream.read(1048577)
    need(len(raw)<=1048576,'repository_file_too_large')
    return raw,dict(uid=info.st_uid,gid=info.st_gid,mode=stat.S_IMODE(info.st_mode))
def is_php(uri):
    parsed=urlsplit(uri)
    return (parsed.scheme in ('http','https') and parsed.hostname in ('ppa.launchpad.net','ppa.launchpadcontent.net')
      and parsed.path.rstrip('/')=='/ondrej/php/ubuntu' and not parsed.username and not parsed.password
      and not parsed.query and not parsed.fragment and parsed.port is None)
def fields(block):
    result={};key=None
    for line in block.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):continue
        if line.startswith((' ','\t')):
            need(key is not None,'malformed_repository_stanza')
            result[key]+='\n'+line[1:];continue
        match=re.fullmatch(r'([A-Za-z][A-Za-z-]*):\s*(.*)',line)
        need(match is not None,'malformed_repository_stanza')
        key=match.group(1).lower();need(key not in result,'duplicate_repository_field')
        result[key]=match.group(2)
    return result
def fingerprints(raw):
    with tempfile.TemporaryDirectory(prefix='php-key-inspect-') as home:
        path=Path(home)/'key';path.write_bytes(raw)
        result=subprocess.run(['/usr/bin/gpg','--homedir',home,'--batch','--show-keys','--with-colons',str(path)],
          stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=15,
          env=dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C'))
    need(result.returncode==0,'PHP_signing_key_cannot_be_inspected')
    found=[];primary=False
    for line in result.stdout.decode().splitlines():
        parts=line.split(':')
        if parts[0]=='pub':primary=True
        elif parts[0]=='sub':primary=False
        elif parts[0]=='fpr' and primary:found.append(parts[9]);primary=False
    return found
def trust(value,root,uid,reader):
    value=value.strip()
    if value.startswith('-----BEGIN PGP PUBLIC KEY BLOCK-----'):
        raw=value.replace('\n.\n','\n\n').encode()+b'\n';paths=[]
    else:
        need(bool(re.fullmatch(r'/(?:etc/apt|usr/share/keyrings)/[A-Za-z0-9_./-]+\.(?:gpg|asc)',value)) and '..' not in value.split('/'),'explicit_existing_PHP_signing_key_required')
        raw,meta=safe(at(root,value),root,uid);paths=[dict(path=value,sha256=sha(raw),metadata=meta)]
    need(reader(raw)==[FINGERPRINT],'unexpected_PHP_repository_primary_signing_key')
    return dict(fingerprint=FINGERPRINT,sha256=sha(raw),files=paths)
def plan(release,root='/',owner_uid=0,key_reader=fingerprints):
    need(release in SUITES,'unsupported_repository_OS_release');suite=SUITES[release]
    names=[]
    main=at(root,'/etc/apt/sources.list')
    if main.exists() or main.is_symlink():names.append(main)
    directory=at(root,'/etc/apt/sources.list.d')
    if directory.exists():names+=sorted(p for p in directory.iterdir() if p.suffix in ('.list','.sources'))
    matches=[]
    for path in names:
        raw,meta=safe(path,root,owner_uid);content=raw.decode('utf-8')
        if path.suffix=='.sources':
            pieces=re.split(r'(\n[ \t]*\n)',content)
            for i in range(0,len(pieces),2):
                block=pieces[i];f=fields(block)
                uris=f.get('uris','').split()
                if not any(is_php(uri) for uri in uris):continue
                need(len(uris)==1 and f.get('types')=='deb' and f.get('components')=='main','ambiguous_PHP_repository_stanza')
                need(f.get('suites') in SUITES.values() and f.get('enabled','yes').lower() in ('yes','no'),'unsupported_PHP_repository_suite_or_enabled_field')
                need(set(f)<=set(('types','uris','suites','components','signed-by','architectures','enabled')),'unsafe_or_unsupported_PHP_repository_options')
                proof=trust(f.get('signed-by',''),root,owner_uid,key_reader)
                updated=re.sub(r'(?im)^Suites:[^\n]*','Suites: '+suite,block)
                updated=re.sub(r'(?im)^Enabled:[^\n]*','Enabled: yes',updated)
                pieces2=list(pieces);pieces2[i]=updated
                matches.append(dict(path='/' + str(path.relative_to(Path(root))).replace(os.sep,'/'),
                    before_sha256=sha(raw),after_sha256=sha(''.join(pieces2).encode()),content=''.join(pieces2),metadata=meta,
                    suite=suite,previous_suite=f['suites'],previous_enabled=f.get('enabled','yes').lower(),trust=proof))
        else:
            lines=content.splitlines(True)
            for i,line in enumerate(lines):
                # Legacy disabled sources are accepted only when the entire
                # commented line is precisely a repository declaration.
                match=re.fullmatch(r'([ \t]*)(?:#[ \t]*)?(deb)([ \t]+)(?:\[([^\]\n]+)\][ \t]+)?(\S+)([ \t]+)(\S+)([ \t]+)main([ \t]*)(?:\n)?',line)
                if not match or not is_php(match.group(5)):continue
                options=match.group(4) or ''
                opts=options.split();signed=[x.split('=',1)[1] for x in opts if x.startswith('signed-by=')]
                need(len(signed)==1 and all(x.startswith(('signed-by=','arch=')) for x in opts),'explicit_safe_legacy_PHP_signing_key_required')
                need(match.group(7) in SUITES.values(),'unsupported_PHP_repository_suite')
                proof=trust(signed[0],root,owner_uid,key_reader)
                changed=match.group(1)+'deb ['+options+'] '+match.group(5)+' '+suite+' main'+match.group(9)+ ('\n' if line.endswith('\n') else '')
                updated=list(lines);updated[i]=changed
                matches.append(dict(path='/'+str(path.relative_to(Path(root))).replace(os.sep,'/'),before_sha256=sha(raw),after_sha256=sha(''.join(updated).encode()),content=''.join(updated),metadata=meta,
                  suite=suite,previous_suite=match.group(7),previous_enabled='no' if line.lstrip().startswith('#') else 'yes',trust=proof))
    need(len(matches)<=1,'multiple_PHP_repository_declarations_require_review')
    return dict(schema=1,release=release,status='existing-PHP-source' if matches else 'no-existing-PHP-source',
      change=matches[0] if matches and matches[0]['before_sha256']!=matches[0]['after_sha256'] else None,
      source=matches[0] if matches else None,new_trust=False)
def apply(reviewed,archive,root='/',owner_uid=0,key_reader=fingerprints):
    current=plan(reviewed['release'],root,owner_uid,key_reader)
    need(current==reviewed,'PHP_repository_plan_drift')
    item=reviewed['change']
    if item is None:return dict(status='aligned',changed=False)
    archive=Path(archive);need(archive.is_dir() and archive.resolve()==archive,'PHP_repository_archive_required')
    info=archive.lstat();need(info.st_uid==owner_uid and stat.S_IMODE(info.st_mode)==0o700,'unsafe_PHP_repository_archive')
    raw,meta=safe(at(root,item['path']),root,owner_uid)
    need(not hasattr(os,'listxattr') or not os.listxattr(str(at(root,item['path']))),'PHP_repository_xattrs_require_preservation_profile')
    backup=archive/'php-source-before';fd=os.open(str(backup),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    target=at(root,item['path']);fd,temp=tempfile.mkstemp(prefix='.php-source-',dir=str(target.parent))
    try:
        with os.fdopen(fd,'wb') as stream:
            stream.write(item['content'].encode());stream.flush();os.fchmod(stream.fileno(),meta['mode']);os.fchown(stream.fileno(),meta['uid'],meta['gid']);os.fsync(stream.fileno())
        need(plan(reviewed['release'],root,owner_uid,key_reader)==reviewed,'PHP_repository_changed_before_commit')
        os.replace(temp,str(target));fd=os.open(str(target.parent),os.O_RDONLY|os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(temp):os.unlink(temp)
    return dict(status='aligned-refresh-authenticated-metadata-required',changed=True,path=item['path'],before_sha256=item['before_sha256'],after_sha256=item['after_sha256'])
