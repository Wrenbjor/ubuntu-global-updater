"""Apply-only FPM FastCGI runtime proof; no app files, shell or service actions."""
import os,re,socket,stat,struct,time,uuid
from pathlib import Path

LIMIT=1048576
class ProofError(ValueError):pass
def need(value,code):
    if not value:raise ProofError(code)
def bounded(path,limit):
    with Path(path).open('rb') as stream:raw=stream.read(limit+1)
    need(len(raw)<=limit,'process_evidence_bound');return raw
def proc_stat(root,pid):
    raw=bounded(Path(root)/str(pid)/'stat',65536).decode()
    need(raw.startswith(str(pid)+' (') and ')' in raw,'invalid_process_stat')
    fields=raw.rsplit(')',1)[1].split();need(len(fields)>19,'short_process_stat')
    return (int(fields[1]),int(fields[19]),fields[0])
def service_process_proof(peer_pid,master_pid,extension_dir,proc_root='/proc',expected_executable='/usr/sbin/php-fpm8.5',owner_uid=0,file_stat=None):
    """Require exact executable inode and current target-API extension maps."""
    need(type(master_pid) is int and master_pid>1 and type(peer_pid) is int and peer_pid>1,'invalid_service_PID')
    extension_dir=str(extension_dir);need(re.fullmatch(r'/usr/lib/php/[0-9]{8}',extension_dir),'nonstandard_target_API_directory')
    expected=Path(expected_executable).stat()
    need(stat.S_ISREG(expected.st_mode) and expected.st_uid==owner_uid and not expected.st_mode&0o022,'unsafe_target_FPM_executable')
    root=Path(proc_root);paths=[p for p in root.iterdir() if p.name.isdecimal()]
    need(len(paths)<=65536,'process_inventory_bound');rows={}
    for path in paths:
        try:rows[int(path.name)]=proc_stat(root,int(path.name))
        except FileNotFoundError:continue
    need(master_pid in rows and rows[master_pid][2] not in ('Z','X'),'FPM_master_not_live')
    selected={master_pid}
    for unused in range(64):
        more={pid for pid,row in rows.items() if row[0] in selected}
        if more<=selected:break
        selected.update(more)
    else:raise ProofError('FPM_lineage_depth_bound')
    need(peer_pid in selected and len(selected)<=1024,'FastCGI_peer_not_target_service')
    module_count=0
    for pid in sorted(selected):
        before=rows[pid];need(before[2] not in ('Z','X'),'FPM_lifecycle_incomplete')
        process=root/str(pid);target=os.readlink(str(process/'exe'))
        need(target==str(expected_executable),'noncanonical_or_deleted_FPM_executable')
        actual=(process/'exe').stat()
        need((actual.st_dev,actual.st_ino)==(expected.st_dev,expected.st_ino),'stale_FPM_executable_inode')
        for line in bounded(process/'maps',8388608).decode().splitlines():
            fields=line.split(None,5)
            if len(fields)<6:continue
            path=fields[5]
            if not path.startswith('/usr/lib/php/'):continue
            need(not path.endswith(' (deleted)'),'deleted_PHP_extension_map')
            need(str(Path(path).parent)==extension_dir and path.endswith('.so'),'old_or_custom_PHP_API_map')
            loaded=(file_stat or os.stat)(path);device=fields[3].split(':')
            need(stat.S_ISREG(loaded.st_mode) and loaded.st_uid==owner_uid and not loaded.st_mode&0o022,
                 'unsafe_PHP_extension_file')
            need(len(device)==2 and int(fields[4])==loaded.st_ino and
                 (int(device[0],16),int(device[1],16))==(os.major(loaded.st_dev),os.minor(loaded.st_dev)),
                 'stale_PHP_extension_inode')
            module_count+=1
        need(proc_stat(root,pid)==before,'FPM_process_changed_during_proof')
    need(proc_stat(root,master_pid)==rows[master_pid],'FPM_master_changed_during_proof')
    return dict(peer_pid=peer_pid,master_pid=master_pid,processes=len(selected),
                extension_map_observations=module_count,target_API_directory=extension_dir,
                current_executables_and_PHP_maps=True)

def length(value):
    need(0<=value<2**31,'FastCGI_parameter_length_bound')
    return bytes([value]) if value<128 else struct.pack('!I',value|0x80000000)
def parameters(values):
    raw=b''
    for key,value in values.items():
        key,value=key.encode('ascii'),str(value).encode('utf-8')
        raw+=length(len(key))+length(len(value))+key+value
    need(len(raw)<=65535,'FastCGI_parameters_bound');return raw
def record(kind,content=b''):
    need(len(content)<=65535,'FastCGI_record_bound')
    return struct.pack('!BBHHBB',1,kind,1,len(content),0,0)+content
def receive(connection,count,deadline):
    raw=b''
    while len(raw)<count:
        remaining=deadline-time.monotonic();need(remaining>0,'FastCGI_deadline')
        connection.settimeout(remaining)
        block=connection.recv(count-len(raw));need(bool(block),'FastCGI_truncated_response');raw+=block
    return raw
def response(connection,deadline):
    stdout=b'';used=0;stdout_closed=False
    while True:
        header=receive(connection,8,deadline);used+=8
        version,kind,request,size,padding,reserved=struct.unpack('!BBHHBB',header)
        need(version==1 and request==1 and reserved==0,'invalid_FastCGI_response_header')
        used+=size+padding;need(used<=LIMIT,'FastCGI_response_bound')
        content=receive(connection,size,deadline)
        if padding:receive(connection,padding,deadline)
        if kind==6:
            need(not stdout_closed or not content,'FastCGI_stdout_after_close')
            if content:stdout+=content
            else:stdout_closed=True
        elif kind==7:need(not content,'FastCGI_stderr_observed')
        elif kind==3:
            need(len(content)==8 and stdout_closed,'invalid_FastCGI_END_REQUEST')
            app,protocol=struct.unpack('!IB3x',content)
            need(app==0 and protocol==0,'FastCGI_request_failed');return stdout
        else:raise ProofError('unexpected_FastCGI_record')
def parsed_stdout(raw,nonce):
    need(b'\r\n\r\n' in raw,'FastCGI_CGI_headers_missing')
    headers,body=raw.split(b'\r\n\r\n',1);statuses=[]
    for line in headers.split(b'\r\n'):
        need(b':' in line,'invalid_CGI_header')
        key,value=line.split(b':',1)
        if key.lower()==b'status':statuses.append(value.strip().split(b' ',1)[0])
    need(statuses in ([],[b'200']),'FastCGI_non200_status')
    match=re.fullmatch(re.escape(nonce.encode())+rb'\|(8\.5\.([0-9]+))\|fpm-fcgi',body)
    need(match is not None and int(match[2])>=12,'wrong_nonce_PHP_version_or_SAPI')
    return match[1].decode('ascii')
def cleanup_probe(path,identity,content,owner_uid):
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:info=os.fstat(stream.fileno());raw=stream.read(len(content)+1)
    named=path.lstat()
    need((info.st_dev,info.st_ino)==identity==(named.st_dev,named.st_ino) and
         stat.S_ISREG(info.st_mode) and stat.S_ISREG(named.st_mode) and info.st_nlink==named.st_nlink==1
         and info.st_uid==named.st_uid==owner_uid and stat.S_IMODE(info.st_mode)==stat.S_IMODE(named.st_mode)==0o644
         and raw==content,'probe_cleanup_ownership_or_content_changed')
    path.unlink()
def prove_pool(sockets,master_pid,extension_dir,probe_dir='/run',proc_root='/proc',
               expected_executable='/usr/sbin/php-fpm8.5',process_checker=None,owner_uid=0):
    """Probe each socket once. Injectable checker/directory are fixture-only APIs.

    Default checker inspects current target service master/descendants before and
    after each response. No app/customer path is read or requested. Errors hold;
    callers may perform a separately bounded read-only recheck, never retry APT.
    """
    need(os.geteuid()==owner_uid,'root_required_for_runtime_probe')
    sockets=list(sockets);need(sockets and len(sockets)<=32 and len(set(sockets))==len(sockets),'invalid_pool_socket_set')
    directory=Path(probe_dir);info=directory.lstat()
    need(stat.S_ISDIR(info.st_mode) and info.st_uid==owner_uid and not info.st_mode&0o022
         and directory.resolve()==directory,'unsafe_probe_directory')
    nonce=uuid.uuid4().hex;path=directory/('ubuntu-php85-probe-'+uuid.uuid4().hex+'.php')
    content=("<?php header('Content-Type: text/plain'); echo '"+nonce+"|', PHP_VERSION, '|', PHP_SAPI;").encode('ascii')
    fd=os.open(str(path),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
    with os.fdopen(fd,'wb') as stream:
        os.fchmod(stream.fileno(),0o644);stream.write(content);stream.flush();os.fsync(stream.fileno())
        own=os.fstat(stream.fileno());identity=(own.st_dev,own.st_ino)
    checker=process_checker or (lambda peer,master,api:service_process_proof(peer,master,api,proc_root,expected_executable,owner_uid))
    proofs=[]
    try:
        for name in sockets:
            need(isinstance(name,str) and name.startswith('/') and '\0' not in name,'absolute_pool_socket_required')
            socket_info=Path(name).lstat();need(stat.S_ISSOCK(socket_info.st_mode),'pool_socket_not_native_socket')
            deadline=time.monotonic()+5
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.settimeout(max(0.001,deadline-time.monotonic()));connection.connect(name)
                peer,uid,gid=struct.unpack('3i',connection.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,struct.calcsize('3i')))
                checker(peer,master_pid,extension_dir)
                params=parameters(dict(GATEWAY_INTERFACE='CGI/1.1',SERVER_PROTOCOL='HTTP/1.1',REQUEST_METHOD='GET',
                    SCRIPT_FILENAME=str(path),SCRIPT_NAME='/ubuntu-php85-runtime-probe.php',REQUEST_URI='/ubuntu-php85-runtime-probe.php',
                    QUERY_STRING='',CONTENT_LENGTH='0',SERVER_NAME='localhost',SERVER_ADDR='127.0.0.1',SERVER_PORT='80',
                    REMOTE_ADDR='127.0.0.1',REMOTE_PORT='0',REDIRECT_STATUS='200'))
                remaining=deadline-time.monotonic();need(remaining>0,'FastCGI_deadline');connection.settimeout(remaining)
                connection.sendall(record(1,struct.pack('!HB5x',1,0))+record(4,params)+record(4)+record(5))
                version=parsed_stdout(response(connection,deadline),nonce)
                process=checker(peer,master_pid,extension_dir)
                need(time.monotonic()<=deadline,'FastCGI_deadline')
                proofs.append(dict(socket=name,PHP_version=version,PHP_SAPI='fpm-fcgi',nonce_matched=True,
                                   peer_pid=peer,service_processes=process))
        return dict(status='target_FPM_runtime_proved',pools=proofs,temporary_probe_removed=True,
                    customer_application_executed=False,package_actions=0,service_actions=0)
    finally:cleanup_probe(path,identity,content,owner_uid)
