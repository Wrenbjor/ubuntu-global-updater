"""Fake FastCGI responder + proc fixtures only; never invoke PHP/FPM/services."""
import ast,contextlib,os,re,socket,struct,tempfile,threading,time,unittest
from pathlib import Path
import php85_runtime as m

def exact(connection,count):
    raw=b''
    while len(raw)<count:
        block=connection.recv(count-len(raw))
        if not block:raise EOFError()
        raw+=block
    return raw
def decode_params(raw):
    result={};at=0
    def size():
        nonlocal at
        first=raw[at];at+=1
        if first&128:
            value=struct.unpack('!I',bytes([first])+raw[at:at+3])[0]&0x7fffffff;at+=3;return value
        return first
    while at<len(raw):
        left,right=size(),size();key=raw[at:at+left];at+=left;value=raw[at:at+right];at+=right
        result[key.decode()]=value.decode()
    return result
@contextlib.contextmanager
def server(root,mode='good'):
    path=str(root/'pool.sock');listener=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
    listener.bind(path);listener.listen(1);listener.settimeout(2);errors=[];observed=[]
    def serve():
        try:
            connection,unused=listener.accept()
            with connection:
                connection.settimeout(2);params=b''
                while True:
                    version,kind,request,size,padding,reserved=struct.unpack('!BBHHBB',exact(connection,8))
                    data=exact(connection,size)
                    if padding:exact(connection,padding)
                    if kind==4:params+=data
                    if kind==5:break
                values=decode_params(params);observed.append(values)
                probe=Path(values['SCRIPT_FILENAME']);code=probe.read_text()
                nonce=re.search(r"echo '([a-f0-9]+)\|'",code)[1]
                if mode=='changed-probe':probe.write_text('fixture replacement bytes')
                if mode=='wrong-nonce':nonce='0'*32
                version='8.5.11' if mode=='old' else '8.5.12'
                sapi='cli' if mode=='wrong-sapi' else 'fpm-fcgi'
                status=b'Status: 503 Unavailable\r\n' if mode=='non200' else b''
                stdout=status+b'Content-Type: text/plain\r\n\r\n'+(nonce+'|'+version+'|'+sapi).encode()
                if mode=='truncated':connection.sendall(m.record(6,stdout)[:10]);return
                connection.sendall(m.record(6,stdout[:5])+m.record(6,stdout[5:])+m.record(6)+
                                   m.record(3,struct.pack('!IB3x',0,0)))
        except (EOFError,ConnectionResetError,BrokenPipeError):pass
        except Exception as error:errors.append(error)
    thread=threading.Thread(target=serve,daemon=True);thread.start()
    try:yield path,observed
    finally:
        thread.join(3);listener.close()
        if Path(path).exists():Path(path).unlink()
        if errors:raise errors[0]

class FastCGIProofs(unittest.TestCase):
    def test_parent_embedded_runtime_source_exact_byte_identity(self):
        tree=ast.parse((Path(__file__).parent/'php85_upgrade.py').read_text())
        source=next(ast.literal_eval(node.value) for node in tree.body if isinstance(node,ast.Assign)
                    and isinstance(node.targets[0],ast.Name) and node.targets[0].id=='RUNTIME_SOURCE')
        self.assertEqual(source.encode(),Path(m.__file__).read_bytes())
    def invoke(self,root,path,checker=None):
        checker=checker or (lambda peer,master,api:dict(peer_pid=peer,master_pid=master,current=True))
        return m.prove_pool([path],os.getpid(),'/usr/lib/php/20250925',probe_dir=root,
                            process_checker=checker,owner_uid=os.geteuid())
    def test_real_unix_peercred_and_nonce_FastCGI_not_actual_PHP(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);calls=[]
            def checker(peer,master,api):
                self.assertEqual(peer,os.getpid());calls.append(peer);return {'current':True}
            with server(root) as (path,observed):result=self.invoke(root,path,checker)
            self.assertEqual(len(calls),2);self.assertEqual(result['pools'][0]['PHP_version'],'8.5.12')
            self.assertEqual(result['pools'][0]['PHP_SAPI'],'fpm-fcgi');self.assertFalse(result['customer_application_executed'])
            self.assertEqual(observed[0]['CONTENT_LENGTH'],'0');self.assertEqual(observed[0]['REQUEST_METHOD'],'GET')
            self.assertEqual(list(root.glob('*.php')),[])
    def test_wrong_nonce_old_version_sapi_status_and_truncation_hold_cleanup(self):
        for mode in ('wrong-nonce','old','wrong-sapi','non200','truncated'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                with server(root,mode) as (path,unused),self.assertRaises(m.ProofError):self.invoke(root,path)
                self.assertEqual(list(root.glob('*.php')),[])
    def test_peer_not_expected_service_holds_before_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            def reject(*unused):raise m.ProofError('wrong service')
            with server(root) as (path,unused),self.assertRaisesRegex(m.ProofError,'wrong service'):
                self.invoke(root,path,reject)
            self.assertEqual(list(root.glob('*.php')),[])
    def test_cleanup_never_deletes_changed_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            with server(root,'changed-probe') as (path,unused),self.assertRaisesRegex(m.ProofError,'cleanup_ownership_or_content'):
                self.invoke(root,path)
            files=list(root.glob('*.php'));self.assertEqual(len(files),1)
            self.assertEqual(files[0].read_text(),'fixture replacement bytes')
    def test_parameter_four_byte_lengths(self):
        values={'SCRIPT_FILENAME':'/run/'+'a'*200+'.php','CONTENT_LENGTH':'0'}
        self.assertEqual(decode_params(m.parameters(values)),values)
    def test_response_limit_and_wrong_request_id(self):
        class BytesSocket:
            def __init__(self,data):self.data=data
            def settimeout(self,value):self.timeout=value
            def recv(self,count):value=self.data[:count];self.data=self.data[count:];return value
        huge=m.record(6,b'a'*65535)*17
        with self.assertRaisesRegex(m.ProofError,'response_bound'):m.response(BytesSocket(huge),time.monotonic()+5)
        bad=struct.pack('!BBHHBB',1,6,2,0,0,0)
        with self.assertRaisesRegex(m.ProofError,'header'):m.response(BytesSocket(bad),time.monotonic()+5)
    def test_expired_deadline_no_blocking_receive(self):
        class Forbidden:
            def recv(self,count):self.fail('must not read')
        with self.assertRaisesRegex(m.ProofError,'deadline'):m.receive(Forbidden(),1,time.monotonic()-1)

class ProcessProofs(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.root=Path(self.temporary.name)
        self.proc=self.root/'proc';self.proc.mkdir();self.binary=self.root/'php-fpm8.5';self.binary.write_bytes(b'fixture executable metadata only')
        self.module=self.root/'pdo.so';self.module.write_bytes(b'fixture mapping metadata only');self.info=self.module.stat()
        self.api='/usr/lib/php/20250925';self.row(777,1);self.row(778,777)
    def tearDown(self):self.temporary.cleanup()
    def row(self,pid,parent,api=None,deleted=False):
        path=self.proc/str(pid);path.mkdir(exist_ok=True)
        (path/'stat').write_text(str(pid)+' (php-fpm8.5) S '+str(parent)+' '+'0 '*17+'100 0')
        target=path/'exe'
        if target.is_symlink():target.unlink()
        target.symlink_to(self.binary)
        module=(api or self.api)+'/pdo.so'+(' (deleted)' if deleted else '')
        (path/'maps').write_text('7f00-7f01 r-xp 00000000 '+format(os.major(self.info.st_dev),'x')+':'+format(os.minor(self.info.st_dev),'x')+' '+str(self.info.st_ino)+' '+module+'\n')
    def prove(self,peer=778):
        return m.service_process_proof(peer,777,self.api,self.proc,str(self.binary),os.geteuid(),
                                       file_stat=lambda path:self.module.stat())
    def test_master_worker_current_inode_API_lineage(self):
        result=self.prove();self.assertEqual(result['processes'],2);self.assertEqual(result['extension_map_observations'],2)
    def test_old_API_deleted_module_and_peer_outside_service_rejected(self):
        with self.assertRaisesRegex(m.ProofError,'not_target_service'):self.prove(999)
        self.row(778,777,api='/usr/lib/php/20220829')
        with self.assertRaisesRegex(m.ProofError,'old_or_custom'):self.prove()
        self.row(778,777,deleted=True)
        with self.assertRaisesRegex(m.ProofError,'deleted_PHP'):self.prove()
    def test_deleted_or_custom_executable_and_stale_extension_inode_rejected(self):
        exe=self.proc/'778/exe';exe.unlink();exe.symlink_to(str(self.binary)+' (deleted)')
        with self.assertRaisesRegex(m.ProofError,'noncanonical_or_deleted'):self.prove()
        self.row(778,777)
        maps=self.proc/'778/maps';maps.write_text(maps.read_text().replace(' '+str(self.info.st_ino)+' ',' '+str(self.info.st_ino+1)+' '))
        with self.assertRaisesRegex(m.ProofError,'stale_PHP_extension_inode'):self.prove()
    def test_current_inode_unsafe_module_permissions_hold(self):
        self.module.chmod(0o666)
        with self.assertRaisesRegex(m.ProofError,'unsafe_PHP_extension_file'):self.prove()

if __name__=='__main__':unittest.main()
