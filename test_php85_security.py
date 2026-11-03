"""Mock-only PHP85 security tests: no package/service/network commands."""
import importlib,importlib.util,os,stat,sys,tempfile,types,unittest,subprocess,time,contextlib,io
from pathlib import Path
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('php85_security_review',Path(__file__).parent/'php85_upgrade.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

def ppa_good_status(fingerprint=None,digest='10',timestamp='1793700000'):
 fingerprint=fingerprint or M.PPA_KEY
 return ('[GNUPG:] NEWSIG\n[GNUPG:] KEY_CONSIDERED '+fingerprint+' 0\n'
  '[GNUPG:] SIG_ID fixture 2026-11-03 '+timestamp+'\n'
  '[GNUPG:] GOODSIG '+fingerprint[-16:]+' Offline public signature fixture\n'
  '[GNUPG:] VALIDSIG '+fingerprint+' 2026-11-03 '+timestamp+' 0 4 0 1 '+digest+' 01 '+fingerprint+'\n')

def ppa_legacy_missing(fingerprint=None,timestamp='1793700000'):
 fingerprint=fingerprint or M.PPA_LEGACY_KEY
 return ('[GNUPG:] NEWSIG\n[GNUPG:] ERRSIG '+fingerprint[-16:]+' 1 10 01 '+timestamp+' 9 '+fingerprint+'\n'
         '[GNUPG:] NO_PUBKEY '+fingerprint[-16:]+'\n')

def ppa_dual_stderr(current=None,legacy=None):
 current=current or M.PPA_KEY;legacy=legacy or M.PPA_LEGACY_KEY
 return ('gpgv: Signature made Tue Nov  3 12:00:00 2026 UTC\n'
  'gpgv:                using RSA key '+current+'\n'
  'gpgv: Good signature from "Offline public signature fixture"\n'
  'gpgv: Signature made Tue Nov  3 12:00:00 2026 UTC\n'
  'gpgv:                using RSA key '+legacy+'\n'
  "gpgv: Can't check signature: No public key\n")


class PpaSignatureStatus(unittest.TestCase):
 def setUp(self):
  self.addCleanup(patch.stopall)
  patch.object(M,'command',side_effect=AssertionError('status parser must not execute commands')).start()
  patch.object(M.subprocess,'run',side_effect=AssertionError('status parser must not create subprocesses')).start()
 def accept(self,output,code=0,stderr='',missing=False):
  proof=M.ppa_signature_status(output,code,stderr)
  self.assertEqual(proof['primary_fingerprint'],M.PPA_KEY)
  self.assertEqual(proof['signing_fingerprint'],M.PPA_KEY)
  self.assertEqual(proof['missing_legacy_signature'],missing)
  self.assertEqual(proof['gpgv_exit_code'],code)
  return proof
 def reject(self,output,code=2,stderr=None):
  with self.assertRaises(M.Hold):
   M.ppa_signature_status(output,code,ppa_dual_stderr() if stderr is None else stderr)
 def test_normal_current_signature_and_optional_known_legacy_good_signature(self):
  self.accept(ppa_good_status())
  self.accept(ppa_good_status()+ppa_good_status(M.PPA_LEGACY_KEY))
  self.accept(ppa_good_status(M.PPA_LEGACY_KEY)+ppa_good_status())
 def test_exact_missing_legacy_signature_is_accepted_in_both_group_orders(self):
  for output in (ppa_good_status()+ppa_legacy_missing(),ppa_legacy_missing()+ppa_good_status()):
   with self.subTest(output=output[:45]):self.accept(output,2,ppa_dual_stderr(),True)
 def test_other_exit_codes_and_incomplete_dual_cases_are_rejected(self):
  good=ppa_good_status();dual=good+ppa_legacy_missing()
  for code,output in ((1,dual),(3,dual),(255,dual),(2,good),(2,ppa_legacy_missing()),(0,dual)):
   with self.subTest(code=code,output=output[:45]):self.reject(output,code)
 def test_missing_or_unknown_current_or_legacy_identity_is_rejected(self):
  for output,code in ((ppa_good_status(M.PPA_LEGACY_KEY),0),(ppa_good_status('A'*40),0),
                      (ppa_good_status()+ppa_legacy_missing('A'*40),2)):
   with self.subTest(code=code,output=output[-50:]):self.reject(output,code)
 def test_all_three_strong_digests_are_accepted_and_weak_digests_rejected(self):
  for digest in ('8','9','10'):
   with self.subTest(digest=digest):self.accept(ppa_good_status(digest=digest))
  for digest in ('1','2','3','11','bad'):
   with self.subTest(digest=digest):self.reject(ppa_good_status(digest=digest),0,'')
 def test_current_good_and_valid_signature_keyids_must_agree_with_primary_pin(self):
  good=ppa_good_status()
  cases=(good.replace('GOODSIG '+M.PPA_KEY[-16:],'GOODSIG '+'A'*16),
         good.replace('VALIDSIG '+M.PPA_KEY,'VALIDSIG '+'A'*40),
         good.rsplit(M.PPA_KEY,1)[0]+'A'*40+'\n')
  for output in cases:
   with self.subTest(output=output[-65:]):self.reject(output,0,'')
 def test_signature_algorithm_class_version_reserved_fields_and_expiration_are_validated(self):
  good=ppa_good_status()
  for replacement in ('0 4 0 17 10 01','0 4 0 1 10 00','0 3 0 1 10 01',
                      '0 4 1 1 10 01','1 4 0 1 10 01'):
   with self.subTest(replacement=replacement):self.reject(good.replace('0 4 0 1 10 01',replacement),0,'')
 def test_legacy_error_requires_exact_missing_key_code_fingerprint_and_pairing(self):
  legacy=ppa_legacy_missing()
  invalid=(legacy.replace(' 9 '+M.PPA_LEGACY_KEY,' 4 '+M.PPA_LEGACY_KEY),
           legacy.replace('NO_PUBKEY '+M.PPA_LEGACY_KEY[-16:],'NO_PUBKEY '+'A'*16),
           legacy.replace('ERRSIG '+M.PPA_LEGACY_KEY[-16:],'ERRSIG '+'A'*16),
           legacy.replace(' 9 '+M.PPA_LEGACY_KEY,' 9 '+'A'*40),
           '\n'.join(line for line in legacy.splitlines() if 'NO_PUBKEY' not in line)+'\n',
           '\n'.join(line for line in legacy.splitlines() if 'ERRSIG' not in line)+'\n')
  for output in invalid:
   with self.subTest(output=output[-75:]):self.reject(ppa_good_status()+output)
 def test_legacy_algorithm_digest_class_and_creation_time_must_match_case(self):
  legacy=ppa_legacy_missing()
  for output in (legacy.replace(' 1 10 01 ',' 17 10 01 '),legacy.replace(' 1 10 01 ',' 1 2 01 '),
                 legacy.replace(' 1 10 01 ',' 1 10 00 '),legacy.replace('1793700000','1793700001')):
   with self.subTest(output=output[-95:]):self.reject(ppa_good_status()+output)
 def test_duplicate_extra_empty_or_unpaired_signature_groups_are_rejected(self):
  good=ppa_good_status();legacy=ppa_legacy_missing()
  for output in (good+good,good+legacy+legacy,good+legacy+'[GNUPG:] NEWSIG\n',
                 good.replace('[GNUPG:] NEWSIG\n','',1)+legacy,
                 good+next(line+'\n' for line in good.splitlines() if 'VALIDSIG' in line),
                 good+next(line+'\n' for line in good.splitlines() if 'GOODSIG' in line)+legacy):
   with self.subTest(output=output[-100:]):self.reject(output)
 def test_bad_expired_revoked_unknown_and_resource_statuses_are_rejected(self):
  for name in ('BADSIG','EXPSIG','EXPKEYSIG','REVKEYSIG','KEYEXPIRED','SIGEXPIRED','NODATA',
               'FAILURE','ERROR','UNEXPECTED','UNKNOWN_STATUS'):
   with self.subTest(name=name):self.reject(ppa_good_status()+'[GNUPG:] '+name+' fixture\n',0,'')
 def test_malformed_status_stream_or_signature_fields_are_rejected(self):
  good=ppa_good_status()
  for output in ('',good+'not a machine status line\n',good.replace('VALIDSIG '+M.PPA_KEY,'VALIDSIG badhex'),
                 good.replace(' 2026-11-03 1793700000 0 4 ',' 2026-11-03 invalid 0 4 '),
                 '\n'.join(line for line in good.splitlines() if 'VALIDSIG' not in line)+'\n'):
   with self.subTest(output=output[-100:]):self.reject(output,0,'')
 def test_resource_errors_and_unrecognized_stderr_cannot_be_waived(self):
  good=ppa_good_status();dual=good+ppa_legacy_missing();normal=ppa_dual_stderr()
  for error in ('gpgv: keyblock resource fixture: No such file or directory\n',
                'gpgv: keydb_search failed: Invalid packet\n','gpgv: Permission denied\n',
                'gpgv: [dont know]: invalid packet (ctb=6e)\n','unexpected diagnostic\n'):
   with self.subTest(error=error):
    self.reject(dual,2,normal+error)
    self.reject(good,0,error)
  self.reject(dual,2,'')


class PpaSignatureRealCrypto(unittest.TestCase):
 """Real RSA fixtures in disposable homes; never read or import any existing key."""
 @classmethod
 def setUpClass(cls):
  cls.tmp=tempfile.TemporaryDirectory(prefix='php85-signature-parser-')
  cls.addClassCleanup(cls.tmp.cleanup)
  cls.root=Path(cls.tmp.name);cls.root.chmod(0o700)
  cls.home=cls.root/'signing';cls.home.mkdir(mode=0o700)
  cls.verify_home=cls.root/'verify';cls.verify_home.mkdir(mode=0o700)
  cls.environment=dict(PATH='/usr/bin:/bin',HOME='/nonexistent',GNUPGHOME='/nonexistent',LC_ALL='C',LANG='C')
  cls.addClassCleanup(lambda:cls.native('gpgconf',cls.home,['--kill','all'],check=False))
  fingerprints=[]
  for label in ('current','legacy'):
   cls.native('gpg',cls.home,['--batch','--pinentry-mode','loopback','--passphrase','',
    '--quick-generate-key','PHP85 Offline '+label+' <fixture@example.invalid>','rsa2048','sign','0'])
   listing=cls.native('gpg',cls.home,['--batch','--with-colons','--list-keys']).stdout.decode()
   fingerprints.append(next(line.split(':')[9] for line in listing.splitlines()
    if line.startswith('fpr:') and line.split(':')[9] not in fingerprints))
  cls.current,cls.legacy=fingerprints
  cls.keyring=cls.verify_home/'current.gpg'
  cls.keyring.write_bytes(cls.native('gpg',cls.home,['--batch','--export',cls.current]).stdout)
  cls.release=cls.root/'Release';cls.release.write_bytes(b'Origin: Offline fixture\nCodename: jammy\n')
  cls.single=cls.root/'InRelease-single';cls.dual=cls.root/'InRelease-dual'
  frozen=str(int(time.time()))+'!'
  for path,signers in ((cls.single,[cls.current]),(cls.dual,[cls.current,cls.legacy])):
   args=['--batch','--yes','--pinentry-mode','loopback','--passphrase','',
         '--faked-system-time',frozen,'--digest-algo','SHA512']
   for signer in signers:args+=['--local-user',signer]
   cls.native('gpg',cls.home,args+['--clearsign','--output',str(path),str(cls.release)])
 @classmethod
 def native(cls,binary,home,args,check=True):
  assert binary in ('gpg','gpgv','gpgconf') and cls.root in home.parents
  command=['/usr/bin/'+binary]+(['--no-options'] if binary=='gpg' else [])+['--homedir',str(home)]+args
  result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=cls.environment,timeout=30)
  if check and result.returncode:raise AssertionError(binary+' fixture failed: '+result.stderr.decode(errors='replace'))
  return result
 def verify(self,path):
  return self.native('gpgv',self.verify_home,['--status-fd=1','--keyring',str(self.keyring),str(path)],check=False)
 def test_real_current_signature_and_exact_missing_legacy_case(self):
  with patch.object(M,'PPA_KEY',self.current),patch.object(M,'PPA_LEGACY_KEY',self.legacy):
   single=self.verify(self.single);self.assertEqual(single.returncode,0)
   proof=M.ppa_signature_status(single.stdout.decode(),single.returncode,single.stderr.decode())
   self.assertFalse(proof['missing_legacy_signature'])
   dual=self.verify(self.dual);self.assertEqual(dual.returncode,2)
   self.assertIn('[GNUPG:] VALIDSIG '+self.current,dual.stdout.decode())
   self.assertIn('[GNUPG:] NO_PUBKEY '+self.legacy[-16:],dual.stdout.decode())
   proof=M.ppa_signature_status(dual.stdout.decode(),dual.returncode,dual.stderr.decode())
   self.assertTrue(proof['missing_legacy_signature'])
   self.assertEqual(proof['primary_fingerprint'],self.current)
 def test_real_tampered_payload_and_unrecognized_second_signer_are_rejected(self):
  tampered=self.root/'InRelease-tampered'
  tampered.write_bytes(self.dual.read_bytes().replace(b'Codename: jammy',b'Codename: altered'))
  with patch.object(M,'PPA_KEY',self.current),patch.object(M,'PPA_LEGACY_KEY',self.legacy):
   result=self.verify(tampered)
   self.assertNotEqual(result.returncode,0)
   with self.assertRaises(M.Hold):M.ppa_signature_status(result.stdout.decode(),result.returncode,result.stderr.decode())
  result=self.verify(self.dual)
  with patch.object(M,'PPA_KEY',self.current),patch.object(M,'PPA_LEGACY_KEY','A'*40):
   with self.assertRaises(M.Hold):M.ppa_signature_status(result.stdout.decode(),result.returncode,result.stderr.decode())

class AptInstallEvidence(unittest.TestCase):
 """Evidence uses real temp files; the APT child is always a fixture callback."""
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='php85-apt-evidence-')
  self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.job=self.root/'job';self.job.mkdir(mode=0o700)
  self.args=['/usr/bin/apt-get','--yes','--no-download','--no-remove','install','fixture-only=1']
  self.addCleanup(self.tmp.cleanup);self.addCleanup(patch.stopall)
  patch.object(M,'_SECURITY_ROOT',self.root).start()
  patch.object(M,'_SECURITY_UID',os.geteuid()).start()
  patch.object(M,'command',side_effect=AssertionError('APT evidence must not use captured command output')).start()
  self.native=patch.object(M.subprocess,'run',side_effect=AssertionError('unmocked native process forbidden')).start()
 def logs(self):return [self.job/'apt-install.stdout',self.job/'apt-install.stderr']
 def run_child(self,code=0,raises=None,after_write=None,payloads=None):
  streams=[];descriptors=[];seen=[]
  secret_out,secret_err=payloads or (b'fixture-private-output-token\n',b'fixture-private-error-token\n')
  def child(args,**kwargs):
   self.assertEqual(args,self.args)
   self.assertIn('timeout',kwargs);self.assertIsNone(kwargs['timeout'])
   self.assertNotIn('capture_output',kwargs)
   streams.extend([kwargs['stdout'],kwargs['stderr']])
   for stream,path,raw in zip(streams,self.logs(),(secret_out,secret_err)):
    fd=stream.fileno();descriptors.append(fd)
    self.assertTrue(path.is_file())
    self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o600)
    self.assertEqual(path.read_bytes(),b'')
    os.write(fd,raw)
    self.assertEqual(path.read_bytes(),raw,'child evidence is readable while the installation is still running')
   seen.append(kwargs['env'])
   if after_write:after_write(streams,self.logs())
   if raises:raise raises
   return types.SimpleNamespace(returncode=code)
  fsynced=[];real_fsync=os.fsync
  def fsync(fd):fsynced.append(fd);return real_fsync(fd)
  captured=io.StringIO();captured_error=io.StringIO();failure=None;proof=None
  with patch.object(M.subprocess,'run',side_effect=child),patch.object(M.os,'fsync',side_effect=fsync), \
       contextlib.redirect_stdout(captured),contextlib.redirect_stderr(captured_error):
   try:proof=M.apt_install(self.args,self.job)
   except (M.Hold,RuntimeError) as error:failure=error
  return dict(streams=streams,fds=descriptors,env=seen,fsynced=fsynced,error=failure,
   stdout=captured.getvalue(),stderr=captured_error.getvalue(),raw=(secret_out,secret_err),proof=proof)
 def closed(self,record):
  self.assertTrue(all(stream.closed for stream in record['streams']))
  for fd in record['fds']:
   with self.assertRaises(OSError):os.fstat(fd)
 def test_success_streams_live_to_0600_files_and_fsyncs_closes_both_descriptors(self):
  result=self.run_child()
  self.assertIsNone(result['error']);self.closed(result)
  self.assertEqual(set(result['fsynced']),set(result['fds']))
  self.assertEqual([path.read_bytes() for path in self.logs()],list(result['raw']))
  self.assertEqual(result['stdout'],'');self.assertEqual(result['stderr'],'')
  self.assertEqual(result['proof'],dict(exit_code=0,logs=[dict(path=str(path),sha256=M.hashlib.sha256(raw).hexdigest(),bytes=len(raw))
   for path,raw in zip(self.logs(),result['raw'])]))
 def test_nonzero_reports_only_exit_and_private_log_paths_without_output_leak(self):
  result=self.run_child(code=100)
  self.assertEqual(str(result['error']),'command_failed_apt-get')
  self.assertEqual(result['error'].details,dict(exit_code=100,stdout_log=str(self.logs()[0]),stderr_log=str(self.logs()[1]),
   logs=[dict(path=str(path),sha256=M.hashlib.sha256(raw).hexdigest(),bytes=len(raw)) for path,raw in zip(self.logs(),result['raw'])]))
  for raw in result['raw']:
   for public in (str(result['error']),repr(result['error'].details),result['stdout'],result['stderr']):
    self.assertNotIn(raw.decode().strip(),public)
  self.assertEqual(set(result['fsynced']),set(result['fds']));self.closed(result)
 def test_child_has_minimal_environment_no_inherited_loader_or_apt_injection(self):
  poison=dict(LD_PRELOAD='/fixture/evil.so',LD_LIBRARY_PATH='/fixture',PYTHONPATH='/fixture',
   PHPRC='/fixture',PHP_INI_SCAN_DIR='/fixture',BASH_ENV='/fixture',CURL_HOME='/fixture')
  with patch.dict(os.environ,poison,clear=True):result=self.run_child()
  self.assertIsNone(result['error'])
  environment=result['env'][0]
  self.assertFalse(set(poison)&set(environment))
  self.assertEqual(environment['PATH'],'/usr/sbin:/usr/bin:/sbin:/bin')
  self.assertEqual(environment['LC_ALL'],'C');self.assertEqual(environment['DEBIAN_FRONTEND'],'noninteractive')
 def test_apt_config_override_is_rejected_before_a_child_can_start(self):
  with patch.dict(os.environ,{'APT_CONFIG':'/fixture/foreign-config'},clear=True),self.assertRaisesRegex(M.Hold,'APT_CONFIG'):
   M.apt_install(self.args,self.job)
  self.native.assert_not_called()
  self.assertTrue(all(path.stat().st_mode&0o077==0 for path in self.logs()))
 def test_wrong_executable_and_nonprivate_or_foreign_owned_job_are_refused(self):
  with self.assertRaisesRegex(M.Hold,'APT_install_executable_required'):
   M.apt_install(['/usr/bin/dpkg','fixture-only'],self.job)
  self.job.chmod(0o750)
  with self.assertRaisesRegex(M.Hold,'unsafe_APT_evidence_directory'):M.apt_install(self.args,self.job)
  self.job.chmod(0o700);real=Path.lstat
  def foreign(path):
   info=real(path)
   if path!=self.job:return info
   values={name:getattr(info,name) for name in dir(info) if name.startswith('st_')}
   values['st_uid']=os.geteuid()+1000
   return types.SimpleNamespace(**values)
  with patch.object(Path,'lstat',foreign),self.assertRaisesRegex(M.Hold,'unsafe_APT_evidence_directory'):
   M.apt_install(self.args,self.job)
  self.native.assert_not_called();self.assertFalse(any(path.exists() for path in self.logs()))
 def test_symlinked_job_or_arbitrary_symlink_parent_cannot_redirect_evidence(self):
  linked=self.root/'linked-job';linked.symlink_to(self.job,target_is_directory=True)
  with self.assertRaisesRegex(M.Hold,'unsafe_APT_evidence_directory'):M.apt_install(self.args,linked)
  parent=self.root/'linked-parent';parent.symlink_to(self.root,target_is_directory=True)
  with self.assertRaisesRegex(M.Hold,'unsafe_file_parent'):M.apt_install(self.args,parent/'job')
  self.native.assert_not_called();self.assertFalse(any(path.exists() for path in self.logs()))
 def test_preexisting_stdout_file_is_preserved_and_never_truncated(self):
  path=self.logs()[0];path.write_bytes(b'prior evidence');path.chmod(0o600)
  with self.assertRaises(FileExistsError):M.apt_install(self.args,self.job)
  self.native.assert_not_called();self.assertEqual(path.read_bytes(),b'prior evidence')
  self.assertFalse(self.logs()[1].exists())
 def test_preexisting_stderr_symlink_cannot_overwrite_a_target_and_closes_first_fd(self):
  target=self.root/'preserve';target.write_bytes(b'untouched')
  self.logs()[1].symlink_to(target)
  real_open=os.open;descriptors=[]
  def observed(path,*args,**kwargs):
   fd=real_open(path,*args,**kwargs);descriptors.append(fd);return fd
  with patch.object(M.os,'open',side_effect=observed),self.assertRaises(FileExistsError):
   M.apt_install(self.args,self.job)
  self.native.assert_not_called();self.assertEqual(target.read_bytes(),b'untouched')
  self.assertEqual(len(descriptors),1)
  with self.assertRaises(OSError):os.fstat(descriptors[0])
  self.assertEqual(stat.S_IMODE(self.logs()[0].stat().st_mode),0o600)
 def test_subprocess_exception_keeps_private_evidence_and_closes_both_streams(self):
  result=self.run_child(raises=RuntimeError('fixture child exception'))
  self.assertIsInstance(result['error'],RuntimeError)
  self.closed(result)
  self.assertEqual([path.read_bytes() for path in self.logs()],list(result['raw']))
 def test_fchmod_failure_after_exclusive_open_does_not_leak_the_raw_descriptor(self):
  real_open=os.open;descriptors=[]
  def observed(path,*args,**kwargs):
   fd=real_open(path,*args,**kwargs);descriptors.append(fd);return fd
  with patch.object(M.os,'open',side_effect=observed),patch.object(M.os,'fchmod',side_effect=PermissionError('fixture mode failure')):
   with self.assertRaises(PermissionError):M.apt_install(self.args,self.job)
  self.native.assert_not_called();self.assertEqual(len(descriptors),1)
  try:
   with self.assertRaises(OSError):os.fstat(descriptors[0])
  finally:
   try:os.close(descriptors[0])
   except OSError:pass
 def test_fdopen_failure_closes_raw_descriptor_and_does_not_mask_original_exception(self):
  for already_closed in (False,True):
   with self.subTest(already_closed=already_closed):
    for path in self.logs():
     if path.exists():path.unlink()
    real_open=os.open;descriptors=[];original=OSError('fixture stream wrapper failed')
    def observed(path,*args,**kwargs):
     fd=real_open(path,*args,**kwargs);descriptors.append(fd);return fd
    def fdopen(fd,*args,**kwargs):
     if already_closed:os.close(fd)
     raise original
    with patch.object(M.os,'open',side_effect=observed),patch.object(M.os,'fdopen',side_effect=fdopen):
     with self.assertRaises(OSError) as caught:M.apt_install(self.args,self.job)
    self.assertIs(caught.exception,original);self.native.assert_not_called()
    for fd in descriptors:
     try:
      with self.assertRaises(OSError):os.fstat(fd)
     finally:
      try:os.close(fd)
      except OSError:pass
 def test_hashing_reads_large_output_only_in_bounded_chunks(self):
  real_fdopen=os.fdopen;requests=[]
  class BoundedStream:
   def __init__(self,stream):self.stream=stream
   def __getattr__(self,name):return getattr(self.stream,name)
   def read(self,size=-1):
    self_test.assertGreater(size,0);self_test.assertLessEqual(size,1024*1024)
    requests.append(size);return self.stream.read(size)
  self_test=self
  with patch.object(M.os,'fdopen',side_effect=lambda *args,**kwargs:BoundedStream(real_fdopen(*args,**kwargs))):
   result=self.run_child(payloads=(b'x'*(3*1024*1024+37),b'error evidence\n'))
  self.assertIsNone(result['error']);self.closed(result)
  self.assertGreaterEqual(len(requests),7)
  self.assertEqual(result['proof']['logs'][0]['bytes'],3*1024*1024+37)
  self.assertEqual(result['proof']['logs'][0]['sha256'],M.hashlib.sha256(result['raw'][0]).hexdigest())
 def test_replaced_log_path_with_identical_content_is_not_accepted_as_the_child_file(self):
  def replace(streams,paths):
   raw=paths[0].read_bytes();paths[0].rename(self.job/'held-original.stdout')
   paths[0].write_bytes(raw);paths[0].chmod(0o600)
  result=self.run_child(after_write=replace)
  self.assertEqual(str(result['error']),'APT_evidence_changed');self.closed(result)
  self.assertIsNone(result['proof'])
 def test_same_inode_content_mutation_during_hashing_is_rejected(self):
  real_fdopen=os.fdopen;changed=False
  class MutatingStream:
   def __init__(self,stream):self.stream=stream
   def __getattr__(self,name):return getattr(self.stream,name)
   def read(self,size=-1):
    nonlocal changed
    value=self.stream.read(size)
    if not changed and value:
     changed=True;path=self_test.logs()[0];before=path.stat()
     path.write_bytes(b'mutated fixture evidence\n')
     os.utime(path,ns=(before.st_atime_ns,before.st_mtime_ns+1000000))
    return value
  self_test=self
  with patch.object(M.os,'fdopen',side_effect=lambda *args,**kwargs:MutatingStream(real_fdopen(*args,**kwargs))):
   result=self.run_child()
  self.assertEqual(str(result['error']),'APT_evidence_changed');self.closed(result)
  self.assertIsNone(result['proof'])
 def test_post_child_permission_hardlink_or_owner_drift_is_rejected_before_a_success_receipt(self):
  for mutation in ('permissions','hardlink','owner'):
   with self.subTest(mutation=mutation):
    for path in self.logs():
     if path.exists():path.unlink()
    changed_fd=[];real_fstat=os.fstat
    def fstat(fd):
     observed=real_fstat(fd)
     if changed_fd and fd==changed_fd[0]:
      values={name:getattr(observed,name) for name in dir(observed) if name.startswith('st_')}
      values['st_uid']=os.geteuid()+1000
      return types.SimpleNamespace(**values)
     return observed
    def drift(streams,paths):
     if mutation=='permissions':paths[0].chmod(0o644)
     elif mutation=='hardlink':os.link(paths[0],self.root/'unexpected-hardlink')
     else:changed_fd.append(streams[0].fileno())
    with patch.object(M.os,'fstat',side_effect=fstat):result=self.run_child(after_write=drift)
    self.assertEqual(str(result['error']),'APT_evidence_metadata_changed')
    self.assertIsNone(result['proof']);self.closed(result)
 def test_initial_fstat_failure_closes_the_not_yet_wrapped_descriptor(self):
  real_open=os.open;real_fstat=os.fstat;descriptors=[];original=OSError('fixture initial fstat failure')
  def observed(path,*args,**kwargs):
   fd=real_open(path,*args,**kwargs);descriptors.append(fd);return fd
  with patch.object(M.os,'open',side_effect=observed),patch.object(M.os,'fstat',side_effect=original):
   with self.assertRaises(OSError) as caught:M.apt_install(self.args,self.job)
  self.assertIs(caught.exception,original);self.native.assert_not_called()
  for fd in descriptors:
   try:
    with self.assertRaises(OSError):real_fstat(fd)
   finally:
    try:os.close(fd)
    except OSError:pass


class ConfigurationContinuationEvidence(unittest.TestCase):
 """Admission evidence guards on private real files; no native actions allowed."""
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='php85-continuation-evidence-')
  self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.base=self.root/'state';self.base.mkdir(mode=0o700)
  self.job=self.base/'job-20261103T010203Z-0123abcd';self.job.mkdir(mode=0o700)
  self.receipt=self.base/('configuration-continuation-'+self.job.name+'.json')
  self.addCleanup(self.tmp.cleanup);self.addCleanup(patch.stopall)
  patch.object(M,'BASE',self.base).start()
  patch.object(M,'_SECURITY_ROOT',self.root).start()
  patch.object(M,'_SECURITY_UID',os.geteuid()).start()
  self.command=patch.object(M,'command',side_effect=AssertionError('continuation evidence check must not execute commands')).start()
  self.native=patch.object(M.subprocess,'run',side_effect=AssertionError('continuation evidence check must not run processes')).start()
  self.atomic=patch.object(M,'atomic',side_effect=AssertionError('continuation evidence check must not repair receipts')).start()
 def write(self,path,raw=b'{"schema":1,"phase":"started"}\n',mode=0o600):
  path.write_bytes(raw);path.chmod(mode)
 def no_actions(self):
  self.command.assert_not_called();self.native.assert_not_called();self.atomic.assert_not_called()
 def test_started_receipt_blocks_with_current_present_or_missing_without_repair(self):
  self.write(self.receipt)
  for current_exists in (False,True):
   with self.subTest(current_exists=current_exists):
    current=self.base/'current.json'
    if current_exists:self.write(current,b'{"historical":"must stay untouched"}\n')
    before=self.receipt.read_bytes()
    with self.assertRaisesRegex(M.Hold,'unfinished_configuration_continuation_preserved'):
     M.verify_configuration_continuation_journals()
    self.assertEqual(self.receipt.read_bytes(),before)
    if current_exists:self.assertEqual(current.read_bytes(),b'{"historical":"must stay untouched"}\n')
  self.no_actions()
 def test_nonprivate_or_foreign_owned_receipt_holds_before_native_or_config_work(self):
  self.write(self.receipt,mode=0o640)
  with self.assertRaisesRegex(M.Hold,'private_file_required'):M.verify_configuration_continuation_journals()
  self.receipt.chmod(0o600);real=Path.lstat
  def foreign(path):
   observed=real(path)
   if path!=self.receipt:return observed
   values={key:getattr(observed,key) for key in dir(observed) if key.startswith('st_')}
   values['st_uid']=os.geteuid()+1000
   return types.SimpleNamespace(**values)
  with patch.object(Path,'lstat',foreign),self.assertRaisesRegex(M.Hold,'unsafe_file_alias_owner'):
   M.verify_configuration_continuation_journals()
  self.no_actions()
 def test_symlinked_or_hardlinked_receipt_never_follows_or_changes_target_evidence(self):
  target=self.root/'preserved';raw=b'{"schema":1,"phase":"started"}\n';self.write(target,raw)
  self.receipt.symlink_to(target)
  with self.assertRaisesRegex(M.Hold,'private_file_symlink'):M.verify_configuration_continuation_journals()
  self.assertEqual(target.read_bytes(),raw);self.receipt.unlink()
  os.link(target,self.receipt)
  with self.assertRaisesRegex(M.Hold,'unsafe_file'):M.verify_configuration_continuation_journals()
  self.assertEqual(target.read_bytes(),raw);self.no_actions()
 def test_duplicate_json_keys_cannot_hide_an_incomplete_continuation(self):
  raw=b'{"schema":1,"phase":"started","phase":"complete"}\n';self.write(self.receipt,raw)
  with self.assertRaisesRegex(M.Hold,'duplicate_preinstall_JSON_key'):M.verify_configuration_continuation_journals()
  self.assertEqual(self.receipt.read_bytes(),raw);self.no_actions()
 def test_nonprivate_or_symlinked_old_job_is_rejected_before_reading_or_applying_a_plan(self):
  previous=dict(version='1.0.6',job=str(self.job),phase='failed_needs_review',event_sha256='0'*64,
   reason='removed_nondefault_INI_setting',details={},recovery=str(self.job/'recovery.json'))
  self.job.chmod(0o750)
  with self.assertRaisesRegex(M.Hold,'unsafe_preinstall_job'):M.continue_v106_configuration(previous)
  self.job.chmod(0o700);self.job.rename(self.base/'original-private-job')
  self.job.symlink_to(self.base/'original-private-job',target_is_directory=True)
  with self.assertRaisesRegex(M.Hold,'unsafe_preinstall_job'):M.continue_v106_configuration(previous)
  self.no_actions()
 def test_failure_to_save_original_current_leaves_old_current_and_event_bytes_untouched(self):
  # Reuse the integrated fixture's fake filesystem/endpoints; production core
  # admission and exception handling execute, while its one targeted write fails.
  fixtures=importlib.import_module('test_php85_upgrade')
  case=fixtures.ApplyFixtures('test_exact_v106_successful_APT_continues_configuration_without_APT_replay')
  case.setUp();self.addCleanup(case.doCleanups)
  result=case.run_apply(previous_configuration=True,continuation_mutation='save-current-failure')
  self.assertIsNotNone(result['error'])
  self.assertEqual(result['continuation_receipts'][0]['phase'],'started')
  self.assertEqual(result['current'],M.json.loads(result['previous_bytes']))
  self.assertEqual(result['preserved_previous']['events.jsonl'],result['previous_files']['events.jsonl'])
  self.assertNotIn('configuration-continuation-original-current.json',result['preserved_previous'])
  self.assertFalse(any(args[0]=='/usr/bin/apt-get' for args in result['commands']))
  self.assertEqual(result['final_site'],result['original_site'])


class Files(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.addCleanup(self.tmp.cleanup)
  self.addCleanup(patch.stopall)
  patch.object(M,'_SECURITY_ROOT',self.root).start();patch.object(M,'_SECURITY_UID',os.geteuid()).start()
  self.parent=self.root/'conf';self.parent.mkdir(mode=0o755);self.file=self.parent/'secret.ini';self.file.write_bytes(b'private=value\n');self.file.chmod(0o600)
 def test_private_file_and_snapshot_metadata(self):
  self.assertEqual(M.safe_file(self.file,True),b'private=value\n')
  snap=M.files_snapshot([self.file])[str(self.file)]
  self.assertEqual(snap['mode'],0o600);self.assertEqual(snap['resolved'],str(self.file));self.assertIsNone(snap['link'])
 def test_readonly_root_owned_leaf_alias_accepted_but_private_alias_refused(self):
  alias=self.parent/'alias.ini';alias.symlink_to('secret.ini')
  self.assertEqual(M.safe_file(alias),b'private=value\n')
  with self.assertRaisesRegex(M.Hold,'private_file_symlink'):M.safe_file(alias,True)
 def test_writable_ancestor_symlink_parent_and_outside_target_hold(self):
  self.parent.chmod(0o777)
  with self.assertRaisesRegex(M.Hold,'parent'):M.safe_file(self.file)
  self.parent.chmod(0o755);alias=self.root/'diralias';alias.symlink_to(self.parent)
  with self.assertRaisesRegex(M.Hold,'parent'):M.safe_file(alias/'secret.ini')
  leaf=self.parent/'outside';leaf.symlink_to('/etc/passwd')
  with self.assertRaisesRegex(M.Hold,'absolute_file_path'):M.safe_file(leaf)
 def test_hardlink_and_xattr_hold(self):
  os.link(self.file,self.parent/'second')
  with self.assertRaisesRegex(M.Hold,'unsafe_file'):M.safe_file(self.file)
  (self.parent/'second').unlink()
  with patch.object(M.os,'listxattr',return_value=['user.secret'],create=True):
   with self.assertRaisesRegex(M.Hold,'xattrs'):M.safe_file(self.file)
 def test_read_race_holds(self):
  real=M.os.open
  def raced(path,flags):
   self.file.write_bytes(b'changed and longer\n');return real(path,flags)
  with patch.object(M.os,'open',side_effect=raced):
   with self.assertRaisesRegex(M.Hold,'changed_during_read'):M.safe_file(self.file)

class MergedUsrParents(unittest.TestCase):
 """Real private filesystem fixtures; no host /lib or native tools are touched."""
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory(prefix='php85-usrmerge-')
  self.root=Path(self.tmp.name);self.root.chmod(0o700)
  self.addCleanup(self.tmp.cleanup)
  self.addCleanup(patch.stopall)
  patch.object(M,'_SECURITY_ROOT',self.root).start()
  patch.object(M,'_SECURITY_UID',os.geteuid()).start()
  patch.object(M,'command',side_effect=AssertionError('native commands forbidden in filesystem fixtures')).start()
  patch.object(M.subprocess,'run',side_effect=AssertionError('native subprocess forbidden')).start()
  self.payload=b'[Service]\nExecStart=/fixture/never-executed\n'

 def merged(self,name='lib',absolute=False):
  target=self.root/'usr'/name
  target.mkdir(mode=0o755,parents=True,exist_ok=True)
  leaf=target/'systemd'/'system'/'php-fpm.service'
  leaf.parent.mkdir(mode=0o755,parents=True,exist_ok=True)
  leaf.write_bytes(self.payload);leaf.chmod(0o600)
  alias=self.root/name
  if alias.is_symlink():alias.unlink()
  alias.symlink_to(str(target) if absolute else 'usr/'+name,target_is_directory=True)
  return alias/'systemd'/'system'/'php-fpm.service',leaf,alias,target

 def snapshot(self,path):return M.files_snapshot([path])[str(path)]

 def test_all_four_fixed_merged_prefixes_accept_exact_relative_and_absolute_targets(self):
  for name in ('bin','sbin','lib','lib64'):
   for absolute in (False,True):
    with self.subTest(name=name,absolute=absolute):
     logical,canonical,alias,target=self.merged(name,absolute)
     leaf,records=M._safe_parents(logical)
     self.assertEqual(leaf,canonical)
     self.assertEqual(records,[(alias,M._file_identity(alias.lstat()),os.readlink(alias))])
     self.assertEqual(M.safe_file(logical,True),self.payload)
     metadata=self.snapshot(logical)
     self.assertEqual(metadata['resolved'],str(canonical))
     self.assertIsNone(metadata['link'])
     self.assertEqual(metadata['parent_aliases'],[dict(path=str(alias),
      identity=list(M._file_identity(alias.lstat())),target=os.readlink(alias))])

 def test_unmerged_root_level_real_directories_remain_valid(self):
  for name in ('bin','sbin','lib','lib64'):
   with self.subTest(name=name):
    parent=self.root/name;parent.mkdir(mode=0o755)
    leaf=parent/'fixture';leaf.write_bytes(self.payload);leaf.chmod(0o600)
    canonical,aliases=M._safe_parents(leaf)
    self.assertEqual(canonical,leaf);self.assertEqual(aliases,[])
    self.assertEqual(M.safe_file(leaf,True),self.payload)
    self.assertEqual(self.snapshot(leaf)['parent_aliases'],[])

 def test_leaf_alias_chain_may_cross_a_fixed_merged_parent_without_losing_logical_link(self):
  logical,canonical,parent_alias,target=self.merged()
  directory=self.root/'etc'/'php';directory.mkdir(mode=0o755,parents=True)
  intermediate=directory/'native.ini';intermediate.symlink_to(str(logical))
  leaf=directory/'active.ini';leaf.symlink_to('native.ini')
  self.assertEqual(M.safe_file(leaf),self.payload)
  metadata=self.snapshot(leaf)
  self.assertEqual(metadata['link'],'native.ini')
  self.assertEqual(metadata['resolved'],str(canonical))
  self.assertEqual(metadata['parent_aliases'][0]['path'],str(parent_alias))
  with self.assertRaisesRegex(M.Hold,'private_file_symlink'):M.safe_file(leaf,True)

 def test_only_exact_fixed_parent_alias_targets_are_accepted(self):
  logical,canonical,alias,target=self.merged()
  invalid=('usr/lib64','usr/share','./usr/lib','usr/../usr/lib','../usr/lib',
           str(self.root/'usr'/'lib'/'..'/'lib'),'/usr/lib')
  for value in invalid:
   with self.subTest(value=value):
    alias.unlink();alias.symlink_to(value,target_is_directory=True)
    with self.assertRaises(M.Hold):M.safe_file(logical)

 def test_arbitrary_root_and_nested_parent_aliases_are_not_admitted(self):
  logical,canonical,alias,target=self.merged()
  arbitrary=self.root/'other-lib';arbitrary.symlink_to(target,target_is_directory=True)
  with self.assertRaisesRegex(M.Hold,'unsafe_file_parent'):
   M.safe_file(arbitrary/'systemd'/'system'/'php-fpm.service')
  directory=self.root/'conf';directory.mkdir(mode=0o755)
  nested=directory/'lib';nested.symlink_to(target,target_is_directory=True)
  with self.assertRaisesRegex(M.Hold,'unsafe_file_parent'):
   M.safe_file(nested/'systemd'/'system'/'php-fpm.service')

 def test_symlinked_canonical_usr_or_target_parent_is_held(self):
  for component in ('usr','lib'):
   with self.subTest(component=component),tempfile.TemporaryDirectory(dir=self.root) as local:
    root=Path(local);root.chmod(0o700)
    real=root/'real';(real/'lib'/'systemd').mkdir(mode=0o755,parents=True)
    leaf=real/'lib'/'systemd'/'unit';leaf.write_bytes(self.payload);leaf.chmod(0o600)
    if component=='usr':
     (root/'usr').symlink_to(real,target_is_directory=True)
    else:
     (root/'usr').mkdir(mode=0o755)
     (root/'usr'/'lib').symlink_to(real/'lib',target_is_directory=True)
    (root/'lib').symlink_to('usr/lib',target_is_directory=True)
    with patch.object(M,'_SECURITY_ROOT',root),self.assertRaisesRegex(M.Hold,'unsafe_file_parent'):
     M.safe_file(root/'lib'/'systemd'/'unit')

 def test_writable_canonical_ancestor_reports_original_request_and_specific_parent(self):
  logical,canonical,alias,target=self.merged()
  parent=self.root/'usr';parent.chmod(0o777)
  with self.assertRaisesRegex(M.Hold,'unsafe_file_parent') as caught:M.safe_file(logical)
  observed=parent.lstat()
  self.assertEqual(caught.exception.details,dict(requested_path=str(logical),parent_path=str(parent),
   uid=observed.st_uid,gid=observed.st_gid,mode=oct(stat.S_IMODE(observed.st_mode)),type='directory'))

 def test_foreign_uid_on_alias_or_canonical_ancestor_is_rejected(self):
  logical,canonical,alias,target=self.merged()
  real=Path.lstat
  for unsafe in (alias,self.root/'usr',target):
   def foreign(path):
    observed=real(path)
    if path!=unsafe:return observed
    values={name:getattr(observed,name) for name in dir(observed) if name.startswith('st_')}
    values['st_uid']=os.geteuid()+1000
    return types.SimpleNamespace(**values)
   with self.subTest(parent=str(unsafe)),patch.object(Path,'lstat',foreign):
    with self.assertRaisesRegex(M.Hold,'unsafe_file_parent') as caught:M.safe_file(logical)
    self.assertEqual(caught.exception.details['parent_path'],str(unsafe))
    self.assertEqual(caught.exception.details['requested_path'],str(logical))

 def test_replacing_parent_alias_with_same_target_during_open_is_detected(self):
  logical,canonical,alias,target=self.merged()
  real=M.os.open;opened=[]
  def raced(path,flags,*args,**kwargs):
   opened.append(str(path))
   alias.rename(self.root/'old-lib-alias');alias.symlink_to('usr/lib',target_is_directory=True)
   return real(path,flags,*args,**kwargs)
  with patch.object(M.os,'open',side_effect=raced),self.assertRaisesRegex(M.Hold,'alias_changed_during_read'):
   M.safe_file(logical)
  self.assertEqual(opened,[str(canonical)],'read only canonical leaf spelling after validating its parent alias')

 def test_retargeting_parent_alias_to_equivalent_absolute_spelling_during_open_is_detected(self):
  logical,canonical,alias,target=self.merged()
  real=M.os.open
  def raced(path,flags,*args,**kwargs):
   alias.rename(self.root/'old-lib-alias');alias.symlink_to(target,target_is_directory=True)
   return real(path,flags,*args,**kwargs)
  with patch.object(M.os,'open',side_effect=raced),self.assertRaisesRegex(M.Hold,'alias_changed_during_read'):
   M.safe_file(logical)

 def test_same_content_parent_replacement_and_retarget_change_snapshot_metadata(self):
  logical,canonical,alias,target=self.merged()
  first=self.snapshot(logical)
  alias.rename(self.root/'old-lib-alias');alias.symlink_to('usr/lib',target_is_directory=True)
  second=self.snapshot(logical)
  alias.rename(self.root/'second-old-lib-alias');alias.symlink_to(target,target_is_directory=True)
  third=self.snapshot(logical)
  for metadata in (second,third):
   self.assertEqual(first['sha256'],metadata['sha256'])
   self.assertEqual(first['resolved'],metadata['resolved'])
   self.assertEqual(first['link'],metadata['link'])
   self.assertNotEqual(first['parent_aliases'],metadata['parent_aliases'])
   self.assertNotEqual(first,metadata)

 def test_parent_alias_swap_reached_through_leaf_alias_is_detected(self):
  logical,canonical,alias,target=self.merged()
  leaf=self.root/'leaf.ini';leaf.symlink_to(logical)
  real=M.os.open
  def raced(path,flags,*args,**kwargs):
   alias.rename(self.root/'old-lib-alias');alias.symlink_to('usr/lib',target_is_directory=True)
   return real(path,flags,*args,**kwargs)
  with patch.object(M.os,'open',side_effect=raced),self.assertRaisesRegex(M.Hold,'alias_changed_during_read'):
   M.safe_file(leaf)


class Sources(unittest.TestCase):
 def test_all_unsafe_list_boolean_forms_hold(self):
  for key in ('trusted','allow-insecure','allow-weak','allow-downgrade-to-insecure','allow-weak-downgrade-to-insecure'):
   for value in ('yes','true','1'):
    with self.subTest(key=key,value=value),self.assertRaisesRegex(M.Hold,'authentication_override'):
     M._source_entries('deb ['+key+'='+value+'] https://example.invalid/repo jammy main','.list')
 def test_safe_false_and_expiry_false_rejection(self):
  self.assertEqual(len(M._source_entries('deb [trusted=no signed-by=/etc/apt/keyrings/key.gpg] https://example.invalid/repo jammy main','.list')),1)
  for key in ('check-valid-until','check-date'):
   with self.assertRaisesRegex(M.Hold,'expiry_override'):M._source_entries('deb ['+key+'=no] https://example.invalid/repo jammy main','.list')
 def test_deb822_inline_key_and_active_waivers(self):
  text='Types: deb\nURIs: https://ppa.launchpadcontent.net/ondrej/php/ubuntu\nSuites: jammy\nComponents: main\nSigned-By:\n -----BEGIN PGP PUBLIC KEY BLOCK-----\n .\n mock\n -----END PGP PUBLIC KEY BLOCK-----\n'
  item=M._source_entries(text,'.sources')[0]
  self.assertTrue(item['signed_by'].strip().startswith('-----BEGIN'))
  with self.assertRaisesRegex(M.Hold,'authentication_override'):M._source_entries(text+'Trusted: yes\n','.sources')
  self.assertEqual(M._source_entries(text+'Enabled: no\nTrusted: yes\n','.sources'),[])
 def test_key_path_bounded_and_duplicate_fields_hold(self):
  self.assertEqual(M._key_paths('/usr/share/keyrings/ppa.gpg'),['/usr/share/keyrings/ppa.gpg'])
  for path in ('/tmp/key.gpg','/etc/apt/../secret.gpg'):
   with self.assertRaises(M.Hold):M._key_paths(path)
  with self.assertRaisesRegex(M.Hold,'duplicate'):M._source_entries('Types: deb\nTypes: deb\n','.sources')
 def test_effective_config_scoped_weak_override_and_APT_CONFIG(self):
  key='Acquire::https::example.invalid::AllowWeakDowngradeToInsecure'
  config=types.SimpleNamespace(keys=lambda:[key],find_b=lambda name,default=False:name==key or default)
  apt=types.SimpleNamespace(init_config=lambda:None,config=config)
  with patch.dict(os.environ,{},clear=True),patch.dict(sys.modules,{'apt_pkg':apt}),patch.object(M,'_configured_sources',return_value=([],[])):
   with self.assertRaisesRegex(M.Hold,'authentication_override'):M.validate_apt_security()
  with patch.dict(os.environ,{'APT_CONFIG':'/tmp/unsealed-config'}):
   with self.assertRaisesRegex(M.Hold,'APT_CONFIG'):M.validate_apt_security()

class CommandsAndSignatures(unittest.TestCase):
 def test_child_environment_is_minimal_and_explicit_php_scan_only(self):
  seen=[]
  def run(args,**kwargs):seen.append(kwargs['env']);return types.SimpleNamespace(returncode=0,stdout=b'ok',stderr=b'')
  with patch.dict(os.environ,{'LD_PRELOAD':'evil','BASH_ENV':'evil','CURL_HOME':'evil','PYTHONPATH':'evil'},clear=True),patch.object(M.subprocess,'run',side_effect=run):
   self.assertEqual(M.command(['/usr/bin/fixture'],env={'PHP_INI_SCAN_DIR':'/etc/php/8.5/fpm/conf.d'}),'ok')
   self.assertFalse(any(name in seen[0] for name in ('LD_PRELOAD','BASH_ENV','CURL_HOME','PYTHONPATH')))
   with self.assertRaisesRegex(M.Hold,'unapproved'):M.command(['/usr/bin/fixture'],env={'PHPRC':'/tmp/evil'})
 def test_PPA_signature_uses_exact_source_path_and_primary_pin(self):
  entry=dict(uris=['https://ppa.launchpadcontent.net/ondrej/php/ubuntu'],types=['deb'],suites=['jammy'],signed_by='/usr/share/keyrings/ppa.gpg',source_path='/etc/apt/sources.list.d/php.sources')
  raw=b'-----BEGIN PGP SIGNED MESSAGE-----\nOrigin: LP-PPA-ondrej-php\nCodename: jammy\n'
  calls=[]
  def read(path,*args):return raw if str(path).endswith('_InRelease') else b'binary-key'
  def run(args,**kwargs):calls.append(args);return ppa_good_status()
  # Real temporary files only; all crypto commands and privileged file reads mocked.
  factory=tempfile.TemporaryDirectory
  with patch.object(M,'_configured_sources',return_value=([],[entry])),patch.object(M,'safe_file',side_effect=read),patch.object(M,'command',side_effect=run),patch.object(M.tempfile,'TemporaryDirectory',side_effect=lambda **kw:factory(prefix=kw['prefix'])):
   result=M.verify_PPA_signature();self.assertEqual(result[0]['primary_fingerprint'],M.PPA_KEY)
   self.assertEqual(result[0]['path'],'/var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_jammy_InRelease')
   with patch.object(M,'command',return_value=ppa_good_status('A'*40)):
    with self.assertRaisesRegex(M.Hold,'fingerprint'):M.verify_PPA_signature()
 def test_unrelated_repo_signature_cannot_satisfy_missing_PPA(self):
  with patch.object(M,'_configured_sources',return_value=([],[])):
   with self.assertRaisesRegex(M.Hold,'existing_Jammy'):M.verify_PPA_signature()
 def test_global_keyring_and_inline_armor_supported_without_truststore_writes(self):
  base=dict(uris=['https://ppa.launchpadcontent.net/ondrej/php/ubuntu'],types=['deb'],suites=['jammy'],source_path='/etc/apt/sources.list.d/php.sources')
  release=b'Origin: LP-PPA-ondrej-php\nCodename: jammy\n'
  factory=tempfile.TemporaryDirectory;real_exists=Path.exists
  for signed in ('','-----BEGIN PGP PUBLIC KEY BLOCK-----\n.\nmock\n-----END PGP PUBLIC KEY BLOCK-----'):
   entry=dict(base,signed_by=signed);calls=[]
   def run(args,**kwargs):
    calls.append(args)
    return ppa_good_status() if args[0].endswith('gpgv') else ''
   def read(path,*args):return release if str(path).endswith('_InRelease') else b'global-key'
   def exists(path):return True if str(path)=='/etc/apt/trusted.gpg' else real_exists(path)
   with self.subTest(inline=bool(signed)),patch.object(M,'_configured_sources',return_value=([],[entry])),patch.object(M,'safe_file',side_effect=read),patch.object(M,'command',side_effect=run),patch.object(M.glob,'glob',return_value=[]),patch.object(Path,'exists',exists),patch.object(M.tempfile,'TemporaryDirectory',side_effect=lambda **kw:factory(prefix=kw['prefix'])):
    proof=M.verify_PPA_signature()[0]
    self.assertEqual(proof['primary_fingerprint'],M.PPA_KEY)
    self.assertEqual(proof['keyrings'][0]['path'],None if signed else '/etc/apt/trusted.gpg')
    self.assertEqual(any(args[0].endswith('/gpg') for args in calls),bool(signed))
    self.assertTrue(all('--output' not in args or str(args[args.index('--output')+1]).startswith(tempfile.gettempdir()+'/php85-key-') for args in calls))
 def test_signedby_keyrings_outside_default_directory_are_in_snapshot(self):
  entry=dict(signed_by='/usr/share/keyrings/ondrej-php.gpg')
  with patch.object(M.glob,'glob',return_value=[]),patch.object(M,'_configured_sources',return_value=(['/etc/apt/sources.list.d/php.sources'],[entry])),patch.object(M,'files_snapshot',side_effect=lambda paths:sorted(set(paths))):
   self.assertEqual(M.source_files(),['/etc/apt/sources.list.d/php.sources','/usr/share/keyrings/ondrej-php.gpg'])
 def test_command_retains_bounded_gpgv_failure_evidence_without_relaxing_other_failures(self):
  output=ppa_good_status()+ppa_legacy_missing();stderr=ppa_dual_stderr()
  result=types.SimpleNamespace(returncode=2,stdout=output.encode(),stderr=stderr.encode())
  with patch.dict(os.environ,{},clear=True),patch.object(M.subprocess,'run',return_value=result):
   with self.assertRaisesRegex(M.Hold,'command_failed_gpgv') as caught:M.command(['/usr/bin/gpgv','fixture-only'])
   self.assertEqual(caught.exception.gpgv_result,dict(returncode=2,stdout=output,stderr=stderr))
   self.assertEqual(caught.exception.details['exit_code'],2)
   self.assertIn('VALIDSIG',caught.exception.details['status_codes'])
   self.assertIn('NO_PUBKEY',caught.exception.details['status_codes'])
   with self.assertRaisesRegex(M.Hold,'command_failed_fixture') as other:M.command(['/usr/bin/fixture'])
   self.assertFalse(hasattr(other.exception,'gpgv_result'))
 def test_signature_verifier_accepts_only_the_structured_exact_gpgv_failure(self):
  entry=dict(uris=['https://ppa.launchpadcontent.net/ondrej/php/ubuntu'],types=['deb'],suites=['jammy'],
   signed_by='/usr/share/keyrings/fixture.gpg',source_path='/etc/apt/sources.list.d/php.sources')
  release=b'Origin: LP-PPA-ondrej-php\nCodename: jammy\n'
  factory=tempfile.TemporaryDirectory
  def execute(output=None,code=2,stderr=None,message='command_failed_gpgv',structured=True):
   error=M.Hold(message)
   error.details=dict(exit_code=code,status_codes=['fixture'])
   if structured:error.gpgv_result=dict(returncode=code,stdout=output if output is not None else ppa_good_status()+ppa_legacy_missing(),
    stderr=stderr if stderr is not None else ppa_dual_stderr())
   def run(args,**kwargs):
    self.assertEqual(args[0],'/usr/bin/gpgv')
    raise error
   with patch.object(M,'_configured_sources',return_value=([],[entry])), \
    patch.object(M,'safe_file',side_effect=lambda path,*unused:release if str(path).endswith('_InRelease') else b'public-fixture-key'), \
    patch.object(M,'command',side_effect=run), \
    patch.object(M.tempfile,'TemporaryDirectory',side_effect=lambda **kw:factory(prefix=kw['prefix'])):
    return M.verify_PPA_signature()
  proof=execute()[0]
  self.assertEqual(proof['primary_fingerprint'],M.PPA_KEY)
  self.assertTrue(proof['missing_legacy_signature']);self.assertEqual(proof['gpgv_exit_code'],2)
  for kwargs in ({'structured':False},{'message':'command_failed_gpg'}, {'code':1},
                 {'output':ppa_good_status()+ppa_legacy_missing('A'*40)},
                 {'stderr':ppa_dual_stderr()+'gpgv: keydb_search failed: Invalid packet\n'}):
   with self.subTest(kwargs=kwargs),self.assertRaises(M.Hold):execute(**kwargs)

class VendorAndUnitGuards(unittest.TestCase):
 def unit(self):
  return dict(FragmentPath='/lib/systemd/system/php8.3-fpm.service',DropInPaths='',Environment='',EnvironmentFiles='',PassEnvironment='',MainPID='123',
   ExecStart='{ path=/usr/sbin/php-fpm8.3 ; argv[]=/usr/sbin/php-fpm8.3 --nodaemonize --fpm-config /etc/php/8.3/fpm/php-fpm.conf ; ignore_errors=no ; }')
 def rendered(self,value):return '\n'.join(key+'='+row for key,row in value.items())+'\n'
 def test_vendor_file_must_match_exact_single_package_inventory(self):
  raw=b'packaged binary';checksum=M.hashlib.md5(raw,usedforsecurity=False).hexdigest()
  def read(path,*args):return (checksum+'  usr/bin/php8.3\n').encode() if str(path).endswith('.md5sums') else raw
  def exists(path):return str(path)=='/var/lib/dpkg/info/php8.3-cli.md5sums'
  with patch.object(M,'safe_file',side_effect=read),patch.object(M,'command',return_value='amd64\n'),patch.object(Path,'is_file',exists),patch.object(Path,'resolve',lambda path:path):
   M.installed_vendor_file('php8.3-cli','/usr/bin/php8.3')
   with patch.object(M,'safe_file',side_effect=lambda p,*args:('0'*32+'  usr/bin/php8.3\n').encode() if str(p).endswith('.md5sums') else raw):
    with self.assertRaisesRegex(M.Hold,'vendor_file_modified'):M.installed_vendor_file('php8.3-cli','/usr/bin/php8.3')
  with patch.object(M,'safe_file',return_value=raw),patch.object(M,'command',return_value='amd64'),patch.object(Path,'is_file',return_value=True):
   with self.assertRaisesRegex(M.Hold,'ambiguous'):M.installed_vendor_file('php8.3-cli','/usr/bin/php8.3')
 def loader_command(self,args,**kwargs):
  if args[0]=='/usr/bin/php8.3':return '/usr/lib/php/20230831'
  if args[:2]==['/usr/bin/dpkg-query','-S']:return 'php8.3-mysql: '+args[-1]+'\n'
  raise AssertionError(args)
 def test_loader_basename_and_package_owned_API_file_required(self):
  profiles={'fpm':{'/etc/php/8.3/fpm/php.ini':'extension = mysqli.so\n'}}
  with patch.object(M,'installed_vendor_file') as vendor,patch.object(M,'command',side_effect=self.loader_command):
   M.validate_loaders('8.3',profiles,{'php8.3-mysql':{}})
   self.assertEqual(vendor.call_args_list[-1].args,('php8.3-mysql','/usr/lib/php/20230831/mysqli.so'))
   for text in ('extension=/opt/mysqli.so','zend_extension=../bad.so'):
    with self.assertRaisesRegex(M.Hold,'loader_path'):M.validate_loaders('8.3',{'cli':{'a':text}},{'php8.3-mysql':{}})
   with patch.object(M,'command',side_effect=lambda args,**kw:'/usr/lib/php/20230831' if args[0]=='/usr/bin/php8.3' else 'php-mysql: '+args[-1]):
    with self.assertRaisesRegex(M.Hold,'unversioned_or_unowned'):M.validate_loaders('8.3',profiles,{'php-mysql':{}})
 def test_custom_extension_directory_cannot_redirect_a_valid_basename(self):
  profiles={'fpm':{'a':'extension_dir=/opt/unowned\nextension=mysqli.so\n'}}
  with patch.object(M,'installed_vendor_file'),patch.object(M,'command',side_effect=self.loader_command):
   with self.assertRaises(M.Hold):M.validate_loaders('8.3',profiles,{'php8.3-mysql':{}})
 def test_stock_native_unit_and_matching_running_environment(self):
  value=self.unit();environment=b'PHPRC=/etc/php/8.3/fpm\0PHP_INI_SCAN_DIR=/etc/php/8.3/fpm/conf.d\0'
  with patch.object(M,'command',return_value=self.rendered(value)),patch.object(M,'installed_vendor_file') as vendor,patch.dict(M.RUNTIME,{'bounded':lambda *args:environment}):
   self.assertEqual(M.validate_native_unit('8.3',True),value['FragmentPath'])
   self.assertEqual(vendor.call_args.args,('php8.3-fpm',value['FragmentPath']))
 def test_custom_unit_arguments_dropins_and_environments_hold(self):
  for key,bad in [('DropInPaths','/etc/systemd/system/php8.3-fpm.service.d/x.conf'),('Environment','PHPRC=/opt'),('PassEnvironment','PHPRC'),('EnvironmentFiles','/etc/override'),('ExecStart','{ argv[]=/usr/sbin/php-fpm8.3 --fpm-config /opt/other.conf ; }')]:
   value=self.unit();value[key]=bad
   with self.subTest(key=key),patch.object(M,'command',return_value=self.rendered(value)),patch.object(M,'installed_vendor_file'):
    with self.assertRaises(M.Hold):M.validate_native_unit('8.3')
 def test_missing_array_needs_exact_typed_DBus_proof(self):
  value=self.unit();value.pop('EnvironmentFiles');calls=[]
  def run(args,**kw):calls.append(args);return self.rendered(value) if args[0]=='/bin/systemctl' else 'a(sb) 0\n'
  with patch.object(M,'command',side_effect=run),patch.object(M,'installed_vendor_file'):
   M.validate_native_unit('8.3');self.assertIn('php8_2e3_2dfpm_2eservice',calls[-1][3])
   for result in ('','a(sb) 1 "/etc/file" false','a(s) 0'):
    with patch.object(M,'command',side_effect=lambda args,**kw:self.rendered(value) if args[0]=='/bin/systemctl' else result):
     with self.assertRaisesRegex(M.Hold,'not_proven_empty'):M.validate_native_unit('8.3')
 def test_running_process_environment_loader_scan_and_ini_override_hold(self):
  value=self.unit()
  for environment in (b'LD_PRELOAD=/tmp/evil\0',b'LD_LIBRARY_PATH=/tmp\0',b'PHPRC=/opt/config\0',b'PHP_INI_SCAN_DIR=/opt/conf\0'):
   with self.subTest(environment=environment),patch.object(M,'command',return_value=self.rendered(value)),patch.object(M,'installed_vendor_file'),patch.dict(M.RUNTIME,{'bounded':lambda *args:environment}):
    with self.assertRaises(M.Hold):M.validate_native_unit('8.3',True)

if __name__=='__main__':unittest.main()
