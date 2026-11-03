"""Mock-only PHP85 security tests: no package/service/network commands."""
import importlib.util,os,stat,sys,tempfile,types,unittest,subprocess,time
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
