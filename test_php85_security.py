"""Mock-only PHP85 security tests: no package/service/network commands."""
import importlib.util,os,stat,sys,tempfile,types,unittest
from pathlib import Path
from unittest.mock import patch
SPEC=importlib.util.spec_from_file_location('php85_security_review',Path(__file__).parent/'php85_upgrade.py')
M=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(M)

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
  def run(args,**kwargs):calls.append(args);return '[GNUPG:] VALIDSIG '+M.PPA_KEY+' date 1 0 4 0 1 10 01 '+M.PPA_KEY+'\n'
  # Real temporary files only; all crypto commands and privileged file reads mocked.
  factory=tempfile.TemporaryDirectory
  with patch.object(M,'_configured_sources',return_value=([],[entry])),patch.object(M,'safe_file',side_effect=read),patch.object(M,'command',side_effect=run),patch.object(M.tempfile,'TemporaryDirectory',side_effect=lambda **kw:factory(prefix=kw['prefix'])):
   result=M.verify_PPA_signature();self.assertEqual(result[0]['primary_fingerprint'],M.PPA_KEY)
   self.assertEqual(result[0]['path'],'/var/lib/apt/lists/ppa.launchpadcontent.net_ondrej_php_ubuntu_dists_jammy_InRelease')
   with patch.object(M,'command',return_value='[GNUPG:] VALIDSIG '+'A'*40+'\n'):
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
    return '[GNUPG:] VALIDSIG '+M.PPA_KEY+' date 1 0 4 0 1 10 01 '+M.PPA_KEY+'\n' if args[0].endswith('gpgv') else ''
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
