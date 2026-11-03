"""Offline fixtures. Never execute APT, PHP, Nginx, systemctl, or the live apply path.

Run with Ubuntu Python 3.10+: python3 -B test_php85_upgrade.py
Native command entry points are denied by default in every fixture.
"""
import base64
import contextlib
import gzip
import importlib.util
import io
import json
from pathlib import Path
import re
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch


SPEC = importlib.util.spec_from_file_location('php85_fixture_subject',
    Path(__file__).with_name('php85_upgrade.py'))
M = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(M)
REAL_COMMAND = M.command
HOST = dict(architecture='amd64', machine_id='a' * 32, hostname='fixture',
            release='22.04', boot_id='fixture-boot')
VERSION = '8.5.13-1+ubuntu22.04.1+deb.sury.org+1'


def origin(**changes):
    values = dict(trusted=True, origin='LP-PPA-ondrej-php', archive='jammy',
                  site='ppa.launchpadcontent.net')
    values.update(changes)
    return SimpleNamespace(**values)


def package(name='php8.5-cli', version=VERSION, **changes):
    values = dict(version=version, architecture='amd64', source_name='php8.5',
        source_version=version, origins=[origin()],
        record={'SHA256': 'a' * 64, 'Filename': 'pool/main/p/php8.5/pkg.deb'})
    values.update(changes)
    return SimpleNamespace(candidate=SimpleNamespace(**values))


def numeric_compare(a, b):
    # Fixtures use numeric upstream versions; production apt_pkg is never invoked.
    def key(value):
        return tuple(map(int, re.match(r'^(\d+)\.(\d+)\.(\d+)', value).groups()))
    return (key(a) > key(b)) - (key(a) < key(b))


# Immutable public v1.0.0 bytes; data fixture only, never imported or executed.
_V100_CORE_GZIP_B64 = (
    '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'
)


def old_core_fixture():
    raw = gzip.decompress(base64.b64decode(_V100_CORE_GZIP_B64))
    if M.digest(raw) != "c1a39b696236d6e45d250ddc7efe1a2370c5606727721b8a7ea87dcc1c850002":
        raise AssertionError("immutable v1.0.0 fixture digest mismatch")
    return raw

class Offline(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(M, 'command', side_effect=AssertionError('native command denied')))
        self.stack.enter_context(patch.object(M.subprocess, 'run', side_effect=AssertionError('subprocess denied')))
        self.stack.enter_context(patch.object(M, 'compare', side_effect=numeric_compare))
        if hasattr(M, 'RUNTIME'):
            self.stack.enter_context(patch.dict(M.RUNTIME,
                {'prove_pool': Mock(side_effect=AssertionError('native FPM connection denied'))}))
        for helper in ('validate_native_unit', 'validate_loaders', 'unit_enabled'):
            if hasattr(M, helper):
                self.stack.enter_context(patch.object(M, helper,
                    side_effect=AssertionError('unmocked native validation helper: ' + helper)))

    def held(self, reason, function, *args, **kwargs):
        with self.assertRaisesRegex(M.Hold, re.escape(reason)):
            function(*args, **kwargs)


class NginxFixtures(Offline):
    def inventory(self, server, extra=None, expand=None):
        files = {'/etc/nginx/nginx.conf': 'events {} http { include /etc/nginx/sites-enabled/site; }',
                 '/etc/nginx/sites-enabled/site': server}
        files.update(extra or {})
        return M.nginx_inventory(read=files.__getitem__,
            expand=expand or (lambda value: [value] if value in files else []))

    @staticmethod
    def server(body='', socket='/var/run/php/php7.4-fpm.sock'):
        return ('server { listen 443 ssl; server_name example.com www.example.com; '
                'root "/srv/site with spaces"; ' + body +
                ' location ~ \\.php$ { fastcgi_pass "unix:' + socket + '"; } }')

    def test_inline_quoted_route_edits_only_operand(self):
        text = self.server('ssl_certificate "/etc/ssl/site cert.pem"; # preserve me\n')
        result = self.inventory(text)
        self.assertEqual(len(result['routes']), 1)
        mapping = {'/run/php/php7.4-fpm.sock': '/run/php/php8.5-fpm.sock'}
        output = M.route_outputs(result['files'], result['routes'], mapping)
        self.assertEqual(output['/etc/nginx/sites-enabled/site'], text.replace(
            '"unix:/var/run/php/php7.4-fpm.sock"', 'unix:/run/php/php8.5-fpm.sock'))
        self.assertEqual(result['health'][0]['aliases'], ['example.com', 'www.example.com'])

    def test_include_inside_server_keeps_context_and_route_span(self):
        snippet = 'location ~ \\.php$ { fastcgi_pass unix:/run/php/custom.sock; }'
        server = 'server { listen 443 ssl; server_name example.com; root /srv/site; include /etc/nginx/snippets/php.conf; }'
        result = self.inventory(server, {'/etc/nginx/snippets/php.conf': snippet})
        self.assertEqual(result['routes'][0]['file'], '/etc/nginx/snippets/php.conf')
        self.assertEqual(result['routes'][0]['socket'], '/run/php/custom.sock')

    def test_comments_escapes_and_literal_hash_are_not_directives(self):
        tokens = M.tokens('root "/srv/a#b"; # fastcgi_pass unix:/run/php/fake.sock;\nset $x a\\ b;')
        self.assertEqual([t[0] for t in tokens], ['root', '/srv/a#b', ';', 'set', '$x', 'a b', ';'])

    def test_quoted_punctuation_is_an_argument_not_parser_structure(self):
        nodes = M.directives('add_header X-Semicolon ";"; add_header X-Brace "}";')
        self.assertEqual([[x[0] for x in header] for header, _ in nodes],
                         [['add_header', 'X-Semicolon', ';'], ['add_header', 'X-Brace', '}']])

    def test_multiple_exact_edits_preserve_all_other_text(self):
        text = self.server() + '\n' + self.server(socket='/run/php/custom.sock')
        result = self.inventory(text)
        mapping = {'/run/php/php7.4-fpm.sock': '/run/php/php8.5-fpm.sock',
                   '/run/php/custom.sock': '/run/php/php8.5-custom.sock'}
        output = M.route_outputs(result['files'], result['routes'], mapping)
        self.assertEqual(output['/etc/nginx/sites-enabled/site'], text.replace(
            '"unix:/var/run/php/php7.4-fpm.sock"', 'unix:/run/php/php8.5-fpm.sock').replace(
            '"unix:/run/php/custom.sock"', 'unix:/run/php/php8.5-custom.sock'))

    def test_ambiguous_or_variable_document_root_holds(self):
        for body in ('root /srv/other;', 'location /other { root /srv/other; }'):
            with self.subTest(body=body):
                self.held('literal_single_document_root_required', self.inventory, self.server(body))
        self.held('literal_single_document_root_required', self.inventory,
                  self.server().replace('"/srv/site with spaces"', '$document_root'))

    def test_unsupported_network_and_socket_routes_hold(self):
        self.held('direct_Unix_FastCGI_required', self.inventory,
                  self.server().replace('"unix:/var/run/php/php7.4-fpm.sock"', '127.0.0.1:9000'))
        for socket in ('/tmp/php.sock', '/run/php/../php/escape.sock', '/run/php/$pool.sock'):
            with self.subTest(socket=socket):
                self.held('standard_local_PHP_Unix_socket_required', self.inventory, self.server(socket=socket))

    def test_non_https_wildcard_hostname_and_external_include_hold(self):
        for original, replacement, reason in (
            ('443 ssl', '80', 'local_HTTPS_443_health_profile_required'),
            ('example.com www.example.com', '_', 'canonical_site_hostname_required'),
            ('root "/srv/site with spaces";', 'include /tmp/outside;', 'absolute_nginx_include_required')):
            with self.subTest(reason=reason):
                self.held(reason, self.inventory, self.server().replace(original, replacement))

    def test_include_cycle_is_bounded(self):
        files = {'/etc/nginx/nginx.conf': 'include /etc/nginx/nginx.conf;'}
        self.held('nginx_include_limit', M.nginx_inventory, read=files.__getitem__, expand=lambda value: [value])

    def test_unbalanced_and_unterminated_text_holds(self):
        for text in ('server {', '}', 'root "/broken;', 'root /a', 'root /a\\'):
            with self.subTest(text=text), self.assertRaises(M.Hold):
                M.directives(text)

    def test_health_requires_success_on_locally_resolved_alias(self):
        spec = [dict(host='example.com', path='/', aliases=['example.com', 'www.example.com'])]
        responses = ['HTTP/1.1 301 Moved\r\nLocation: https://www.example.com/\r\n\nPHP85-CODE:301',
                     'HTTP/1.1 200 OK\r\n\nPHP85-CODE:200']
        with patch.object(M, 'command', side_effect=responses) as command:
            M.health(spec)
            self.assertEqual(command.call_count, 2)
            self.assertIn('example.com:443:127.0.0.1', command.call_args_list[0].args[0])
            self.assertIn('www.example.com:443:127.0.0.1', command.call_args_list[1].args[0])
            for call in command.call_args_list:
                self.assertIn('--disable', call.args[0])
                self.assertNotIn('--location', call.args[0])
        for location in ('https://example.com.evil.example/', 'http://example.com/',
                         'https://user:password@example.com/', 'https://example.com:444/'):
            with self.subTest(location=location), patch.object(M, 'command', return_value=
                'HTTP/1.1 302 Found\r\nLocation: ' + location + '\r\n\nPHP85-CODE:302') as command:
                self.held('health_redirect_outside_local_aliases', M.health, spec)
                self.assertEqual(command.call_count, 1, 'never send the redirected request outside approved aliases')
        with patch.object(M, 'command', return_value='HTTP/1.1 502 Bad Gateway\r\n\nPHP85-CODE:502'):
            self.held('application_health_failed', M.health, spec)


class NginxVendorAliasFixtures(Offline):
    """Distribution module aliases may be inspected, never become route targets."""
    ALIASES = (
        ('50-mod-brotli', 'mod-brotli'), ('50-mod-http-geoip', 'mod-http-geoip'),
        ('50-mod-http-image-filter', 'mod-http-image-filter'),
        ('50-mod-http-xslt-filter', 'mod-http-xslt-filter'),
        ('50-mod-mail', 'mod-mail'), ('50-mod-ssl-ct', 'mod-ssl-ct'),
        ('50-mod-stream', 'mod-stream'), ('70-mod-stream-geoip', 'mod-stream-geoip'))

    def inspect_aliases(self, aliases=None, fragment='load_module modules/ngx_fixture_module.so;\n',
                        owner='libnginx-mod-fixture', vendor_error=None, read_observations=None):
        aliases = aliases or {'/etc/nginx/modules-enabled/' + name + '.conf':
            '/usr/share/nginx/modules-available/' + target + '.conf' for name, target in self.ALIASES}
        files = {'/etc/nginx/nginx.conf': 'include /etc/nginx/modules-enabled/*.conf; events {} http { '
                 + NginxFixtures.server() + ' }'}
        files.update({path: fragment for path in aliases})
        def resolve(path, *args, **kwargs):
            if str(path) in aliases:
                return Path(aliases[str(path)])
            return Path(str(path))
        native_calls = []
        def command(args, *unused, **kwargs):
            native_calls.append(args)
            self.assertIn(args[0], ('/usr/bin/dpkg', '/usr/bin/dpkg-query'))
            if '-W' in args:
                return 'ii'
            self.assertTrue('-S' in args or '--search' in args, 'only mocked ownership lookup is permitted')
            return owner + ': ' + args[-1] + '\n'
        def read(path):
            logical = next((name for name, target in aliases.items() if target == str(path)), str(path))
            if read_observations is not None and logical in aliases:
                read_observations[logical] = read_observations.get(logical, 0) + 1
                if read_observations[logical] > 1:
                    return 'fastcgi_pass unix:/run/php/never-verified.sock;'
            return files[logical]
        with patch.object(Path, 'resolve', autospec=True, side_effect=resolve), \
             patch.object(Path, 'is_symlink', autospec=True, side_effect=lambda path: str(path) in aliases), \
             patch.object(M, 'safe_file', side_effect=lambda path, *unused: read(str(path)).encode()), \
             patch.object(M, 'command', side_effect=command), \
             patch.object(M, 'installed_vendor_file', side_effect=vendor_error) as proof:
            result = M.nginx_inventory(read=read,
                expand=lambda value: sorted(aliases) if value == '/etc/nginx/modules-enabled/*.conf' else [])
        return result, proof.call_args_list, native_calls

    def test_all_eight_distribution_module_aliases_are_read_but_never_route_edit_targets(self):
        result, proofs, native_calls = self.inspect_aliases()
        self.assertEqual(len(proofs), 16, 'prove both eight vendor configs and eight referenced module binaries')
        self.assertEqual(len(native_calls), 32, 'each proof checks owner and installed package status')
        for call in proofs:
            self.assertEqual(call.args[0], 'libnginx-mod-fixture')
            self.assertIn(Path(str(call.args[1])).parent,
                          (Path('/usr/share/nginx/modules-available'), Path('/usr/lib/nginx/modules')))
        self.assertTrue(all(route['file'].startswith('/etc/nginx/') for route in result['routes']))
        outputs = M.route_outputs(result['files'], result['routes'],
                                 {'/run/php/php7.4-fpm.sock': '/run/php/php8.5-fpm.sock'})
        self.assertEqual(set(outputs), {'/etc/nginx/nginx.conf'})
        self.assertFalse(any(path.startswith('/usr/share/') for path in outputs))

    def test_external_alias_admission_is_limited_to_immediate_vendor_module_directories(self):
        for logical, resolved in (
            ('/etc/nginx/sites-enabled/site.conf', '/usr/share/nginx/modules-available/mod-http-geoip.conf'),
            ('/etc/nginx/modules-enabled/nested/module.conf', '/usr/share/nginx/modules-available/mod-http-geoip.conf'),
            ('/etc/nginx/modules-enabled/50-module.conf', '/usr/share/nginx/modules-available/nested/mod-module.conf'),
            ('/etc/nginx/modules-enabled/50-module.conf', '/opt/nginx/mod-module.conf'),
            ('/etc/nginx/modules-enabled/50-module.conf', '/etc/passwd')):
            with self.subTest(logical=logical, resolved=resolved), self.assertRaises(M.Hold):
                self.inspect_aliases({logical: resolved})

    def test_vendor_module_fragments_cannot_introduce_routes_includes_or_other_directives(self):
        for fragment in ('fastcgi_pass unix:/run/php/php7.4-fpm.sock;',
                         'load_module modules/ngx_fixture_module.so; include /etc/nginx/other.conf;',
                         'server { listen 443 ssl; }', 'set $fixture arbitrary;'):
            with self.subTest(fragment=fragment), self.assertRaises(M.Hold):
                self.inspect_aliases(fragment=fragment)

    def test_unrelated_package_owner_and_changed_vendor_bytes_hold(self):
        with self.assertRaises(M.Hold):
            self.inspect_aliases(owner='unrelated-package')
        self.held('fixture_vendor_digest_mismatch', self.inspect_aliases,
                  vendor_error=M.Hold('fixture_vendor_digest_mismatch'))

    def test_outside_path_diagnostics_contain_paths_without_configuration_contents(self):
        logical = '/etc/nginx/sites-enabled/site.conf'
        resolved = '/opt/private/site.conf'
        with self.assertRaises(M.Hold) as caught:
            self.inspect_aliases({logical: resolved}, fragment='private content never returned')
        self.assertEqual(str(caught.exception), 'nginx_path_outside_config')
        self.assertEqual(caught.exception.details, {'logical_path': logical, 'resolved_path': resolved})

    def test_vendor_fragment_is_not_reread_or_revisited_after_validation(self):
        observations = {}
        result, _, _ = self.inspect_aliases(read_observations=observations)
        self.assertEqual(set(observations.values()), {1})
        self.assertFalse(any(route['socket'] == '/run/php/never-verified.sock' for route in result['routes']))
        for path in observations:
            self.assertEqual(result['files'][path], 'load_module modules/ngx_fixture_module.so;\n')


class PreflightArchiveFixtures(Offline):
    """Exercise real evidence validation and archive writes on temporary files.

    Owner metadata is fake root metadata; all bytes, permissions, renames,
    hashes, directory fsyncs and evidence preservation operate on private tempFS.
    Timer observations and host identity are mocked. No timer is changed.
    """
    def run_archive(self, mutation=None, partial_receipt=False):
        raw_old_core = old_core_fixture()
        with tempfile.TemporaryDirectory(prefix='php85-preflight-archive-') as temporary:
            actual_path_type = type(Path())
            class RootFixturePath(actual_path_type):
                def lstat(self):
                    observed = super().lstat()
                    values = {key: getattr(observed, key) for key in dir(observed) if key.startswith('st_')}
                    values['st_uid'] = 0
                    return SimpleNamespace(**values)
                def exists(self):
                    if str(self) == '/usr/sbin/policy-rc.d':
                        return False
                    return super().exists()
            base = RootFixturePath(temporary) / 'state'
            base.mkdir(mode=0o700)
            job = base / 'job-20261103T010203Z-0123abcd'
            job.mkdir(mode=0o700)
            raw_rows, previous_sha = [], '0' * 64
            phases = ['preflight', 'refreshing_indexes', 'failed_needs_review']
            if mutation == 'stage':
                phases[1] = 'installing_packages'
            if mutation == 'extra-stage':
                phases.append('cleanup_failed')
            for phase in phases:
                row = dict(time='2026-11-03T01:02:03Z', phase=phase, previous_sha256=previous_sha)
                if phase == 'failed_needs_review':
                    row.update(reason='nginx_path_outside_config', recovery=str(job / 'recovery.json'))
                    if mutation == 'event-extra-field':
                        row['source'] = '7.4'
                raw = M.encoded(row)
                previous_sha = M.digest(raw)
                raw_rows.append(raw)
            previous = dict(version='1.0.0', job=str(job), phase='failed_needs_review',
                event_sha256=previous_sha, reason='nginx_path_outside_config', recovery=str(job / 'recovery.json'))
            if mutation == 'version':
                previous['version'] = '1.0.1'
            if mutation == 'current-hash':
                previous['event_sha256'] = '9' * 64
            timers = ['apt-daily.timer']
            if mutation == 'timer-receipt':
                timers *= 2
            old_files = {'php85_upgrade.py': raw_old_core,
                         'events.jsonl': b''.join(raw_rows), 'timers.json': M.encoded(timers)}
            if mutation == 'old-code':
                old_files['php85_upgrade.py'] += b'\n# altered fixture\n'
            if mutation == 'broken-chain':
                altered = json.loads(raw_rows[1])
                altered['previous_sha256'] = '8' * 64
                old_files['events.jsonl'] = raw_rows[0] + M.encoded(altered) + b''.join(raw_rows[2:])
            if mutation == 'extra-artifact':
                old_files['plan.json'] = b'{"not_a_preflight_only_job":true}\n'
            for name, raw in old_files.items():
                path = job / name
                path.write_bytes(raw)
                path.chmod(0o600)
            raw_current = M.encoded(previous)
            current = base / 'current.json'
            current.write_bytes(raw_current if mutation != 'current-file-drift' else b'{}\n')
            current.chmod(0o600)
            if partial_receipt:
                receipt = base / ('preflight-recovery-' + job.name + '.json')
                receipt.write_bytes(M.encoded(dict(schema=1, phase='started')))
                receipt.chmod(0o600)
            observations = []
            def subprocess(args, *unused, **kwargs):
                observations.append(args)
                self.assertEqual(args[:3], ['/bin/systemctl', 'is-active', '--quiet'])
                active = args[-1] == 'apt-daily.timer' and mutation != 'timer-not-restored'
                return SimpleNamespace(returncode=0 if active else 3)
            def read(path, private=False):
                path = RootFixturePath(path)
                self.assertTrue(base in path.parents, 'archive fixture filesystem escape: ' + str(path))
                if private and path.stat().st_mode & 0o077:
                    raise M.Hold('private_file_required')
                return path.read_bytes()
            error = None
            with patch.object(M, 'BASE', base), patch.object(M, 'Path', RootFixturePath), \
                 patch.object(M, 'safe_file', side_effect=read), patch.object(M, 'identity', return_value=HOST), \
                 patch.object(M.subprocess, 'run', side_effect=subprocess), contextlib.redirect_stdout(io.StringIO()):
                try:
                    M.verify_preflight_archive_journals()
                    M.recover_v100_preflight(previous)
                    M.verify_preflight_archive_journals()
                except M.Hold as failure:
                    error = str(failure)
            old_preserved = {path.name: path.read_bytes() for path in job.iterdir()}
            archives = list(base.glob('archived-preflight-*.json'))
            receipts = list(base.glob('preflight-recovery-*.json'))
            return dict(error=error, old_files=old_files, preserved=old_preserved,
                archive_bytes=[path.read_bytes() for path in archives], current_bytes=raw_current,
                current_exists=current.exists(), observations=observations,
                receipts=[json.loads(path.read_bytes()) for path in receipts])

    def test_exact_old_preflight_archives_current_and_preserves_every_old_file_byte(self):
        result = self.run_archive()
        self.assertIsNone(result['error'])
        self.assertEqual(result['preserved'], result['old_files'])
        self.assertEqual(result['archive_bytes'], [result['current_bytes']])
        self.assertFalse(result['current_exists'])
        self.assertEqual(result['receipts'][0]['phase'], 'complete')
        self.assertFalse(result['receipts'][0]['old_PHP_package_stage_started'])
        self.assertEqual(result['receipts'][0]['historical_host_binding'], 'not_persisted_in_v1_0_0_preflight')
        self.assertEqual(len(result['observations']), 2)

    def test_modified_code_added_work_and_nonpreflight_stages_are_never_archived(self):
        for mutation, reason in (
            ('old-code', 'unrecognized_preflight_code'),
            ('extra-artifact', 'preflight_has_unrecognized_work_artifacts'),
            ('stage', 'preflight_stage_or_current_mismatch'),
            ('extra-stage', 'preflight_journal_has_other_stages'),
            ('event-extra-field', 'unexpected_preflight_event_fields'),
            ('version', 'previous_job_preserved_use_status')):
            with self.subTest(mutation=mutation):
                result = self.run_archive(mutation)
                self.assertEqual(result['error'], reason)
                self.assertTrue(result['current_exists'])
                self.assertEqual(result['preserved'], result['old_files'])
                self.assertEqual(result['archive_bytes'], [])

    def test_broken_chain_current_binding_or_unrestored_timers_block_archival(self):
        for mutation, reason in (
            ('broken-chain', 'preflight_event_chain_changed'),
            ('current-hash', 'preflight_stage_or_current_mismatch'),
            ('current-file-drift', 'preflight_current_changed'),
            ('timer-receipt', 'preflight_timer_receipt_invalid'),
            ('timer-not-restored', 'preflight_timers_not_restored')):
            with self.subTest(mutation=mutation):
                result = self.run_archive(mutation)
                self.assertEqual(result['error'], reason)
                self.assertTrue(result['current_exists'])
                self.assertEqual(result['preserved'], result['old_files'])
                self.assertEqual(result['archive_bytes'], [])

    def test_partial_archive_receipt_blocks_before_retry_or_any_timer_observation(self):
        result = self.run_archive(partial_receipt=True)
        self.assertEqual(result['error'], 'unfinished_preflight_archive_preserved')
        self.assertEqual(result['observations'], [])
        self.assertTrue(result['current_exists'])
        self.assertEqual(result['preserved'], result['old_files'])


class PoolFixtures(Offline):
    def test_duplicate_scalar_listener_uses_last_and_preserves_arrays(self):
        text = ('[www]\nuser = forge\ngroup = forge\nlisten = /run/php/obsolete.sock\n'
            'listen = /var/run/php/custom.sock ; last wins\nlisten.mode = 0666\n'
            'env[FIRST] = one\nenv[SECOND] = two\nphp_admin_value[memory_limit] = 512M\n')
        texts = {'/etc/php/7.4/fpm/pool.d/www.conf': text}
        pools = M.parse_pools(texts)
        self.assertEqual(pools['www']['listen'], '/run/php/custom.sock')
        output = M.pool_outputs(texts, pools, {'/run/php/custom.sock': '/run/php/php8.5-custom.sock'})['www.conf']
        self.assertEqual(output.count('listen = /run/php/php8.5-custom.sock'), 2)
        self.assertIn('env[FIRST] = one\nenv[SECOND] = two\n', output)
        self.assertIn('php_admin_value[memory_limit] = 512M\n', output)

    def test_multiple_pools_map_distinct_custom_sockets(self):
        texts = {'/etc/php/7.4/fpm/pool.d/a.conf': '[a]\nlisten = /run/php/a.sock\n',
                 '/etc/php/7.4/fpm/pool.d/b.conf': '[b]\nlisten = /run/php/b.sock\n'}
        pools = M.parse_pools(texts)
        mapping = {row['listen']: '/run/php/php8.5-' + name + '.sock' for name, row in pools.items()}
        output = M.pool_outputs(texts, pools, mapping)
        self.assertIn('/run/php/php8.5-a.sock', output['a.conf'])
        self.assertIn('/run/php/php8.5-b.sock', output['b.conf'])

    def test_duplicate_section_socket_missing_listener_and_loader_hold(self):
        examples = (
            ('[a]\nlisten=/run/php/a.sock\n[a]\nlisten=/run/php/b.sock\n', 'duplicate_or_global_pool'),
            ('[a]\nlisten=/run/php/a.sock\n[b]\nlisten=/run/php/a.sock\n', 'duplicate_pool_socket'),
            ('[a]\nuser=forge\n', 'pool_listener_missing'),
            ('listen=/run/php/a.sock\n', 'unscoped_pool_listener'),
            ('[a]\nlisten=/run/php/a.sock\ninclude=/tmp/other.conf\n', 'custom_pool_include_or_loader'),
            ('[a]\nlisten=/run/php/a.sock\nphp_admin_value[extension_dir]=/old\n', 'custom_pool_include_or_loader'))
        for text, reason in examples:
            with self.subTest(reason=reason):
                self.held(reason, M.parse_pools, {'a.conf': text})


class IniFixtures(Offline):
    def render(self, old_values=None, target_values=None, settings=None, old_modules=None, target_modules=None):
        old = dict(ini=old_values or {}, modules=old_modules or ['Core', 'mysqli'])
        target = dict(ini=target_values if target_values is not None else old['ini'],
                      modules=target_modules or ['Core', 'mysqli', 'Zend OPcache'])
        return M.ini_output(old, target, settings or {'php.ini': ''})

    def test_values_are_escaped_and_only_explicit_values_migrate(self):
        value = 'C:\\private\\a"b;$variable'
        output = self.render({'error_log': value, 'memory_limit': '512M', 'implicit': 'do not copy'},
            settings={'php.ini': 'error_log=old\nmemory_limit=512M\n; implicit=old\n'})
        self.assertIn('error_log="C:\\\\private\\\\a\\"b;\\$variable"\n', output)
        self.assertIn('memory_limit="512M"\n', output)
        self.assertNotIn('implicit=', output)

    def test_old_extension_loaders_never_copy(self):
        output = self.render({'extension_dir': '/usr/lib/php/20190902'},
            settings={'php.ini': 'extension_dir=/usr/lib/php/20190902\nextension=old.so\nzend_extension=opcache.so\n'})
        self.assertEqual(output, '; Preserved settings; PHP 8.5 owns its extension loaders.\n')

    def test_removed_defaults_skip_but_custom_values_hold(self):
        self.assertNotIn('track_errors=', self.render({'track_errors': '0'}, {}, {'php.ini': 'track_errors=0\n'}))
        self.held('removed_nondefault_INI_setting', self.render,
                  {'track_errors': '1'}, {}, {'php.ini': 'track_errors=1\n'})
        self.held('removed_nondefault_INI_setting', self.render,
                  {'unsupported_custom': '1'}, {}, {'php.ini': 'unsupported_custom=1\n'})

    def test_missing_extension_or_stale_paths_hold(self):
        self.held('target_extension_parity_failed', self.render,
                  old_modules=['Core', 'redis'], target_modules=['Core'])
        for value in ('/etc/php/7.4/x', '/usr/bin/php8.2', '/usr/lib/php/20190902/custom'):
            with self.subTest(value=value):
                self.held('legacy_PHP_path_in_setting', self.render, {'session.save_path': value},
                          settings={'php.ini': 'session.save_path=custom\n'})

    def test_multiline_and_per_directory_settings_hold(self):
        for value in ('a\nb', 'a\rb', 'a\x00b'):
            with self.subTest(value=repr(value)):
                self.held('multiline_INI_value', self.render, {'error_log': value},
                          settings={'php.ini': 'error_log=x\n'})
        self.held('per_directory_INI_profile_required', self.render,
                  settings={'php.ini': '[PATH=/srv/site]\nmemory_limit=512M\n'})

    def test_effective_nonempty_prepend_cannot_hide_behind_earlier_empty_value(self):
        self.held('application_preload_prepend_or_basedir_requires_review', self.render,
            {'auto_prepend_file': '/srv/bootstrap.php'},
            settings={'php.ini': 'auto_prepend_file=""\n',
                      '99-app.ini': 'auto_prepend_file=/srv/bootstrap.php\n'})

    def test_later_empty_prepend_allows_migration_and_never_copies_bootstrap(self):
        output = self.render({'auto_prepend_file': ''}, settings={
            'php.ini': 'auto_prepend_file=/srv/disabled-bootstrap.php\n',
            '99-app.ini': 'auto_prepend_file=""\n'})
        self.assertNotIn('auto_prepend_file=', output)

    def test_preload_basedir_and_environment_interpolation_hold(self):
        for key in ('opcache.preload', 'opcache.preload_user', 'open_basedir'):
            with self.subTest(key=key):
                self.held('application_preload_prepend_or_basedir_requires_review', self.render,
                          settings={'php.ini': key + '=/srv/custom\n'})
        self.held('environment_interpolated_INI_requires_review', self.render,
                  settings={'php.ini': 'session.save_path=${PRIVATE_PATH}\n'})

    def test_configuration_mode_intersection_never_broadens_private_settings(self):
        self.assertEqual(M.merged_mode([{'mode': 0o644, 'gid': 0}, {'mode': 0o600, 'gid': 0}]), (0o600, 0))
        self.assertEqual(M.merged_mode([{'mode': 0o644, 'gid': 0}, {'mode': 0o640, 'gid': 33}]), (0o640, 33))
        self.held('mixed_private_INI_groups_require_review', M.merged_mode,
                  [{'mode': 0o640, 'gid': 33}, {'mode': 0o640, 'gid': 44}])

    def test_fpm_global_preserves_limits_and_maps_only_native_pid_log_include(self):
        text = ('[global]\n; keep comment\npid = /run/php/php7.4-fpm.pid\n'
                'error_log = /var/log/php7.4-fpm.log\nprocess.max = 37\n'
                'emergency_restart_threshold = 9\nlog_level = warning\n'
                'include = /etc/php/7.4/fpm/pool.d/*.conf\n')
        output = M.global_FPM_output(text, '7.4')
        self.assertEqual(output, text.replace('/run/php/php7.4-', '/run/php/php8.5-')
            .replace('/var/log/php7.4-', '/var/log/php8.5-').replace('/etc/php/7.4/', '/etc/php/8.5/'))
        self.held('unsupported_FPM_global_setting', M.global_FPM_output, text + 'custom=unsafe\n', '7.4')
        self.held('custom_FPM_PID_requires_review', M.global_FPM_output, text.replace('/run/php/php7.4-fpm.pid', '/tmp/private.pid'), '7.4')


class CandidateFixtures(Offline):
    def test_newer_same_branch_candidate_and_now_origin_are_allowed(self):
        item = package(origins=[origin(), origin(trusted=False, origin='', archive='now', site='')])
        result = M.candidate({'php8.5-cli': item}, 'php8.5-cli', HOST)
        self.assertEqual(result['version'], VERSION)
        self.assertEqual(len(result['origins']), 1)

    def test_foreign_untrusted_wrong_arch_and_missing_digest_hold(self):
        for kwargs, reason in (
            ({'origins': [origin(trusted=False)]}, 'authenticated_Jammy_candidate_required'),
            ({'origins': [origin(archive='noble')]}, 'authenticated_Jammy_candidate_required'),
            ({'origins': [origin(site='evil.example')]}, 'authenticated_Jammy_candidate_required'),
            ({'architecture': 'arm64'}, 'candidate_architecture_mismatch'),
            ({'record': {'SHA256': 'bad', 'Filename': 'pool/pkg.deb'}}, 'candidate_archive_SHA_missing'),
            ({'record': {'SHA256': 'a' * 64, 'Filename': '../pkg.deb'}}, 'candidate_archive_path_invalid'),
            ({'version': '8.5.11-1+ubuntu22.04.1'}, 'patched_8_5_core_candidate_required'),
            ({'source_name': 'wrong'}, 'patched_8_5_core_candidate_required')):
            with self.subTest(reason=reason, kwargs=kwargs):
                self.held(reason, M.candidate, {'php8.5-cli': package(**kwargs)}, 'php8.5-cli', HOST)

    def test_only_now_and_missing_candidates_hold(self):
        self.held('authenticated_Jammy_candidate_required', M.candidate,
                  {'php8.5-cli': package(origins=[origin(archive='now')])}, 'php8.5-cli', HOST)
        self.held('candidate_missing_php8.5-cli', M.candidate, {}, 'php8.5-cli', HOST)

    def test_simulation_rejects_removal_protected_and_old_version_drift(self):
        for text, reason in (
            ('Remv php7.4-fpm [7.4.33]', 'package_removal_forbidden'),
            ('Purg something [1.0]', 'package_removal_forbidden'),
            ('Inst nginx [1.0.0] (2.0.0 Ubuntu:22.04 [amd64])', 'protected_package_change'),
            ('Inst php7.4-fpm [7.4.33] (7.4.34 PPA [amd64])', 'protected_package_change'),
            ('Inst php8.5-cli [8.5.11] (' + VERSION + ' PPA [amd64])', 'APT_old_version_mismatch')):
            with self.subTest(text=text):
                self.held(reason, M.simulated_changes, text,
                    {'php8.5-cli': {'version': '8.5.12', 'architecture': 'amd64'}},
                    {'php8.5-cli': package()}, HOST)

    def test_simulation_records_exact_candidate_and_rejects_duplicates(self):
        line = 'Inst php8.5-cli (' + VERSION + ' PPA [amd64])\n'
        result = M.simulated_changes(line, {}, {'php8.5-cli': package()}, HOST)
        self.assertEqual(result['php8.5-cli']['old'], '-')
        self.assertEqual(result['php8.5-cli']['sha256'], 'a' * 64)
        self.held('APT_old_version_mismatch', M.simulated_changes, line + line,
                  {}, {'php8.5-cli': package()}, HOST)


class AptHookFixtures(Offline):
    archive = '/var/cache/apt/archives/php8.5-cli_fixture_amd64.deb'

    def execute(self, actions=None, changes=None, raw=b'fixture archive', actual=None,
                header='VERSION 2\nfixture=1\n\n', baseline=None, installed=None):
        record = dict(old='-', version=VERSION, architecture='amd64', sha256=M.digest(b'fixture archive'))
        baseline = baseline or {}
        plan = dict(code_sha256=M.digest(Path(M.__file__).read_bytes()), host=HOST, sources={}, packages=baseline,
                    changes=changes if changes is not None else {'php8.5-cli': record})
        plan_path = '/fixture/job/plan.json'
        plan_bytes = M.encoded(plan)
        actions = actions if actions is not None else ['php8.5-cli - < ' + VERSION + ' ' + self.archive]
        files = {plan_path: plan_bytes, self.archive: raw}
        writes = []
        def command(args, *unused, **kwargs):
            if args[0] == '/usr/bin/dpkg-query':
                return installed if installed is not None else ''.join(
                    name + '\t' + row['version'] + '\t' + row['architecture'] + '\tii \n'
                    for name, row in baseline.items())
            self.assertEqual(args[:2], ['/usr/bin/dpkg-deb', '-f'])
            return actual or 'Package: php8.5-cli\nVersion: ' + VERSION + '\nArchitecture: amd64\n'
        with patch.object(M, 'safe_file', side_effect=lambda path, *args: files[str(path)]), \
             patch.object(M, 'identity', return_value=HOST), \
             patch.object(M, 'source_files', return_value={}), \
             patch.object(M, 'command', side_effect=command), \
             patch.object(M, 'atomic', side_effect=lambda path, value: writes.append((str(path), value))), \
             patch.object(M.sys, 'stdin', io.StringIO(header + '\n'.join(actions) + '\n')):
            M.hook(plan_path)
        return writes, plan_bytes

    def test_exact_archive_and_configure_records_produce_bound_proof(self):
        actions = ['php8.5-cli - < ' + VERSION + ' ' + self.archive,
                   'php8.5-cli - < ' + VERSION + ' **CONFIGURE**']
        writes, plan_bytes = self.execute(actions)
        self.assertEqual(writes[0][0], '/fixture/job/hook-accepted.json')
        self.assertEqual(json.loads(writes[0][1]), {'plan_sha256': M.digest(plan_bytes), 'accepted': True})

    def test_no_extra_unplanned_package_or_archive_is_accepted(self):
        good = 'php8.5-cli - < ' + VERSION + ' ' + self.archive
        self.held('unplanned_APT_action', self.execute, [good, 'nginx - < 1.0 **CONFIGURE**'])
        self.held('APT_archive_digest_mismatch', self.execute, [good, good])
        self.held('actual_APT_transaction_changed', self.execute, [])

    def test_changed_bytes_archive_identity_or_version_holds(self):
        self.held('APT_archive_digest_mismatch', self.execute, raw=b'altered')
        self.held('APT_archive_identity_mismatch', self.execute,
            actual='Package: php8.5-cli\nVersion: ' + VERSION + '\nArchitecture: arm64\n')
        self.held('APT_versions_changed', self.execute,
            ['php8.5-cli - < 8.5.99 ' + self.archive])
        self.held('unsafe_APT_archive_path', self.execute,
            ['php8.5-cli - < ' + VERSION + ' /tmp/archive.deb'])

    def test_bad_protocol_or_downgrade_holds(self):
        self.held('APT_v2_hook_required', self.execute, header='VERSION 1\n\n')
        self.held('bad_APT_hook_action', self.execute, ['not five fields'])
        self.held('APT_versions_changed', self.execute,
            ['php8.5-cli - > ' + VERSION + ' ' + self.archive])

    def test_locked_inventory_rejects_unplanned_and_untouched_package_drift(self):
        self.held('unplanned_package_under_APT_lock', self.execute,
                  installed='unexpected\t1.0\tamd64\tii \n')
        baseline = {'nginx': dict(version='1.20', architecture='amd64')}
        self.held('untouched_package_drift_under_APT_lock', self.execute, baseline=baseline,
                  installed='nginx\t1.21\tamd64\tii \n')
        self.held('untouched_package_drift_under_APT_lock', self.execute, baseline=baseline, installed='')
        self.execute(baseline=baseline)

    def test_duplicate_configure_and_changed_planned_inventory_hold(self):
        archive = 'php8.5-cli - < ' + VERSION + ' ' + self.archive
        configure = 'php8.5-cli - < ' + VERSION + ' **CONFIGURE**'
        self.held('duplicate_APT_configure_action', self.execute, [archive, configure, configure])
        self.held('planned_package_drift_under_APT_lock', self.execute,
                  installed='php8.5-cli\t8.5.99\tamd64\tii \n')


class ProfileFixtures(Offline):
    def inspect_fixture(self, branch='7.4', extra_packages=None, selected=None,
                        route_sockets=None, add_custom_pool=False, configuration_dump=None,
                        authentication_override=False, discovery_drift=False):
        names = ['php' + branch + '-' + suffix for suffix in ('cli', 'common', 'fpm')]
        old_version = '8.5.12' if branch == '8.5' else branch + '.33'
        before = {name: dict(version=old_version, architecture='amd64') for name in names}
        before.update(extra_packages or {})
        listener = '/run/php/php' + branch + '-fpm.sock'
        pool_path = '/etc/php/' + branch + '/fpm/pool.d/www.conf'
        pool_text = '[www]\nuser=forge\ngroup=forge\nlisten=' + listener + '\nlisten.mode=0666\n'
        if add_custom_pool:
            pool_text += '[custom]\nuser=forge\ngroup=forge\nlisten=/run/php/tenant.sock\n'
        source_config = '/etc/php/' + branch + '/fpm/php-fpm.conf'
        source_ini = '/etc/php/' + branch + '/fpm/php.ini'
        source_cli_ini = '/etc/php/' + branch + '/cli/php.ini'
        files = {pool_path: pool_text,
                 source_config: 'include = /etc/php/' + branch + '/fpm/pool.d/*.conf\n',
                 source_ini: 'memory_limit=512M\n', source_cli_ini: 'memory_limit=-1\n'}
        nginx = dict(files={'/etc/nginx/nginx.conf': 'http {}'},
            routes=[dict(file='/etc/nginx/nginx.conf', start=0, end=0, socket=s)
                    for s in (route_sockets or [listener] + (['/run/php/tenant.sock'] if add_custom_pool else []))],
            health=[dict(host='example.com', path='/', aliases=['example.com'])])
        cache = {'php8.5-' + suffix: package() for suffix in ('cli', 'common', 'fpm')}
        commands = []
        def command(args, *unused, **kwargs):
            commands.append(args)
            if args[:2] == ['/usr/sbin/nginx', '-T']:
                return configuration_dump if configuration_dump is not None else '# configuration file /etc/nginx/nginx.conf:\n'
            if args[0] == '/usr/bin/php':
                return selected or branch
            if args[:2] == ['/usr/bin/apt-get', '--simulate']:
                return ''.join('Inst ' + name + (' [' + before[name]['version'] + ']' if name in before else '')
                    + ' (' + VERSION + ' PPA [amd64])\n' for name in sorted(cache))
            if args[:2] == ['/usr/sbin/nginx', '-t'] or args[:2] == ['/bin/systemctl', 'is-active']:
                return ''
            raise AssertionError('unexpected mocked command ' + repr(args))
        def expand(pattern):
            if pattern == '/etc/php/' + branch + '/fpm/pool.d/*.conf':
                return [pool_path]
            return []
        def snapshot(paths):
            captured = dict(files, **nginx['files'])
            return {str(path): {'sha256': '0' * 64 if discovery_drift and str(path) == pool_path else
                M.digest(captured.get(str(path), 'fixture native unit').encode())} for path in paths}
        apt = SimpleNamespace(Cache=lambda: cache)
        apt_pkg = SimpleNamespace(init=lambda: None,
            config=SimpleNamespace(find_b=lambda key, default: authentication_override))
        registry = dict(version=old_version, directory='/usr/lib/php/fixture',
                        modules=['Core'], ini={'memory_limit': '512M'})
        original_resolve = Path.resolve
        def resolve(path, *args, **kwargs):
            if str(path) == '/usr/bin/php':
                return Path('/usr/bin/php' + (selected or branch))
            if re.fullmatch(r'/usr/bin/php[0-9]+\.[0-9]+', str(path)):
                return path
            return original_resolve(path, *args, **kwargs)
        with contextlib.ExitStack() as stack:
            for name, value in (('identity', HOST), ('packages', before), ('source_files', {}),
                ('nginx_inventory', nginx), ('registry', registry), ('verify_PPA_signature', []),
                ('validate_apt_security', True)):
                stack.enter_context(patch.object(M, name, return_value=value))
            stack.enter_context(patch.dict('sys.modules', {'apt': apt, 'apt_pkg': apt_pkg}))
            stack.enter_context(patch.object(M, 'command', side_effect=command))
            stack.enter_context(patch.object(M.glob, 'glob', side_effect=expand))
            stack.enter_context(patch.object(M, 'safe_file', side_effect=lambda path, *args: files[str(path)].encode()))
            stack.enter_context(patch.object(M, 'files_snapshot', side_effect=snapshot))
            stack.enter_context(patch.object(Path, 'resolve', autospec=True, side_effect=resolve))
            stack.enter_context(patch.object(M, 'validate_native_unit',
                return_value='/lib/systemd/system/php' + branch + '-fpm.service'))
            stack.enter_context(patch.object(M, 'validate_loaders', return_value=None))
            stack.enter_context(patch.object(M, 'unit_enabled', return_value=True))
            health = stack.enter_context(patch.object(M, 'health'))
            result = M.inspect()
        return result, commands, health

    def test_supported_source_branches_and_custom_unix_mapping(self):
        for branch in ('7.2', '7.3', '7.4', '8.0', '8.1', '8.2', '8.3', '8.4'):
            with self.subTest(branch=branch):
                plan, commands, health = self.inspect_fixture(branch=branch, add_custom_pool=True)
                self.assertEqual(plan['mode'], 'migration')
                self.assertEqual(plan['socket_map']['/run/php/php' + branch + '-fpm.sock'], '/run/php/php8.5-fpm.sock')
                custom = '/run/php/php8.5-' + M.digest(b'/run/php/tenant.sock')[:12] + '.sock'
                self.assertEqual(plan['socket_map']['/run/php/tenant.sock'], custom)
                self.assertEqual(set(plan['target_records']), {'php8.5-cli', 'php8.5-common', 'php8.5-fpm'})
                health.assert_called_once()
                self.assertTrue(all('--simulate' in args for args in commands if args[0] == '/usr/bin/apt-get'))

    def test_existing_85_profile_is_patch_with_unchanged_socket(self):
        plan, _, _ = self.inspect_fixture(branch='8.5')
        self.assertEqual(plan['mode'], 'patch')
        self.assertEqual(plan['socket_map'], {'/run/php/php8.5-fpm.sock': '/run/php/php8.5-fpm.sock'})

    def test_cli_dormant_target_apache_cgi_and_unowned_route_hold(self):
        for kwargs, reason in (
            ({'selected': '8.4'}, 'CLI_and_web_PHP_branch_diverge'),
            ({'extra_packages': {'php8.5-cli': {'version': VERSION}}}, 'existing_dormant_target_requires_review'),
            ({'extra_packages': {'libapache2-mod-php7.4': {'version': '7.4.33'}}}, 'Apache_CGI_separate_profile_required'),
            ({'extra_packages': {'php7.4-cgi': {'version': '7.4.33'}}}, 'Apache_CGI_separate_profile_required'),
            ({'route_sockets': ['/run/php/php7.4-fpm.sock', '/run/php/unowned.sock']}, 'unowned_PHP_socket_route')):
            with self.subTest(reason=reason):
                self.held(reason, self.inspect_fixture, **kwargs)

    def test_dumped_include_graph_and_apt_authentication_guards(self):
        self.held('Nginx_include_graph_mismatch', self.inspect_fixture,
                  configuration_dump='# configuration file /etc/nginx/unknown.conf:\n')
        self.held('APT_authentication_override', self.inspect_fixture, authentication_override=True)

    def test_discovery_read_bytes_must_match_sealed_configuration_snapshot(self):
        self.held('configuration_changed_during_discovery', self.inspect_fixture, discovery_drift=True)


class ApplyFixtures(Offline):
    """Execute orchestration against a private temporary filesystem and fake services.

    Every absolute system path is translated before filesystem access. Native
    processes, APT locks, ownership changes, time delays and runtime connections
    are mocked; the actual orchestration/journal/configuration transformations run.
    """
    def run_apply(self, mode='migration', web_failure=False, package_drift=False, rollback_request=False,
                  source_enabled=True, patch_changes=False, alternative_status='auto',
                  target_injection=None, patched_setting_drift=None, previous_preflight=False):
        with tempfile.TemporaryDirectory(prefix='php85-orchestration-') as directory:
            physical_root = Path(directory)
            actual_core = Path(M.__file__)
            actual_os_open = M.os.open
            branch = '7.4' if mode == 'migration' else '8.5'
            writes, commands, ownership = [], [], []
            installed = False
            saved_metadata = {}
            health_calls = []
            runtime_calls = []
            registry_calls, loader_calls, unit_calls = [], [], []

            class FakePath:
                def __init__(self, value):
                    self.logical = value.logical if isinstance(value, FakePath) else Path(value)
                def physical(self):
                    return physical_root / str(self.logical).lstrip('/')
                def __str__(self): return str(self.logical)
                def __fspath__(self): return str(self.logical)
                def __eq__(self, other): return isinstance(other, FakePath) and self.logical == other.logical
                def __hash__(self): return hash(self.logical)
                def __truediv__(self, value): return FakePath(self.logical / value)
                @property
                def name(self): return self.logical.name
                @property
                def parent(self): return FakePath(self.logical.parent)
                def mkdir(self, *args, **kwargs):
                    kwargs['parents'] = True
                    return self.physical().mkdir(*args, **kwargs)
                def stat(self):
                    physical = FakePath('/usr/sbin/php-fpm8.5').physical() if str(self) == '/proc/1234/exe' else self.physical()
                    info = physical.stat()
                    values = {name: getattr(info, name) for name in dir(info) if name.startswith('st_')}
                    values['st_uid'] = 0
                    if str(self).startswith('/run/php/') and str(self).endswith('.sock'):
                        values['st_mode'] = stat.S_IFSOCK | 0o660
                    return SimpleNamespace(**values)
                lstat = stat
                def exists(self): return self.physical().exists()
                def is_symlink(self): return self.physical().is_symlink()
                def is_file(self): return self.physical().is_file()
                def resolve(self, *args, **kwargs): return self
                def glob(self, pattern):
                    return [FakePath('/' + str(p.relative_to(physical_root))) for p in self.physical().glob(pattern)]
                def iterdir(self):
                    return [FakePath(self.logical / p.name) for p in self.physical().iterdir()]
                def open(self, *args, **kwargs): return self.physical().open(*args, **kwargs)
                def read_bytes(self):
                    if self.logical == actual_core:
                        return actual_core.read_bytes()
                    return self.physical().read_bytes()
                def read_text(self, *args, **kwargs): return self.read_bytes().decode()
                def write_bytes(self, raw):
                    self.physical().parent.mkdir(parents=True, exist_ok=True)
                    return self.physical().write_bytes(raw)
                def chmod(self, mode): return self.physical().chmod(mode)
                def rename(self, destination):
                    destination = FakePath(destination)
                    destination.physical().parent.mkdir(parents=True, exist_ok=True)
                    self.physical().rename(destination.physical())
                    return destination
                def unlink(self, *args, **kwargs): return self.physical().unlink(*args, **kwargs)

            def write(path, raw, mode=0o600):
                path = FakePath(path)
                raw = raw.encode() if isinstance(raw, str) else raw
                path.write_bytes(raw)
                path.chmod(mode)
                writes.append((str(path), raw, mode))

            def snapshot(paths):
                result = {}
                for name in paths:
                    path = FakePath(name)
                    metadata = saved_metadata.get(str(path), {'uid': 0, 'gid': 0, 'mode': 0o600})
                    result[str(path)] = dict(metadata, sha256=M.digest(path.read_bytes()), link=None,
                                             resolved=str(path), link_uid=0, link_inode=None)
                return result

            def seed(path, content, mode=0o640, gid=33):
                write(path, content, mode)
                saved_metadata[path] = dict(uid=0, gid=gid, mode=mode)

            site = '/etc/nginx/sites-enabled/site.conf'
            old_socket = '/run/php/php' + branch + '-fpm.sock'
            operand = 'unix:' + old_socket
            nginx_text = 'server { fastcgi_pass ' + operand + '; }\n'
            seed(site, nginx_text)
            pool = '/etc/php/' + branch + '/fpm/pool.d/www.conf'
            pool_text = ('[www]\nuser=forge\ngroup=forge\nlisten=' + old_socket + '\n'
                         'listen.mode=0666\nenv[PRIVATE_TOKEN]=fixture-only-value\n'
                         '[unused]\nuser=forge\ngroup=forge\nlisten=/run/php/unused.sock\n')
            seed(pool, pool_text)
            global_path = '/etc/php/' + branch + '/fpm/php-fpm.conf'
            global_text = ('[global]\npid=/run/php/php' + branch + '-fpm.pid\n'
                           'process.max=23\ninclude=/etc/php/' + branch + '/fpm/pool.d/*.conf\n')
            seed(global_path, global_text)
            unit_path = '/lib/systemd/system/php' + branch + '-fpm.service'
            seed(unit_path, '[Service]\nExecStart=/usr/sbin/php-fpm' + branch + '\n', 0o644, 0)
            ini_files = {}
            for sapi, value, permission in (('fpm', '512M', 0o600), ('cli', '-1', 0o640)):
                path = '/etc/php/' + branch + '/' + sapi + '/php.ini'
                ini_files[sapi] = {path: 'memory_limit=' + value + '\n'}
                seed(path, ini_files[sapi][path], permission)
            if mode == 'migration':
                seed('/etc/php/8.5/fpm/pool.d/www.conf', '[www]\nlisten=/run/php/php8.5-fpm.sock\n')
                seed('/etc/php/8.5/fpm/php-fpm.conf', '[global]\ninclude=/etc/php/8.5/fpm/pool.d/*.conf\n')
                for sapi in ('cli', 'fpm'):
                    seed('/etc/php/8.5/' + sapi + '/php.ini', 'memory_limit=128M\n', 0o644, 0)
            if target_injection:
                sapi, text = target_injection
                seed('/etc/php/8.5/' + sapi + '/conf.d/99-retained.ini', text)
            for name in ('php', 'phar'):
                seed('/usr/bin/' + name + '8.5', 'fixture binary', 0o755, 0)
            seed('/usr/sbin/php-fpm8.5', 'fixture FPM binary', 0o755, 0)
            # Policy parent exists, but no live policy file is read or modified.
            FakePath('/usr/sbin').mkdir(exist_ok=True)
            target_names = ['php8.5-' + suffix for suffix in ('cli', 'common', 'fpm')]
            before = {'php' + branch + '-' + suffix: dict(version=('8.5.12' if patch_changes else '8.5.13') if branch == '8.5' else '7.4.33', architecture='amd64')
                      for suffix in ('cli', 'common', 'fpm')}
            before['nginx'] = dict(version='1.20.0', architecture='amd64')
            records = {name: dict(version='8.5.13', architecture='amd64', old='-') for name in target_names}
            if patch_changes:
                for name, record in records.items():
                    record['old'] = before[name]['version']
            changes = records if mode == 'migration' or patch_changes else {}
            after = dict(before, **{name: dict(version=row['version'], architecture=row['architecture']) for name, row in changes.items()})
            if package_drift:
                after['nginx'] = dict(version='1.21.0', architecture='amd64')
            mapping = {old_socket: '/run/php/php8.5-fpm.sock', '/run/php/unused.sock': '/run/php/php8.5-unused.sock'}
            if mode == 'patch':
                mapping = {value: value for value in (old_socket, '/run/php/unused.sock')}
            for socket in mapping.values():
                seed(socket, 'fixture socket placeholder', 0o600, 0)
            nginx = dict(files={site: nginx_text}, routes=[dict(file=site, start=nginx_text.index(operand),
                end=nginx_text.index(operand) + len(operand), socket=old_socket)],
                health=[dict(host='example.com', path='/', aliases=['example.com'])])
            source_registry = dict(version='7.4.33', directory='/usr/lib/php/old', modules=['Core'], ini={'memory_limit': '512M'})
            cli_registry = dict(source_registry, ini={'memory_limit': '-1'})
            config_names = [site, pool, global_path, unit_path] + [path for values in ini_files.values() for path in values]
            plan = dict(host=HOST, source_branch=branch, mode=mode, packages=before, changes=changes,
                files=snapshot(config_names), sources={}, nginx=nginx, pools={pool: pool_text},
                parsed_pools=M.parse_pools({pool: pool_text}), socket_map=mapping,
                source_registry=source_registry, source_CLI_registry=cli_registry, INI_files=ini_files,
                target_global_FPM=M.global_FPM_output(global_text, branch), target_records=records,
                pins=[name + '=8.5.13' for name in target_names], code_sha256=M.digest(actual_core.read_bytes()),
                source_enabled=source_enabled)
            writes.clear()
            base = FakePath('/var/lib/ubuntu-php85-upgrade')
            previous_bytes, previous_files, previous_job = None, None, None
            if previous_preflight:
                base.mkdir(mode=0o700, exist_ok=True)
                previous_job = base / 'job-20261103T010203Z-0123abcd'
                previous_job.mkdir(mode=0o700)
                rows, last = [], '0' * 64
                for phase in ('preflight', 'refreshing_indexes', 'failed_needs_review'):
                    row = dict(time='2026-11-03T01:02:03Z', phase=phase, previous_sha256=last)
                    if phase == 'failed_needs_review':
                        row.update(reason='nginx_path_outside_config', recovery=str(previous_job / 'recovery.json'))
                    raw = M.encoded(row)
                    rows.append(raw)
                    last = M.digest(raw)
                previous_files = {'php85_upgrade.py': old_core_fixture(),
                    'events.jsonl': b''.join(rows), 'timers.json': M.encoded(['apt-daily.timer'])}
                for name, raw in previous_files.items():
                    write(previous_job / name, raw)
                previous_bytes = M.encoded(dict(version='1.0.0', phase='failed_needs_review', job=str(previous_job),
                    event_sha256=last, reason='nginx_path_outside_config', recovery=str(previous_job / 'recovery.json')))
                write(base / 'current.json', previous_bytes)
                writes.clear()

            def command(args, *unused, **kwargs):
                nonlocal installed
                commands.append(args)
                if args[0] == '/usr/bin/apt-get':
                    if '--no-download' in args:
                        installed = True
                        jobs = [job for job in base.glob('job-*') if (job / 'plan.json').exists()]
                        self.assertEqual(len(jobs), 1)
                        write(jobs[0] / 'hook-accepted.json', M.encoded({'plan_sha256': M.digest(M.encoded(plan)), 'accepted': True}))
                    return ''
                if args[:2] == ['/usr/bin/update-alternatives', '--query']:
                    return 'Status: ' + alternative_status + '\nValue: /usr/bin/' + args[2] + branch + '\n'
                if args[:2] in (['/usr/bin/update-alternatives', '--set'], ['/usr/bin/update-alternatives', '--auto']):
                    return ''
                if args[0] == '/usr/bin/php':
                    return '8.5'
                if args[0] == '/bin/systemctl' and 'MainPID' in args:
                    return '1234'
                if args[0] in ('/bin/systemctl', '/usr/sbin/php-fpm8.5', '/usr/sbin/php-fpm7.4', '/usr/sbin/nginx'):
                    return ''
                raise AssertionError('unmocked native command: ' + repr(args))

            def subprocess(args, *unused, **kwargs):
                commands.append(args)
                if args[:3] == ['/bin/systemctl', 'is-active', '--quiet']:
                    return SimpleNamespace(returncode=0 if args[-1] == 'apt-daily.timer' else 3)
                if args[:2] == ['/usr/bin/update-alternatives', '--query']:
                    name = args[2]
                    return SimpleNamespace(returncode=0 if name in ('php', 'phar') else 2,
                        stdout=('Status: ' + alternative_status + '\nValue: /usr/bin/' + name + branch + '\n').encode())
                raise AssertionError('unmocked subprocess: ' + repr(args))

            def registry(branch, fpm=False):
                registry_calls.append((branch, fpm))
                value = '512M' if fpm else '-1'
                if patched_setting_drift == ('fpm' if fpm else 'cli'):
                    value = '256M'
                return dict(version='8.5.13', directory='/usr/lib/php/fixture', modules=['Core'], ini={'memory_limit': value})

            def validate_loaders(*args):
                loader_calls.append(args)

            def validate_unit(branch, running=False):
                unit_calls.append((branch, running))
                return '/lib/systemd/system/php' + branch + '-fpm.service'

            def expand(pattern):
                logical = Path(pattern)
                return [str(path) for path in FakePath(logical.parent).glob(logical.name)]

            def health(specs):
                health_calls.append(specs)
                if web_failure:
                    raise M.Hold('application_health_failed')

            def final_nginx():
                return dict(routes=[{'socket': '/run/php/php8.5-fpm.sock'}])

            def runtime_proof(sockets, master_pid, extension_directory):
                runtime_calls.append(dict(sockets=sorted(sockets), master_pid=master_pid,
                    extension_directory=extension_directory,
                    site=FakePath(site).read_bytes(), command_count=len(commands)))
                return {'fixture_sockets': sorted(sockets), 'master_pid': master_pid}

            def open_os(path, *args, **kwargs):
                # Intercept literal os.open policy operations; all other fixture
                # file descriptors are temporary files created above.
                logical = str(path)
                if logical.startswith(('/usr/', '/etc/', '/var/')):
                    path = str(FakePath(logical).physical())
                else:
                    self.assertTrue(logical.startswith(str(physical_root)), 'native filesystem escape: ' + logical)
                return actual_os_open(path, *args, **kwargs)

            error = None
            rollback_error = None
            with contextlib.ExitStack() as stack, contextlib.redirect_stdout(io.StringIO()):
                for name, value in (('BASE', base), ('Path', FakePath)):
                    stack.enter_context(patch.object(M, name, value))
                for name, callback in (('identity', lambda: HOST), ('source_files', lambda: {}),
                    ('validate_apt_security', lambda: True), ('inspect', lambda: plan),
                    ('safe_file', lambda path, *unused: FakePath(path).read_bytes()),
                    ('files_snapshot', snapshot), ('atomic', write), ('command', command),
                    ('packages', lambda: after if installed or (mode == 'patch' and not patch_changes) else before),
                    ('registry', registry), ('health', health), ('nginx_inventory', final_nginx),
                    ('validate_native_unit', validate_unit), ('validate_loaders', validate_loaders),
                    ('unit_enabled', lambda branch: source_enabled)):
                    stack.enter_context(patch.object(M, name, side_effect=callback))
                stack.enter_context(patch.object(M.subprocess, 'run', side_effect=subprocess))
                stack.enter_context(patch.object(M.os, 'geteuid', return_value=0))
                stack.enter_context(patch.object(M.os, 'open', side_effect=open_os))
                stack.enter_context(patch.object(M.os, 'chown', side_effect=lambda path, uid, gid: ownership.append((str(path), uid, gid))))
                stack.enter_context(patch.object(M.fcntl, 'flock'))
                stack.enter_context(patch.object(M.time, 'sleep'))
                stack.enter_context(patch.object(M.glob, 'glob', side_effect=expand))
                stack.enter_context(patch.dict(M.RUNTIME, {'prove_pool': runtime_proof}))
                if hasattr(M, 'lock_packages'):
                    stack.enter_context(patch.object(M, 'lock_packages', return_value=contextlib.nullcontext()))
                if hasattr(M, 'package_locks'):
                    stack.enter_context(patch.object(M, 'package_locks', return_value=[]))
                if hasattr(M, 'shared_lock'):
                    stack.enter_context(patch.object(M, 'shared_lock', side_effect=lambda:
                        actual_os_open(str(physical_root / 'fixture-shared-lock'), M.os.O_RDWR | M.os.O_CREAT, 0o600)))
                try:
                    M.apply()
                except M.Hold as failure:
                    error = str(failure)
                if rollback_request:
                    try:
                        M.rollback()
                    except M.Hold as failure:
                        rollback_error = str(failure)
            # Capture all observations before the private filesystem is removed.
            current = json.loads((base / 'current.json').read_bytes()) if (base / 'current.json').exists() else {}
            final_site = FakePath(site).read_bytes()
            policy_exists = FakePath('/usr/sbin/policy-rc.d').exists()
            current_job = FakePath(current['job']) if current.get('job') else None
            events = (current_job / 'events.jsonl').read_bytes().splitlines(keepends=True) if current_job else []
            archived_current = [path.read_bytes() for path in base.glob('archived-preflight-*.json')]
            preserved_previous = {path.name: path.read_bytes() for path in previous_job.iterdir()} if previous_job else None
            return dict(error=error, writes=writes, commands=commands, ownership=ownership,
                        current=current, final_site=final_site, original_site=nginx_text.encode(),
                        health_calls=health_calls, policy_exists=policy_exists, events=events,
                        rollback_error=rollback_error, runtime_calls=runtime_calls,
                        registry_calls=registry_calls, loader_calls=loader_calls, unit_calls=unit_calls,
                        previous_bytes=previous_bytes, previous_files=previous_files,
                        archived_current=archived_current, preserved_previous=preserved_previous)

    def test_full_migration_preserves_pool_permissions_and_distinct_sapi_settings(self):
        result = self.run_apply()
        self.assertIsNone(result['error'])
        self.assertEqual(result['current']['phase'], 'complete')
        outputs = {path: (raw, mode) for path, raw, mode in result['writes']}
        self.assertEqual(outputs['/etc/php/8.5/fpm/pool.d/www.conf'][1], 0o640)
        self.assertIn(b'env[PRIVATE_TOKEN]=fixture-only-value', outputs['/etc/php/8.5/fpm/pool.d/www.conf'][0])
        self.assertEqual(outputs['/etc/php/8.5/fpm/conf.d/99-ubuntu-php85-migration.ini'][1], 0o600)
        self.assertIn(b'memory_limit="512M"', outputs['/etc/php/8.5/fpm/conf.d/99-ubuntu-php85-migration.ini'][0])
        self.assertIn(b'memory_limit="-1"', outputs['/etc/php/8.5/cli/conf.d/99-ubuntu-php85-migration.ini'][0])
        self.assertIn(b'process.max=23', outputs['/etc/php/8.5/fpm/php-fpm.conf'][0])
        self.assertIn(b'unix:/run/php/php8.5-fpm.sock;', result['final_site'])
        self.assertFalse(result['policy_exists'])
        self.assertIn(['/bin/systemctl', 'start', 'apt-daily.timer'], result['commands'])
        install = next(i for i, args in enumerate(result['commands']) if args[0] == '/usr/bin/apt-get' and '--no-download' in args)
        cli_pin = result['commands'].index(['/usr/bin/update-alternatives', '--set', 'php', '/usr/bin/php7.4'])
        self.assertLess(cli_pin, install)
        self.assertEqual(len(result['runtime_calls']), 2)
        self.assertEqual(result['runtime_calls'][0]['site'], result['original_site'])
        self.assertEqual(result['runtime_calls'][1]['site'], result['final_site'])
        self.assertEqual(result['runtime_calls'][0]['master_pid'], 1234)
        self.assertEqual(result['runtime_calls'][0]['extension_directory'], '/usr/lib/php/fixture')
        self.assertEqual(result['runtime_calls'][0]['sockets'],
                         ['/run/php/php8.5-fpm.sock', '/run/php/php8.5-unused.sock'])

    def test_verified_old_preflight_is_archived_before_a_fresh_bound_apply_job(self):
        result = self.run_apply(previous_preflight=True)
        self.assertIsNone(result['error'])
        self.assertEqual(result['current']['phase'], 'complete')
        self.assertEqual(result['archived_current'], [result['previous_bytes']])
        self.assertEqual(result['preserved_previous'], result['previous_files'])
        self.assertNotEqual(result['current']['job'].split('/')[-1], 'job-20261103T010203Z-0123abcd')

    def test_http_failure_is_not_reported_as_complete_and_restores_timer_policy(self):
        result = self.run_apply(web_failure=True)
        self.assertEqual(result['error'], 'application_health_failed')
        self.assertNotEqual(result['current']['phase'], 'complete')
        self.assertEqual(len(result['health_calls']), 3)
        self.assertFalse(result['policy_exists'])
        self.assertIn(['/bin/systemctl', 'start', 'apt-daily.timer'], result['commands'])
        self.assertNotIn(['/usr/bin/update-alternatives', '--set', 'php', '/usr/bin/php8.5'], result['commands'])

    def test_post_apt_package_drift_blocks_before_config_or_nginx_cutover(self):
        result = self.run_apply(package_drift=True)
        self.assertEqual(result['error'], 'final_package_version_mismatch')
        self.assertEqual(result['final_site'], result['original_site'])
        self.assertFalse(any(path.startswith('/etc/php/8.5/') for path, _, _ in result['writes']))
        self.assertFalse(result['policy_exists'])

    def test_same_branch_zero_change_does_not_restart_enable_or_edit_nginx(self):
        result = self.run_apply(mode='patch')
        self.assertIsNone(result['error'])
        self.assertEqual(result['current']['phase'], 'complete')
        self.assertEqual(result['final_site'], result['original_site'])
        self.assertFalse(any(args[0] == '/usr/bin/apt-get' and 'install' in args for args in result['commands']))
        self.assertFalse(any(args[:2] in (['/bin/systemctl', 'restart'], ['/bin/systemctl', 'enable']) for args in result['commands']))
        self.assertFalse(any(path.startswith('/etc/') for path, _, _ in result['writes']))
        self.assertFalse(any(args[0] == '/usr/bin/update-alternatives' and args[1] in ('--set', '--auto')
                             for args in result['commands']))

    def test_migration_preserves_a_disabled_source_service(self):
        result = self.run_apply(source_enabled=False)
        self.assertIsNone(result['error'])
        self.assertIn(['/bin/systemctl', 'disable', 'php8.5-fpm.service'], result['commands'])
        self.assertNotIn(['/bin/systemctl', 'enable', 'php8.5-fpm.service'], result['commands'])

    def test_same_branch_package_patch_preserves_automatic_and_manual_tool_modes(self):
        for status in ('auto', 'manual'):
            with self.subTest(status=status):
                result = self.run_apply(mode='patch', patch_changes=True, alternative_status=status)
                self.assertIsNone(result['error'])
                self.assertEqual(result['current']['phase'], 'complete')
                self.assertEqual(result['final_site'], result['original_site'])
                self.assertIn(['/bin/systemctl', 'restart', 'php8.5-fpm.service'], result['commands'])
                self.assertFalse(any(args[:2] == ['/bin/systemctl', 'enable'] for args in result['commands']))
                automatic = [args for args in result['commands'] if args[:2] == ['/usr/bin/update-alternatives', '--auto']]
                self.assertEqual(automatic, [['/usr/bin/update-alternatives', '--auto', name] for name in ('php', 'phar')]
                                 if status == 'auto' else [])
                saved = next(raw for path, raw, _ in result['writes'] if path.endswith('/alternative-modes.json'))
                self.assertEqual(json.loads(saved), {'php': status, 'phar': status})

    def test_retained_target_bootstrap_holds_before_any_registry_or_runtime_start(self):
        for sapi, directive in (('cli', 'auto_prepend_file=/srv/retained-bootstrap.php\n'),
                                ('fpm', 'opcache.preload=/srv/retained-preload.php\n')):
            with self.subTest(sapi=sapi):
                result = self.run_apply(target_injection=(sapi, directive))
                self.assertEqual(result['error'], 'application_preload_prepend_or_basedir_requires_review')
                self.assertEqual(result['registry_calls'], [])
                self.assertEqual(result['loader_calls'], [])
                self.assertEqual(result['unit_calls'], [])
                self.assertEqual(result['runtime_calls'], [])
                self.assertFalse(any(args[:2] == ['/bin/systemctl', 'restart'] for args in result['commands']))
                self.assertEqual(result['final_site'], result['original_site'])

    def test_same_branch_cli_and_fpm_setting_drift_holds_before_restart(self):
        for sapi in ('cli', 'fpm'):
            with self.subTest(sapi=sapi):
                result = self.run_apply(mode='patch', patch_changes=True, patched_setting_drift=sapi)
                self.assertEqual(result['error'], 'patched_INI_effective_value_drift')
                self.assertEqual(result['runtime_calls'], [])
                self.assertFalse(any(args[:2] == ['/bin/systemctl', 'restart'] for args in result['commands']))
                self.assertEqual(result['final_site'], result['original_site'])

    def test_explicit_operator_rollback_restores_routes_cli_and_continues_journal_chain(self):
        result = self.run_apply(rollback_request=True)
        self.assertIsNone(result['error'])
        self.assertIsNone(result['rollback_error'])
        self.assertEqual(result['current']['phase'], 'rolled_back')
        self.assertEqual(result['final_site'], result['original_site'])
        self.assertIn(['/usr/bin/update-alternatives', '--set', 'phar', '/usr/bin/phar7.4'], result['commands'])
        self.assertEqual(result['commands'][-1], ['/usr/bin/update-alternatives', '--set', 'php', '/usr/bin/php7.4'])
        self.assertEqual(sum('--no-download' in args for args in result['commands']), 1,
                         'rollback must retain packages without another APT transaction')
        previous = '0' * 64
        for raw in result['events']:
            self.assertEqual(json.loads(raw)['previous_sha256'], previous,
                             'operator recovery must continue the existing durable event chain')
            previous = M.digest(raw)


class StateFixtures(Offline):
    def test_command_environment_cannot_inherit_php_or_dynamic_loader_injection(self):
        fake = SimpleNamespace(returncode=0, stdout=b'fixture output', stderr=b'')
        poison = {'PHPRC': '/tmp/evil', 'PHP_INI_SCAN_DIR': '/tmp/evil',
                  'LD_PRELOAD': '/tmp/evil.so', 'LD_LIBRARY_PATH': '/tmp/evil', 'PYTHONPATH': '/tmp/evil'}
        with patch.dict(M.os.environ, poison), patch.object(M.subprocess, 'run', return_value=fake) as run:
            self.assertEqual(REAL_COMMAND(['/fixture/not-a-real-command']), 'fixture output')
            environment = run.call_args.kwargs['env']
            self.assertFalse(set(poison) & set(environment))
            self.assertEqual(environment['NEEDRESTART_MODE'], 'l')
            self.assertEqual(environment['DEBIAN_FRONTEND'], 'noninteractive')

    def test_readiness_checks_running_executable_and_actual_socket_type(self):
        def execute(pid='123', actual_inode=77, socket_mode=stat.S_IFSOCK, exists=True):
            def command(args, *unused, **kwargs):
                return pid if 'MainPID' in args else ''
            def path(value):
                info = SimpleNamespace(st_dev=2,
                    st_ino=actual_inode if str(value).startswith('/proc/') else 77,
                    st_mode=socket_mode)
                return SimpleNamespace(stat=lambda: info, exists=lambda: exists)
            with patch.object(M, 'command', side_effect=command), patch.object(M, 'Path', side_effect=path), \
                 patch.object(M, 'registry', return_value={'directory': '/usr/lib/php/fixture'}), \
                 patch.object(M, 'validate_native_unit', return_value='/lib/systemd/system/php8.5-fpm.service'), \
                 patch.dict(M.RUNTIME, {'prove_pool': Mock(return_value={'proved': True})}):
                M.fpm_ready(['/run/php/php8.5-fpm.sock'])
        execute()
        self.held('target_master_PID_missing', execute, pid='0')
        self.held('target_executable_stale', execute, actual_inode=78)
        self.held('target_socket_missing', execute, socket_mode=stat.S_IFREG)
        self.held('target_socket_missing', execute, exists=False)

    def test_private_state_file_rejects_untrusted_owner_or_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            fixture = root / 'plan.json'
            fixture.write_bytes(b'fixture')
            fixture.chmod(0o600)
            with patch.object(M, '_SECURITY_ROOT', root), patch.object(M, '_SECURITY_UID', M.os.getuid()):
                self.assertEqual(M.safe_file(fixture, True), b'fixture')
                fixture.chmod(0o622)
                self.held('unsafe_file', M.safe_file, fixture, True)
                fixture.chmod(0o644)
                self.held('private_file_required', M.safe_file, fixture, True)
                fixture.chmod(0o600)
                with patch.object(M, '_SECURITY_UID', M.os.getuid() + 1):
                    self.held('unsafe_file', M.safe_file, fixture, True)

    def test_journal_hash_chain_and_current_phase_match_durable_events(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            job = base / 'job'; job.mkdir()
            with patch.object(M, 'BASE', base), contextlib.redirect_stdout(io.StringIO()):
                journal = M.Journal(job)
                journal.phase('preflight')
                journal.phase('plan_sealed', plan_sha256='a' * 64)
            rows = (job / 'events.jsonl').read_bytes().splitlines(keepends=True)
            self.assertEqual(json.loads(rows[0])['previous_sha256'], '0' * 64)
            self.assertEqual(json.loads(rows[1])['previous_sha256'], M.digest(rows[0]))
            current = json.loads((base / 'current.json').read_bytes())
            self.assertEqual(current['event_sha256'], M.digest(rows[1]))
            self.assertEqual(current['phase'], 'plan_sealed')
            self.assertEqual((base / 'current.json').stat().st_mode & 0o777, 0o600)

    def test_apply_nonroot_guard_precedes_any_native_operation(self):
        with patch.object(M.os, 'geteuid', return_value=1000):
            self.held('root_required', M.apply)

    def test_snapshot_stops_on_identity_source_file_or_package_drift(self):
        plan = dict(host=HOST, sources={'source': 1}, files={'file': 1}, packages={'php': 1})
        values = [('identity', HOST), ('source_files', plan['sources']),
                  ('files_snapshot', plan['files']), ('packages', plan['packages'])]
        for changed, reason in [('identity', 'host_identity_changed'), ('source_files', 'APT_sources_changed'),
                                ('files_snapshot', 'configuration_changed'), ('packages', 'package_inventory_changed')]:
            with self.subTest(changed=changed), contextlib.ExitStack() as stack:
                for name, value in values:
                    stack.enter_context(patch.object(M, name, return_value={} if name == changed else value))
                self.held(reason, M.current_snapshot, plan)


if __name__ == '__main__':
    unittest.main(verbosity=2)
