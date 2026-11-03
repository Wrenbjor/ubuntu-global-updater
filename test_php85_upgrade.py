"""Offline fixtures. Never execute APT, PHP, Nginx, systemctl, or the live apply path.

Run with Ubuntu Python 3.10+: python3 -B test_php85_upgrade.py
Native command entry points are denied by default in every fixture.
"""
import contextlib
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
                        authentication_override=False):
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
            stack.enter_context(patch.object(M, 'files_snapshot', side_effect=lambda paths: {str(p): {'sha256': 'fixture'} for p in paths}))
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


class ApplyFixtures(Offline):
    """Execute orchestration against a private temporary filesystem and fake services.

    Every absolute system path is translated before filesystem access. Native
    processes, APT locks, ownership changes, time delays and runtime connections
    are mocked; the actual orchestration/journal/configuration transformations run.
    """
    def run_apply(self, mode='migration', web_failure=False, package_drift=False, rollback_request=False,
                  source_enabled=True, patch_changes=False, alternative_status='auto',
                  target_injection=None, patched_setting_drift=None):
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

            def command(args, *unused, **kwargs):
                nonlocal installed
                commands.append(args)
                if args[0] == '/usr/bin/apt-get':
                    if '--no-download' in args:
                        installed = True
                        jobs = base.glob('job-*')
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
            jobs = base.glob('job-*')
            events = (jobs[0] / 'events.jsonl').read_bytes().splitlines(keepends=True) if jobs else []
            return dict(error=error, writes=writes, commands=commands, ownership=ownership,
                        current=current, final_site=final_site, original_site=nginx_text.encode(),
                        health_calls=health_calls, policy_exists=policy_exists, events=events,
                        rollback_error=rollback_error, runtime_calls=runtime_calls,
                        registry_calls=registry_calls, loader_calls=loader_calls, unit_calls=unit_calls)

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
