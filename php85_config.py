#!/usr/bin/python3
"""Small config-only helper. Native package/service/runtime checks belong to caller."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile


class ConfigError(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise ConfigError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _uncomment(text):
    # Preserve offsets so only the native operand bytes are ever changed.
    result, quote, escaped, comment = [], None, False, False
    for char in text:
        if comment:
            result.append('\n' if char == '\n' else ' ')
            comment = char != '\n'
        elif escaped:
            result.append(char)
            escaped = False
        elif char == '\\':
            result.append(char)
            escaped = True
        elif quote:
            result.append(char)
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            result.append(char)
            quote = char
        elif char == '#':
            result.append(' ')
            comment = True
        else:
            result.append(char)
    require(quote is None and not escaped, 'unsupported_Nginx_quoting')
    return ''.join(result)


ROUTE = re.compile(r'\bfastcgi_pass\s+(?P<q>[\"\x27]?)(?P<operand>unix:(?P<socket>/(?:run|var/run)/php/php(?P<branch>7\.[234]|8\.[0-5])-fpm\.sock))(?P=q)\s*;')


def _outside_quotes(text):
    result, quote, escaped = [], None, False
    for char in text:
        if escaped:
            result.append(' ')
            escaped = False
        elif char == '\\':
            result.append(' ')
            escaped = True
        elif quote:
            result.append(' ')
            if char == quote:
                quote = None
        elif char in ('"', "'"):
            result.append(' ')
            quote = char
        else:
            result.append(char)
    return ''.join(result)


def _server_names(text):
    clean = _uncomment(text)
    outside = _outside_quotes(clean)
    return [match[1] for match in re.finditer(r'\bserver_name\s+([^;{}]+);', clean)
            if outside[match.start():].startswith('server_name') and _directive_start(outside, match.start())]


def _directive_start(text, offset):
    prefix = text[:offset].rstrip()
    return (not prefix or prefix[-1] in ';{}') and (offset == 0 or text[offset - 1] != '$')


def _routes(text):
    clean = _uncomment(text)
    outside = _outside_quotes(clean)
    matches = [m for m in ROUTE.finditer(clean) if outside[m.start():].startswith('fastcgi_pass') and _directive_start(outside, m.start())]
    count = sum(_directive_start(outside, m.start()) for m in re.finditer(r'\bfastcgi_pass\b', outside))
    require(len(matches) == count, 'unsupported_fastcgi_pass_operand')
    return matches


def parse_nginx_dump(text):
    """Read native nginx -T file boundaries; do not traverse includes ourselves."""
    files, current = {}, None
    for line in text.splitlines(keepends=True):
        header = re.fullmatch(r'# configuration file (/[^\r\n]+):\r?\n?', line)
        if header:
            current = header[1]
            require(current not in files, 'duplicate_Nginx_dump_file')
            files[current] = ''
        elif current is not None and not line.startswith('nginx: '):
            files[current] += line
    require(files, 'native_Nginx_dump_headers_required')
    routes, branches, hosts, health_specs = [], set(), set(), []
    for path, content in files.items():
        matches = _routes(content)
        if matches:
            require(path.startswith('/etc/nginx/'), 'route_file_outside_etc_nginx')
        for match in matches:
            branches.add(match['branch'])
            routes.append(dict(file=path, old_socket=match['socket'],
                               new_socket=match['socket'].replace('php' + match['branch'], 'php8.5')))
        for names in _server_names(content):
            hosts.update(name.lower() for name in names.split()
                         if re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', name) and '.' in name)
        if matches:
            primaries = []
            for names in _server_names(content):
                candidates = [name.lower() for name in names.split()
                              if re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?', name) and '.' in name]
                require(candidates, 'route_file_primary_hostname_required')
                primaries.append(candidates[0])
            require(len(set(primaries)) == 1, 'route_file_has_multiple_primary_hostnames')
            health_specs.append(dict(host=primaries[0], file=path))
    require(routes and len(branches) == 1, 'single_active_web_PHP_branch_required')
    return dict(source_branch=branches.pop(), routes=routes, health_candidates=sorted(hosts), health_specs=health_specs,
                dump_sha256=sha(text.encode()))


def _read(path, root, owner_uid, boundary):
    root = Path(root).resolve()
    logical = root / path.lstrip('/')
    canonical = logical.resolve(strict=True)
    base = root / boundary.lstrip('/')
    require(canonical.is_relative_to(base), 'configuration_outside_allowed_tree')
    for destination in (logical.parent, canonical.parent):
        cursor = destination
        while cursor != root:
            info = cursor.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner_uid and not info.st_mode & 0o022,
                    'unsafe_configuration_parent')
            cursor = cursor.parent
    info, alias = canonical.lstat(), logical.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == owner_uid and info.st_nlink == 1
            and not info.st_mode & 0o022 and info.st_size <= 4 * 1024 * 1024, 'unsafe_configuration_file')
    require(alias.st_uid == owner_uid and alias.st_nlink == 1, 'unsafe_configuration_alias')
    require(not os.listxattr(canonical), 'configuration_xattrs_require_manual_preservation')
    def identity(row):
        return (row.st_dev, row.st_ino, row.st_mode, row.st_uid, row.st_gid, row.st_nlink, row.st_size, row.st_mtime_ns, row.st_ctime_ns)
    fd = os.open(canonical, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        opened = os.fstat(stream.fileno())
        require(identity(opened) == identity(info), 'configuration_changed_during_open')
        raw = stream.read(4 * 1024 * 1024 + 1)
    require(len(raw) <= 4 * 1024 * 1024 and identity(opened) == identity(canonical.stat()) == identity(info)
            and identity(logical.lstat()) == identity(alias)
            and logical.resolve(strict=True) == canonical, 'configuration_changed_during_read')
    return raw, dict(path=path, canonical='/' + str(canonical.relative_to(root)), sha256=sha(raw),
                     mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid,
                     link=os.readlink(logical) if stat.S_ISLNK(alias.st_mode) else None,
                     link_inode=alias.st_ino if stat.S_ISLNK(alias.st_mode) else None)


SKIP = {'extension', 'zend_extension', 'extension_dir', 'user_ini.filename', 'auto_prepend_file',
        'auto_append_file', 'opcache.preload', 'opcache.preload_user', 'open_basedir',
        'session.sid_length', 'session.sid_bits_per_character', 'session.hash_function',
        'session.hash_bits_per_character', 'mysqli.reconnect', 'disable_classes', 'log_errors_max_len'}
INI_KEYS = set(('memory_limit upload_max_filesize post_max_size max_execution_time max_input_time max_input_vars '
    'date.timezone expose_php display_errors display_startup_errors log_errors error_reporting disable_functions '
    'default_socket_timeout allow_url_fopen allow_url_include session.gc_maxlifetime session.save_handler session.save_path '
    'session.serialize_handler session.cookie_secure '
    'session.cookie_httponly session.cookie_samesite session.use_strict_mode mysqli.default_socket '
    'pdo_mysql.default_socket opcache.enable opcache.memory_consumption opcache.max_accelerated_files '
    'opcache.validate_timestamps opcache.revalidate_freq').split())
GUARD_KEYS = {'auto_prepend_file', 'auto_append_file', 'opcache.preload', 'opcache.preload_user', 'open_basedir',
              'session.sid_length', 'session.sid_bits_per_character', 'extension_dir'}


def validate_source_ini(branch, *, root='/', owner_uid=0, expected_directory=None):
    require(re.fullmatch(r'7\.[234]|8\.[0-5]', branch), 'unsupported_source_branch')
    for sapi in ('fpm', 'cli'):
        paths = ['/etc/php/' + branch + '/' + sapi + '/php.ini']
        paths += ['/' + str(p.relative_to(Path(root))) for p in sorted((Path(root) / ('etc/php/' + branch + '/' + sapi + '/conf.d')).glob('*.ini'))]
        for path in paths:
            raw, _ = _read(path, root, owner_uid, '/etc/php')
            text = raw.decode()
            require(not re.search(r'(?mi)^\s*\[(?:PATH|HOST)\s*=', text), 'per_directory_INI_requires_review')
            for line in text.splitlines():
                match = re.match(r'^\s*([A-Za-z0-9_.-]+)\s*=\s*(.*)', line)
                if not match:
                    continue
                key, value = match[1], match[2].strip()
                if key not in GUARD_KEYS | {'extension', 'zend_extension'}:
                    continue
                if value.startswith(('"', "'")):
                    quoted = re.fullmatch(r'(["\x27])([^"\x27\\]*)\1\s*(?:;.*)?', value)
                    require(quoted is not None, 'unsupported_guard_INI_quoting')
                    value = quoted[2]
                else:
                    value = value.split(';', 1)[0].strip()
                require('${' not in value, 'interpolated_INI_requires_review')
                if key in GUARD_KEYS - {'session.sid_length', 'session.sid_bits_per_character', 'extension_dir'}:
                    require(value == '', 'custom_executable_INI_requires_manual_review')
                if key in ('extension', 'zend_extension'):
                    require(re.fullmatch(r'[A-Za-z0-9_-]+(?:\.so)?', value), 'custom_extension_loader_requires_review')
                if key == 'extension_dir':
                    require(re.fullmatch(r'/usr/lib/php/[0-9]{8}', value)
                            and (expected_directory is None or value == expected_directory),
                            'custom_extension_directory_requires_review')
    return True


def ini_overlay(source, target):
    require(target['ini'].get('session.save_handler', 'files') == 'files',
            'custom_target_session_backend_requires_separate_profile')
    require(source['ini'].get('session.save_handler', 'files') == 'files', 'custom_session_backend_requires_dedicated_profile')
    require({m.lower() for m in source['modules']} <= {m.lower() for m in target['modules']}, 'target_extension_missing')
    for key in ('auto_prepend_file', 'auto_append_file', 'opcache.preload', 'opcache.preload_user', 'open_basedir'):
        require(source['ini'].get(key) in (None, '', False), 'custom_executable_INI_requires_manual_review')
    sid = tuple(str(source['ini'].get(key, '')) for key in ('session.sid_length', 'session.sid_bits_per_character'))
    require(sid in (('', ''), ('26', '5'), ('32', '4')), 'custom_session_identifier_settings_require_review')
    lines = ['; Settings preserved by the PHP 8.5 updater; native 8.5 owns module loaders.']
    for key, value in sorted(source['ini'].items()):
        if key not in INI_KEYS or key in SKIP or key not in target['ini'] or value is None:
            continue
        if key in ('mysqli.default_socket', 'pdo_mysql.default_socket') and value == '':
            continue
        value = str(value)
        require(re.fullmatch(r'[A-Za-z0-9_.-]+', key) and not any(c in value for c in '\r\n\0'), 'unsupported_INI_value')
        require(not re.search(r'/(?:etc/)?php/(?:7\.[234]|8\.[0-4])(?:/|$)|/20\d{6}/', value), 'foreign_PHP_ABI_setting')
        value = value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$')
        lines.append(key + '="' + value + '"')
    return '\n'.join(lines) + '\n'


def plan_configuration(dump, source_registry, target_registry=None, *, root='/', owner_uid=0, reuse_target=False,
                       source_CLI_registry=None, target_CLI_registry=None):
    parsed = parse_nginx_dump(dump)
    branch = parsed['source_branch']
    require(source_registry['version'].startswith(branch + '.'), 'registry_branch_mismatch')
    validate_source_ini(branch, root=root, owner_uid=owner_uid)
    if target_registry is not None:
        require(target_registry['version'].startswith('8.5.'), 'registry_branch_mismatch')
        require({m.lower() for m in source_registry['modules']} <= {m.lower() for m in target_registry['modules']}, 'target_extension_missing')
    changes, seen = [], set()
    for route in parsed['routes']:
        path = route['file']
        if path in seen:
            continue
        seen.add(path)
        raw, before = _read(path, root, owner_uid, '/etc/nginx')
        text = raw.decode()
        matches = _routes(text)
        expected = [r['old_socket'] for r in parsed['routes'] if r['file'] == path]
        require([m['socket'] for m in matches] == expected, 'Nginx_dump_routes_changed')
        for match in reversed(matches):
            replacement = match['operand'].replace('php' + branch, 'php8.5')
            text = text[:match.start('operand')] + replacement + text[match.end('operand'):]
        if text.encode() != raw:
            changes.append(dict(kind='route', before=before, content=text))
    old_dir = Path(root) / ('etc/php/' + branch + '/fpm/pool.d')
    pool_paths = sorted(old_dir.glob('*.conf'))
    require(len(pool_paths) == 1, 'single_standard_FPM_pool_required')
    source_path = '/' + str(pool_paths[0].relative_to(Path(root)))
    raw, pool_record = _read(source_path, root, owner_uid, '/etc/php')
    text = raw.decode()
    require(re.findall(r'(?m)^\s*\[([^]]+)\]\s*$', text) == ['www'], 'standard_www_pool_required')
    require(not re.search(r'(?mi)^\s*(?:include|php_(?:admin_)?(?:value|flag)\[(?:extension|extension_dir|zend_extension|auto_prepend_file|auto_append_file|opcache.preload|opcache.preload_user|open_basedir)\])\s*=', text), 'custom_pool_loader_requires_manual_review')
    require(not re.search(r'/usr/lib/php/20[0-9]{6}(?:/|\b)', text), 'foreign_pool_ABI_requires_review')
    for key in re.findall(r'(?m)^\s*php_(?:admin_)?(?:value|flag)\[([^]]+)\]\s*=', text):
        registry_evidence = target_registry or source_registry
        require(key in registry_evidence.get('registered_keys', registry_evidence['ini']), 'unsupported_pool_INI_setting')
    listens = list(re.finditer(r'(?m)^(\s*listen\s*=\s*)(/[^\s;]+)([ \t]*(?:;[^\n]*)?)$', text))
    require(len(listens) == 1 and listens[0][2] in {r['old_socket'] for r in parsed['routes']}, 'pool_route_socket_mismatch')
    old_socket = listens[0][2]
    require({r['old_socket'] for r in parsed['routes']} == {old_socket}, 'single_FPM_socket_required')
    new_socket = old_socket.replace('php' + branch, 'php8.5')
    if target_registry is None:
        # Read/validate every source input before the caller can request packages.
        for evidence in (source_registry, source_CLI_registry or source_registry):
            ini_overlay(evidence, evidence)
        return dict(schema=1, source_branch=branch, install_needed=True, changes=[], source_pool=pool_record,
                    health_specs=parsed['health_specs'], health_candidates=parsed['health_candidates'])
    output = text[:listens[0].start(2)] + new_socket + text[listens[0].end(2):]
    target_pools = sorted((Path(root) / 'etc/php/8.5/fpm/pool.d').glob('*.conf'))
    require(len(target_pools) == 1, 'unexpected_target_pools')
    target_path = '/' + str(target_pools[0].relative_to(Path(root)))
    target_pool, target_record = _read(target_path, root, owner_uid, '/etc/php')
    def identity_fields(content):
        clean = re.sub(r'(?m);.*$', '', content)
        return {key: re.findall(r'(?m)^\s*' + key + r'\s*=\s*(\S+)\s*$', clean) for key in ('user', 'group', 'listen')}
    source_fields, target_fields = identity_fields(text), identity_fields(target_pool.decode())
    compatible = (all(len(source_fields[k]) == len(target_fields[k]) == 1 for k in ('user', 'group', 'listen'))
             and all(source_fields[k] == target_fields[k] for k in ('user', 'group'))
             and target_fields['listen'] == [new_socket])
    reuse = reuse_target or branch == '8.5'
    require(not reuse or compatible, 'existing_target_pool_identity_or_socket_mismatch')
    if not reuse and target_pool != output.encode():
        require(branch != '8.5', 'same_branch_pool_changed')
        changes.append(dict(kind='pool', before=target_record, content=output,
                            write_metadata={key: pool_record[key] for key in ('mode', 'uid', 'gid')}))
    source_by_sapi = {'fpm': source_registry, 'cli': source_CLI_registry or source_registry}
    target_by_sapi = {'fpm': target_registry, 'cli': target_CLI_registry or target_registry}
    if reuse:
        for sapi in ('fpm', 'cli'):
            source, target = source_by_sapi[sapi], target_by_sapi[sapi]
            ini_overlay(source, target)
            for key in INI_KEYS & source['ini'].keys() & target['ini'].keys():
                value = source['ini'][key]
                if value is None or key.endswith('.default_socket') and value == '':
                    continue
                require(str(value) == str(target['ini'][key]), 'existing_target_supported_INI_mismatch')
    for sapi in (() if reuse else ('fpm', 'cli')):
        destination = '/etc/php/8.5/' + sapi + '/conf.d/99-php85-updater.ini'
        require(not (Path(root) / destination.lstrip('/')).exists(), 'overlay_destination_exists')
        _, source_ini = _read('/etc/php/' + branch + '/' + sapi + '/php.ini', root, owner_uid, '/etc/php')
        changes.append(dict(kind='ini', before=dict(path=destination, canonical=destination, absent=True, mode=source_ini['mode'] & 0o644,
                                                  uid=owner_uid, gid=source_ini['gid']),
                            content=ini_overlay(source_by_sapi[sapi], target_by_sapi[sapi])))
    return dict(schema=1, source_branch=branch, install_needed=False, reuse_target=reuse, new_socket=new_socket, changes=changes,
                health_candidates=parsed['health_candidates'], health_specs=parsed['health_specs'], source_pool=pool_record,
                prerequisite='caller_must_validate_native_FPM_Nginx_and_target_runtime_before_route_switch')


def apply_configuration(plan, backup_dir, *, root='/', owner_uid=0, kinds=('pool', 'ini', 'route')):
    require(plan.get('schema') == 1 and set(kinds) <= {'pool', 'ini', 'route'}, 'invalid_configuration_plan')
    backup_dir = Path(backup_dir)
    require(backup_dir.is_relative_to(Path(root)), 'backup_directory_outside_run_root')
    cursor = backup_dir.parent
    while cursor != Path(root):
        if cursor.exists() or cursor.is_symlink():
            parent = cursor.lstat()
            require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == owner_uid and not parent.st_mode & 0o022,
                    'unsafe_backup_parent')
        cursor = cursor.parent
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = backup_dir.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner_uid and not info.st_mode & 0o077, 'unsafe_backup_directory')
    selected = [row for row in plan['changes'] if row['kind'] in kinds]
    require(len({row['before']['canonical'] for row in selected}) == len(selected), 'duplicate_configuration_destination')
    for row in selected:
        before = row['before']
        boundary = '/etc/nginx' if row['kind'] == 'route' else '/etc/php/8.5'
        canonical = Path(root) / before['canonical'].lstrip('/')
        require(canonical.is_relative_to(Path(root) / boundary.lstrip('/')) and '..' not in canonical.parts,
                'configuration_destination_outside_scope')
        path = Path(root) / before['path'].lstrip('/')
        if before.get('absent'):
            require(row['kind'] == 'ini' and before['canonical'] == before['path']
                    and re.fullmatch(r'/etc/php/8\.5/(?:cli|fpm)/conf.d/99-php85-updater\.ini', before['path'])
                    and not path.exists() and not path.is_symlink(), 'configuration_destination_appeared')
            cursor = path.parent
            while cursor != Path(root):
                parent = cursor.lstat()
                require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == owner_uid and not parent.st_mode & 0o022,
                        'unsafe_configuration_parent')
                cursor = cursor.parent
        else:
            raw, actual = _read(before['path'], root, owner_uid, '/etc/nginx' if row['kind'] == 'route' else '/etc/php')
            require(actual == before, 'configuration_plan_drift')
            backup = backup_dir / (sha(before['path'].encode()) + '.before')
            require(not backup.exists() and not backup.is_symlink(), 'backup_already_exists')
            fd = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
    directory = os.open(backup_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    for row in selected:
        before = row['before']
        path = Path(root) / before['canonical'].lstrip('/')
        metadata = row.get('write_metadata', before)
        require(metadata['uid'] == owner_uid and not metadata['mode'] & 0o022, 'unsafe_configuration_write_metadata')
        if before.get('absent'):
            require(not path.exists() and not path.is_symlink(), 'configuration_destination_appeared')
            cursor = path.parent
            while cursor != Path(root):
                parent = cursor.lstat()
                require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == owner_uid and not parent.st_mode & 0o022,
                        'unsafe_configuration_parent')
                cursor = cursor.parent
        else:
            _, actual = _read(before['path'], root, owner_uid, '/etc/nginx' if row['kind'] == 'route' else '/etc/php')
            require(actual == before, 'configuration_plan_drift')
        require(path.parent.is_dir() and not path.parent.is_symlink(), 'configuration_parent_missing')
        fd, temporary = tempfile.mkstemp(prefix='.php85-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(row['content'].encode())
                os.fchmod(stream.fileno(), metadata['mode'])
                os.fchown(stream.fileno(), metadata['uid'], metadata['gid'])
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return dict(changed_files=len(selected), kinds=list(kinds))


def main():
    parser = argparse.ArgumentParser(description='Private PHP 8.5 configuration planning; no package or service commands.')
    commands = parser.add_subparsers(dest='operation', required=True)
    planner = commands.add_parser('plan')
    for name in ('dump', 'source', 'output'):
        planner.add_argument('--' + name, required=True)
    planner.add_argument('--target')
    planner.add_argument('--reuse-target', action='store_true')
    executor = commands.add_parser('apply')
    executor.add_argument('--plan', required=True)
    executor.add_argument('--backups', required=True)
    executor.add_argument('--kinds', choices=('prepare', 'routes'), required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, 'root_required')
    def private_input(path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o077, 'private_input_required')
            raw = stream.read(4 * 1024 * 1024 + 1)
        require(len(raw) <= 4 * 1024 * 1024, 'private_input_too_large')
        return raw.decode()
    if args.operation == 'plan':
        plan = plan_configuration(private_input(args.dump), json.loads(private_input(args.source)),
                                  json.loads(private_input(args.target)) if args.target else None,
                                  reuse_target=args.reuse_target)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(plan, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        result = dict(source_branch=plan['source_branch'], install_needed=plan['install_needed'], changes=len(plan['changes']))
    else:
        result = apply_configuration(json.loads(private_input(args.plan)), args.backups,
                                     kinds=('pool', 'ini') if args.kinds == 'prepare' else ('route',))
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except ConfigError as error:
        raise SystemExit(str(error))
