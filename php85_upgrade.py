#!/usr/bin/python3
"""One host: native packages, PHP-FPM, exact Nginx routes, HTTP verification."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid

VERSION = '2.0.0'
STATE = Path('/var/lib/php85-updater')
TARGET = '8.5'
FLOOR = 12
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root', LANG='C', LC_ALL='C',
           DEBIAN_FRONTEND='noninteractive', NEEDRESTART_MODE='l', UCF_FORCE_CONFFOLD='1')
PROTECTED = re.compile(r'^(?:mysql|mariadb|percona|postgresql|nginx|libnginx|apache|libapache|redis-server|nodejs|libnode|openssh|systemd|linux-|ubuntu-|grub|initramfs|php(?:7\.[234]|8\.[0-4])(?:-|$))')
PPA = re.compile(r'https?://(?:ppa\.launchpad\.net|ppa\.launchpadcontent\.net|ppa\.setup-php\.com)/ondrej/php/ubuntu\s+jammy/main\s+')


class Stop(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise Stop(reason)


def config_module():
    namespace = dict(__name__='php85_config')
    if 'CONFIG_SOURCE' in globals():
        exec(compile(CONFIG_SOURCE, 'php85_config.py', 'exec'), namespace)
        return type('Config', (), namespace)
    spec = importlib.util.spec_from_file_location('php85_config', Path(__file__).with_name('php85_config.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CFG = config_module()


def private_directory(path):
    path = Path(path)
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077
            and path.resolve() == path, 'unsafe_private_directory')
    return path


def save(path, value):
    path = Path(path)
    fd, name = tempfile.mkstemp(prefix='.receipt-', dir=path.parent)
    with os.fdopen(fd, 'w') as out:
        os.fchmod(out.fileno(), 0o600)
        json.dump(value, out, indent=2, sort_keys=True)
        out.write('\n'); out.flush(); os.fsync(out.fileno())
    os.replace(name, path)


def emit(phase, **fields):
    print(json.dumps(dict(phase=phase, **fields)), flush=True)


def archive_source(run_dir):
    helper = CONFIG_SOURCE if 'CONFIG_SOURCE' in globals() else Path(CFG.__file__).read_text()
    for name, raw in (('php85_upgrade.py', Path(__file__).read_bytes()), ('php85_config.py', helper.encode())):
        fd = os.open(run_dir / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(raw); out.flush(); os.fsync(out.fileno())


class Runner:
    def __init__(self, logs):
        self.logs, self.number = Path(logs), 0

    def run(self, args, timeout=60, check=True):
        self.number += 1
        base = self.logs / ('%03d-%s' % (self.number, Path(args[0]).name))
        with open(str(base) + '.stdout', 'wb') as out, open(str(base) + '.stderr', 'wb') as error:
            os.fchmod(out.fileno(), 0o600); os.fchmod(error.fileno(), 0o600)
            try:
                result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=out, stderr=error,
                                        env=ENV, timeout=timeout)
            except subprocess.TimeoutExpired:
                raise Stop('command_timeout_' + Path(args[0]).name)
        if check:
            require(result.returncode == 0, 'command_failed_' + Path(args[0]).name)
        with Path(str(base) + '.stdout').open('rb') as stream:
            raw = stream.read(8 * 1024 * 1024 + 1)
        require(len(raw) <= 8 * 1024 * 1024, 'command_output_too_large')
        return raw.decode('utf-8', 'strict').strip() if result.returncode == 0 else None


def package_table(runner):
    raw = runner.run(['/usr/bin/dpkg-query', '-W', '-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n'])
    rows = {}
    for line in raw.splitlines():
        status, name, version = line.split('\t')
        if status.startswith('ii'):
            rows[name.split(':')[0]] = version
    return rows


def requested_packages(branch, table):
    wanted = {'php8.5-cli', 'php8.5-fpm', 'php8.5-common'}
    for name in table:
        if name.startswith('php' + branch + '-'):
            suffix = name[len('php' + branch + '-'):]
            if suffix not in ('json', 'opcache'):
                wanted.add('php8.5-' + suffix)
    return sorted(wanted)


def candidates(runner, packages):
    result = {}
    for name in packages:
        raw = runner.run(['/usr/bin/apt-cache', 'policy', name])
        match = re.search(r'^\s*Candidate:\s+(\S+)', raw, re.M)
        require(match and match[1] != '(none)', 'missing_candidate_' + name)
        version = match[1]
        blocks = re.split(r'(?m)^\s*(?:\*\*\*\s+)?(\S+)\s+[0-9]+\s*$', raw)
        own = [blocks[index + 1] for index in range(1, len(blocks) - 1, 2) if blocks[index] == version]
        require('+ubuntu22.04.' in version and len(own) == 1 and PPA.search(own[0]),
                'matching_Jammy_PHP_repository_required')
        if name in ('php8.5-cli', 'php8.5-fpm', 'php8.5-common'):
            found = re.match(r'^(?:\d+:)?8\.5\.(\d+)[-+]', version)
            require(found and int(found[1]) >= FLOOR, 'PHP_8_5_security_floor_not_available')
        result[name] = version
    return result


def install_plan(runner, target, table):
    # Keep installed database, web, OS and legacy-runtime packages at their
    # current versions in the real native APT transaction, as well as simulation.
    protected = {name: version for name, version in table.items() if PROTECTED.match(name)}
    pins = [name + '=' + version for name, version in sorted((protected | target).items())]
    raw = runner.run(['/usr/bin/apt-get', '-s', '--no-remove', 'install'] + pins)
    require(not re.search(r'^Remv\s', raw, re.M), 'package_removals_refused')
    actions = re.findall(r'^Inst\s+(\S+)(?:\s+\[[^\]]+\])?\s+\((\S+)', raw, re.M)
    require(len(actions) == len(re.findall(r'^Inst\s', raw, re.M)) and
            len({name.split(':')[0] for name, version in actions}) == len(actions), 'ambiguous_APT_simulation')
    changed = [name for name, version in actions]
    require(all(not PROTECTED.match(name.split(':')[0]) for name in changed), 'protected_package_change_refused')
    require(all(runner.run(['/usr/bin/dpkg', '--compare-versions', table[name], 'le', version], check=False) is not None
                for name, version in target.items() if name in table), 'package_downgrade_refused')
    return pins, changed, dict(actions)


def apt_guard(path, stream):
    """Native APT v1 archive list: confirm the simulated package/version set."""
    release = Path('/etc/os-release').read_text()
    require(re.search(r'^ID=ubuntu$', release, re.M) and 'VERSION_ID="22.04"' in release,
            'Ubuntu_release_changed_before_package_install')
    expected = json.loads(Path(path).read_text())
    raw = stream.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024, 'APT_archive_list_too_large')
    actual = {}
    for archive in raw.splitlines():
        require(archive.startswith('/') and archive.endswith('.deb'), 'unexpected_APT_hook_protocol')
        name = subprocess.check_output(['/usr/bin/dpkg-deb', '-f', archive, 'Package'], env=ENV, timeout=10).decode().strip()
        version = subprocess.check_output(['/usr/bin/dpkg-deb', '-f', archive, 'Version'], env=ENV, timeout=10).decode().strip()
        require(name not in actual and not PROTECTED.match(name), 'unexpected_APT_package')
        actual[name] = version
    require(actual == {name.split(':')[0]: version for name, version in expected.items()}, 'APT_transaction_changed')


def apt_hook(run_dir, actions):
    plan = run_dir / 'apt-packages.json'
    save(plan, actions)
    script = run_dir / 'apt-guard'
    import shlex
    source = run_dir / 'php85_upgrade.py'
    require(source.is_file(), 'saved_updater_source_missing')
    script.write_text('#!/bin/sh\nexec /usr/bin/python3 -I -B ' + shlex.quote(str(source)) +
                      ' --apt-guard ' + shlex.quote(str(plan)) + '\n')
    script.chmod(0o700)
    return script


def registry(runner, branch, sapi='fpm'):
    compiled = runner.run(['/usr/bin/php' + branch, '-n', '-r', 'echo PHP_EXTENSION_DIR;'])
    CFG.validate_source_ini(branch, expected_directory=compiled)
    settings = sorted(CFG.INI_KEYS | CFG.GUARD_KEYS)
    script = '$all=ini_get_all(null,false);$keys=json_decode(' + json.dumps(json.dumps(settings)) + ',true);'
    script += '$ini=[];foreach($keys as $k){if($k==="session.save_path"&&($all["session.save_handler"]??"files")!=="files")continue;if(array_key_exists($k,$all))$ini[$k]=$all[$k];}'
    script += 'echo json_encode(["version"=>PHP_VERSION,"directory"=>PHP_EXTENSION_DIR,"modules"=>get_loaded_extensions(),"ini"=>$ini,"registered_keys"=>array_keys($all)]);'
    args = ['/usr/bin/php' + branch, '-c', '/etc/php/' + branch + '/' + sapi + '/php.ini']
    for key in ('auto_prepend_file', 'auto_append_file', 'opcache.preload', 'opcache.preload_user'):
        args += ['-d', key + '=']
    # Select the real SAPI scan directory without executing customer application code.
    old_env = ENV.get('PHP_INI_SCAN_DIR')
    ENV['PHP_INI_SCAN_DIR'] = '/etc/php/' + branch + '/' + sapi + '/conf.d'
    try:
        result = json.loads(runner.run(args + ['-r', script]))
        require(result['directory'] == compiled, 'custom_PHP_extension_directory')
        return result
    finally:
        if old_env is None: ENV.pop('PHP_INI_SCAN_DIR', None)
        else: ENV['PHP_INI_SCAN_DIR'] = old_env


def stock_target_pool(runner):
    """Only an untouched native package pool may replace an unconfigured 8.5 pool."""
    path = Path('/etc/php/8.5/fpm/pool.d/www.conf')
    if sorted(p.name for p in path.parent.glob('*.conf')) != ['www.conf']:
        return False
    raw, unused = CFG._read(str(path), '/', 0, '/etc/php')
    files = runner.run(['/usr/bin/dpkg-query', '-L', 'php8.5-fpm']).splitlines()
    inventory = Path('/var/lib/dpkg/info/php8.5-fpm.md5sums')
    if not inventory.is_file():
        arch = runner.run(['/usr/bin/dpkg', '--print-architecture'])
        inventory = Path('/var/lib/dpkg/info/php8.5-fpm:' + arch + '.md5sums')
    expected = {}
    for line in inventory.read_text().splitlines():
        digest, name = line.split(None, 1)
        expected['/' + name] = digest
    for name in files:
        if name.startswith('/usr/share/') and Path(name).name == 'www.conf' and name in expected:
            template = Path(name).read_bytes()
            if hashlib.md5(template, usedforsecurity=False).hexdigest() == expected[name] and template == raw:
                return True
    conffiles = runner.run(['/usr/bin/dpkg-query', '-W', '-f=${Conffiles}', 'php8.5-fpm'])
    return any(len(row := line.split()) == 2 and row[0] == str(path) and
               hashlib.md5(raw, usedforsecurity=False).hexdigest() == row[1] for line in conffiles.splitlines())


def restore_CLI(runner, receipt):
    match = re.search(r'^Value: (/.+)$', receipt['CLI_before'], re.M)
    require(match and Path(match[1]).is_file(), 'original_CLI_selection_unavailable')
    runner.run(['/usr/bin/update-alternatives', '--set', 'php', match[1]])
    # The original auto/manual mode is retained in CLI_before. An added higher
    # priority version prevents restoring both the old value and auto mode.


def health(runner, hosts):
    result = []
    for host in hosts:
        for path in ('/', '/wp-login.php'):
            code = runner.run(['/usr/bin/curl', '--noproxy', '*', '--resolve', host + ':443:127.0.0.1',
                               '--connect-timeout', '3', '--max-time', '20', '-sS', '-o', '/dev/null',
                               '-w', '%{http_code}', 'https://' + host + path], timeout=25)
            require(re.fullmatch('[23][0-9]{2}', code or ''), 'application_health_failed')
            result.append(dict(host=host, path=path, http=int(code)))
    return result


def native_target(runner, expected_socket, extension_directory=None):
    runner.run(['/usr/sbin/php-fpm8.5', '-t'])
    version = re.search(r'\bPHP (8\.5\.(\d+))', runner.run(['/usr/sbin/php-fpm8.5', '-v']))
    require(version and int(version[2]) >= FLOOR, 'live_FPM_version_below_security_floor')
    require(runner.run(['/bin/systemctl', 'is-active', 'php8.5-fpm']) == 'active', 'PHP_8_5_FPM_not_active')
    pid = int(runner.run(['/bin/systemctl', 'show', 'php8.5-fpm', '-p', 'MainPID', '--value']))
    require(pid > 1, 'FPM_master_missing')
    binary = Path('/usr/sbin/php-fpm8.5')
    live = Path('/proc') / str(pid) / 'exe'
    require(os.readlink(live) == str(binary) and (live.stat().st_dev, live.stat().st_ino) ==
            (binary.stat().st_dev, binary.stat().st_ino), 'FPM_restart_required')
    require(stat.S_ISSOCK(Path(expected_socket).stat().st_mode), 'FPM_socket_missing')
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as peer:
        peer.settimeout(3)
        peer.connect(expected_socket)
        import struct
        peer_pid, peer_uid, unused_gid = struct.unpack('3i', peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    require(peer_pid == pid and peer_uid == 0, 'FPM_socket_not_owned_by_target_service')
    if extension_directory:
        for line in (Path('/proc') / str(pid) / 'maps').read_text().splitlines():
            fields = line.split(None, 5)
            if len(fields) < 6 or not fields[5].startswith('/usr/lib/php/'):
                continue
            path = fields[5]
            require(not path.endswith(' (deleted)') and str(Path(path).parent) == extension_directory,
                    'FPM_restart_required')
            module = Path(path).stat()
            dev = fields[3].split(':')
            require(module.st_ino == int(fields[4]) and (os.major(module.st_dev), os.minor(module.st_dev)) ==
                    (int(dev[0], 16), int(dev[1], 16)), 'FPM_restart_required')
    return dict(PHP=version[1], master_pid=pid, executable=str(binary), socket=expected_socket)


def maintenance_locks():
    folder = private_directory('/run/ubuntu-php-updater')
    paths = [folder / 'worker.lock']
    old = Path('/var/lib/ubuntu-php85-upgrade/maintenance.lock')
    if old.exists(): paths.append(old)
    fds = []
    try:
        for path in paths:
            fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            fds.append(fd)
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o077, 'unsafe_maintenance_lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fds
    except BaseException:
        for fd in fds: os.close(fd)
        raise Stop('another_updater_is_running_or_lock_is_unsafe')


def execute(runner, apply=False, run_dir=None):
    if apply:
        archive_source(run_dir)
    release = Path('/etc/os-release').read_text()
    require(re.search(r'^ID=ubuntu$', release, re.M) and 'VERSION_ID="22.04"' in release,
            'native_Ubuntu_22_04_required')
    require('microsoft' not in Path('/proc/sys/kernel/osrelease').read_text().lower()
            and runner.run(['/usr/bin/systemd-detect-virt', '--container'], check=False) is None,
            'native_systemd_host_required')
    require(not runner.run(['/usr/bin/dpkg', '--audit']), 'unfinished_package_operation')
    runner.run(['/usr/sbin/nginx', '-t'])
    require(runner.run(['/bin/systemctl', 'is-active', 'nginx']) == 'active', 'nginx_not_active')
    dump = runner.run(['/usr/sbin/nginx', '-T'])
    route = CFG.parse_nginx_dump(dump)
    hosts = sorted({spec['host'] for spec in route['health_specs']})
    require(hosts and len(hosts) <= 32, 'primary_HTTPS_sites_required')
    branch = route['source_branch']
    table = package_table(runner)
    source = registry(runner, branch)
    source_cli = registry(runner, branch, 'cli')
    wanted = requested_packages(branch, table)
    existing_target = registry(runner, TARGET) if {'php8.5-cli', 'php8.5-fpm'} <= table.keys() else None
    existing_target_cli = registry(runner, TARGET, 'cli') if existing_target else None
    reuse = branch == TARGET or (existing_target is not None and not stock_target_pool(runner))
    preflight = CFG.plan_configuration(dump, source, existing_target, reuse_target=reuse,
                                      source_CLI_registry=source_cli, target_CLI_registry=existing_target_cli)
    if not apply:
        target = candidates(runner, wanted)
        pins, changed, actions = install_plan(runner, target, table)
        return dict(status='plan-only', version=VERSION, source=branch, target=TARGET,
                    package_changes=changed, configuration_changes=len(preflight['changes']),
                    sites=hosts, indexes='cached; refreshed during apply', target_validation_pending=existing_target is None)
    receipt = dict(version=VERSION, host=socket.gethostname(), machine_id=Path('/etc/machine-id').read_text().strip(),
                   source=branch, phase='baseline', sites=hosts, legacy_checkpoints='preserved; not used as admission gates')
    active_timers = []
    def phase(name, **fields):
        receipt.update(phase=name, **fields, updated_at=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()))
        save(run_dir / 'status.json', receipt); save(STATE / 'current.json', receipt | {'run':str(run_dir)})
        emit(name, **{key: value for key, value in fields.items() if key in ('package_changes', 'route_changes')})
    def restore_timers():
        pending = list(active_timers)
        active_timers.clear()  # One cleanup attempt; never repeatedly retry commands.
        if pending:
            runner.run(['/bin/systemctl', 'start'] + pending)
            for timer in pending:
                require(runner.run(['/bin/systemctl', 'is-active', timer]) == 'active', 'APT_timer_restore_failed')
        receipt['APT_timers_restored'] = True
    try:
        receipt['baseline_health'] = health(runner, hosts)
        receipt['CLI_before'] = runner.run(['/usr/bin/update-alternatives', '--query', 'php'])
        phase('refreshing_package_indexes')
        for timer in ('apt-daily.timer', 'apt-daily-upgrade.timer'):
            if runner.run(['/bin/systemctl', 'is-active', timer], check=False) == 'active':
                active_timers.append(timer)
        receipt['APT_timers_before'] = list(active_timers)
        if active_timers: runner.run(['/bin/systemctl', 'stop'] + active_timers)
        runner.run(['/usr/bin/apt-get', '-o', 'Acquire::Retries=0', '-o', 'Acquire::http::Timeout=15',
                    '-o', 'Acquire::https::Timeout=15', '-o', 'APT::Update::Error-Mode=any', 'update'], timeout=180)
        target = candidates(runner, wanted)
        pins, changed, actions = install_plan(runner, target, package_table(runner))
        receipt['target_packages'] = target
        phase('package_plan', package_changes=changed)
        if changed:
            guard = apt_hook(run_dir, actions)
            phase('installing_packages')
            try:
                runner.run(['/usr/bin/apt-get', '-y', '--no-remove', '-o', 'DPkg::Lock::Timeout=60',
                            '-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Dpkg::Options::=--force-confdef',
                            '-o', 'Dpkg::Options::=--force-confold', '-o', 'DPkg::Pre-Install-Pkgs::=' + str(guard),
                            '-o', 'DPkg::Tools::Options::' + str(guard) + '::Version=1', 'install'] + pins, timeout=None)
            except Stop as error:
                if str(error) == 'command_failed_apt-get':
                    restore_CLI(runner, receipt)
                raise
            restore_CLI(runner, receipt)
        require(not runner.run(['/usr/bin/dpkg', '--audit']), 'unfinished_package_operation')
        after = package_table(runner)
        require(all(after.get(name) == version for name, version in target.items()), 'target_packages_not_installed')
        require(Path('/etc/os-release').read_text() == release, 'Ubuntu_release_changed_during_package_stage')
        require(Path('/etc/machine-id').read_text().strip() == receipt['machine_id'], 'host_identity_changed')
        require(runner.run(['/usr/sbin/nginx', '-T']) == dump, 'Nginx_configuration_changed_during_package_stage')
        target_registry = registry(runner, TARGET)
        target_cli = registry(runner, TARGET, 'cli')
        plan = CFG.plan_configuration(dump, source, target_registry, reuse_target=reuse,
                                      source_CLI_registry=source_cli, target_CLI_registry=target_cli)
        require(plan.get('source_pool') == preflight.get('source_pool'), 'source_pool_changed_during_package_stage')
        save(run_dir / 'configuration-plan.json', plan)
        phase('configuring_FPM')
        CFG.apply_configuration(plan, run_dir / 'backup', kinds=('pool', 'ini'))
        runner.run(['/usr/sbin/php-fpm8.5', '-t'])
        if runner.run(['/bin/systemctl', 'is-enabled', 'php8.5-fpm'], check=False) != 'enabled':
            runner.run(['/bin/systemctl', 'enable', 'php8.5-fpm'])
        active = runner.run(['/bin/systemctl', 'is-active', 'php8.5-fpm'], check=False) == 'active'
        if changed or any(row['kind'] in ('pool', 'ini') for row in plan['changes']) or not active:
            runner.run(['/bin/systemctl', 'restart' if active else 'start', 'php8.5-fpm'])
        try:
            proof = native_target(runner, plan['new_socket'], target_registry['directory'])
        except Stop as error:
            if str(error) != 'FPM_restart_required': raise
            runner.run(['/bin/systemctl', 'restart', 'php8.5-fpm'])
            proof = native_target(runner, plan['new_socket'], target_registry['directory'])
        phase('switching_Nginx', route_changes=sum(row['kind'] == 'route' for row in plan['changes']))
        CFG.apply_configuration(plan, run_dir / 'backup', kinds=('route',))
        runner.run(['/usr/sbin/nginx', '-t'])
        if any(row['kind'] == 'route' for row in plan['changes']):
            runner.run(['/bin/systemctl', 'reload', 'nginx'])
        receipt['health'] = health(runner, hosts)
        if Path('/usr/bin/php').resolve() != Path('/usr/bin/php8.5').resolve():
            runner.run(['/usr/bin/update-alternatives', '--set', 'php', '/usr/bin/php8.5'])
        require(runner.run(['/usr/bin/php', '-n', '-r', 'echo PHP_VERSION;']).startswith('8.5.'), 'default_CLI_not_8_5')
        receipt['runtime'] = proof
        restore_timers()
        phase('complete')
        return dict(status='complete', host=receipt['host'], PHP=target_registry['version'],
                    sites=hosts, checks=receipt['health'], evidence=str(run_dir))
    except BaseException as error:
        receipt['failed_during'] = receipt.get('phase')
        phase('failed', reason=str(error) if isinstance(error, (Stop, CFG.ConfigError)) else type(error).__name__)
        raise
    finally:
        if active_timers:
            try:
                restore_timers()
            except BaseException as error:
                receipt['cleanup_error'] = str(error) if isinstance(error, Stop) else type(error).__name__
                save(run_dir / 'status.json', receipt); save(STATE / 'current.json', receipt | {'run':str(run_dir)})
                raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--plan-only', action='store_true')
    mode.add_argument('--status', action='store_true')
    mode.add_argument('--rollback', action='store_true', help='manually restore only the last run Nginx routes and CLI')
    parser.add_argument('--run', help='explicit saved run ID or path for --rollback')
    parser.add_argument('--adopt-vendor-socket', action='store_true', help='compatibility option; preserve configured target defaults')
    args = parser.parse_args(argv)
    require(not args.run or args.rollback, '--run_requires_rollback')
    require(os.geteuid() == 0, 'run_as_root')
    os.umask(0o077)
    if args.status:
        print((STATE / 'current.json').read_text() if (STATE / 'current.json').exists() else json.dumps(dict(status='no_simple_updater_run')))
        return 0
    locks = maintenance_locks() if args.apply or args.rollback else []
    try:
        if args.rollback:
            private_directory(STATE)
            current = json.loads((STATE / 'current.json').read_text()) if not args.run else None
            run_dir = STATE / args.run if args.run else Path(current['run'])
            require(run_dir.parent == STATE and re.fullmatch(r'run-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}', run_dir.name)
                    and run_dir.is_dir() and run_dir.resolve() == run_dir,
                    'invalid_rollback_run')
            private_directory(run_dir)
            if args.run:
                current = json.loads((run_dir / 'status.json').read_text()) | {'run':str(run_dir)}
            logs = private_directory(run_dir / ('rollback-attempt-' + uuid.uuid4().hex[:8]))
            return rollback(Runner(logs), run_dir, current)
        elif args.apply:
            private_directory(STATE)
            if (STATE / 'current.json').exists():
                previous = json.loads((STATE / 'current.json').read_text())
                require(not (previous.get('phase') == 'installing_packages' or
                             previous.get('phase') == 'failed' and previous.get('failed_during') == 'installing_packages'),
                        'previous_APT_install_failed_or_interrupted_inspect_saved_logs_before_retry')
            run_dir = private_directory(STATE / ('run-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + uuid.uuid4().hex[:8]))
            runner = Runner(run_dir)
            try:
                result = execute(runner, True, run_dir)
            except BaseException as error:
                if not (run_dir / 'status.json').exists():
                    failure = dict(version=VERSION, host=socket.gethostname(), run=str(run_dir), phase='failed',
                                   failed_during='preflight', reason=str(error) if isinstance(error,(Stop,CFG.ConfigError))
                                   else type(error).__name__)
                    save(run_dir / 'status.json', failure); save(STATE / 'current.json', failure)
                error.evidence = str(run_dir)
                raise
        else:
            with tempfile.TemporaryDirectory(prefix='php85-plan-', dir='/run') as path:
                result = execute(Runner(path))
        print(json.dumps(result), flush=True)
        return 0
    finally:
        for fd in reversed(locks): os.close(fd)


def rollback(runner, run_dir, receipt):
    require((run_dir / 'configuration-plan.json').is_file(), 'no_configuration_plan_for_this_run')
    require(receipt['machine_id'] == Path('/etc/machine-id').read_text().strip(), 'host_identity_changed')
    plan = json.loads((run_dir / 'configuration-plan.json').read_text())
    source = plan['source_branch']
    require(source != TARGET, 'same_branch_package_patch_has_no_route_rollback')
    require(runner.run(['/bin/systemctl', 'is-active', 'php' + source + '-fpm']) == 'active',
            'start_retained_source_FPM_before_rollback')
    rows = [row for row in plan['changes'] if row['kind'] == 'route']
    require(rows, 'no_Nginx_route_changes_to_restore')
    restore = []
    for row in rows:
        before = row['before']
        raw, now = CFG._read(before['path'], '/', 0, '/etc/nginx')
        require(raw == row['content'].encode(), 'Nginx_changed_since_cutover_manual_review_required')
        backup = run_dir / 'backup' / (CFG.sha(before['path'].encode()) + '.before')
        original = backup.read_bytes()
        require(CFG.sha(original) == before['sha256'], 'route_backup_changed')
        restore.append(dict(kind='route', before=now, content=original.decode(),
                            write_metadata={key:before[key] for key in ('uid','gid','mode')}))
    CFG.apply_configuration(dict(schema=1, changes=restore), run_dir / 'rollback-backup', kinds=('route',))
    runner.run(['/usr/sbin/nginx', '-t'])
    runner.run(['/bin/systemctl', 'reload', 'nginx'])
    checks = health(runner, receipt['sites'])
    restore_CLI(runner, receipt)
    receipt.update(phase='routes-rolled-back', rollback_health=checks)
    save(run_dir / 'status.json', receipt); save(STATE / 'current.json', receipt)
    print(json.dumps(dict(status='routes-rolled-back', host=receipt['host'], evidence=str(run_dir),
                          packages='not downgraded; target INIs retained', CLI_mode='manual; original selection restored')))
    return 0


if __name__ == '__main__':
    try:
        if len(sys.argv) == 3 and sys.argv[1] == '--apt-guard':
            apt_guard(sys.argv[2], sys.stdin)
        else:
            raise SystemExit(main())
    except Exception as error:
        print(json.dumps(dict(status='stopped', reason=str(error) if isinstance(error, (Stop, CFG.ConfigError))
                              else type(error).__name__, evidence=getattr(error,'evidence',None))), flush=True)
        raise SystemExit(1)
