"""Host-local, resumable Ubuntu 24.04 maintenance coordinator.

Run --plan to inspect. The single-paste installer explicitly selects --apply.
No SSH, cloud API token, database queries, application dependency updates or builds.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import ubuntu_global_guard as guard
import ubuntu_global_os as os_upgrade
import ubuntu_global_runtime as node
import unattended_handoff_v7 as unattended
import upgrade_state_guard_v10_1 as legacy
import ubuntu_global_support as support

BASE = Path('/var/lib/visionline-global-updater')
UNIT = 'visionline-global-updater.service'
GUARD_CONF = Path('/etc/apt/apt.conf.d/99visionline-global-guard')
PAYLOAD = Path(__file__).resolve().parent
ENV = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root', LC_ALL='C', LANG='C',
           DEBIAN_FRONTEND='noninteractive', UCF_FORCE_CONFFOLD='1', NEEDRESTART_MODE='l')
APT_OPTIONS = ['-o', 'Acquire::Retries=0', '-o', 'Acquire::http::Timeout=15',
               '-o', 'Acquire::https::Timeout=15', '-o', 'DPkg::Lock::Timeout=60',
               '-o', 'APT::Get::AllowUnauthenticated=false', '-o', 'Acquire::AllowInsecureRepositories=false',
               '-o', 'Acquire::AllowWeakRepositories=false', '-o', 'Acquire::Check-Valid-Until=true',
               '-o', 'Dpkg::Options::=--force-confold']

class UpdateError(Exception):
    pass

def need(value, code):
    if not value:
        raise UpdateError(code)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def private_directory(path):
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700)
    i = path.lstat()
    need(stat.S_ISDIR(i.st_mode) and i.st_uid == 0 and stat.S_IMODE(i.st_mode) == 0o700,
         'unsafe_private_directory')

def write_json(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    temp = path.with_name(path.name + '.new')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw); stream.flush(); os.fsync(stream.fileno())
    os.replace(temp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def emit(stage, status, **fields):
    value = dict(time=time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), stage=stage, status=status, **fields)
    print(json.dumps(value, sort_keys=True), flush=True)
    if BASE.is_dir():
        path = BASE / 'events.jsonl'
        previous = digest(path.read_bytes()) if path.exists() else '0' * 64
        value['previous_sha256'] = previous
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as stream:
            stream.write(json.dumps(value, sort_keys=True) + '\n'); stream.flush(); os.fsync(stream.fileno())

def run(argv, timeout=30, check=True, capture=True):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=ENV, timeout=timeout)
    if check:
        need(result.returncode == 0, 'command_failed:' + Path(argv[0]).name)
    return result.stdout.decode(errors='replace') if capture else result.returncode

def package_command(argv, label):
    """Installer has no kill-on-timeout: it remains supervised, never blindly retried."""
    log = BASE / ('command-' + label + '-' + str(time.time_ns()) + '.log')
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    emit(label, 'running', private_log=log.name)
    with os.fdopen(fd, 'wb') as stream:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream, stderr=subprocess.STDOUT, env=ENV)
        started = time.monotonic()
        warned = False
        while process.poll() is None:
            time.sleep(2)
            if time.monotonic() - started > 3600 and not warned:
                emit(label, 'still-running-needs-attention', pid=process.pid)
                warned = True
        need(process.returncode == 0, 'package_command_failed:' + label)
    emit(label, 'command-complete', private_log=log.name)

def identity():
    release = {}
    for line in Path('/etc/os-release').read_text().splitlines():
        if '=' in line:
            key, value = line.split('=', 1); release[key] = value.strip('"')
    return dict(ubuntu=release.get('ID') == 'ubuntu', hostname=os.uname().nodename, machine_id=Path('/etc/machine-id').read_text().strip(),
                boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
                os_id=release.get('ID'), release=release.get('VERSION_ID'), codename=release.get('VERSION_CODENAME'),
                kernel=os.uname().release)

def droplet_id():
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://169.254.169.254/metadata/v1/id', timeout=3) as response:
        need(response.geturl() == 'http://169.254.169.254/metadata/v1/id', 'metadata_redirect_refused')
        value = response.read(32).decode().strip()
    need(re.fullmatch(r'[1-9][0-9]{0,19}', value), 'cannot_verify_current_droplet')
    return value

def packages():
    raw = run(['/usr/bin/dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${db:Status-Status}\n'])
    result = {}
    for line in raw.splitlines():
        values = line.split('\t')
        if len(values) == 3 and values[2] == 'installed':
            need(':' not in values[0] or values[0].endswith(':amd64'), 'multiarch_packages_require_profile')
            result[values[0].split(':')[0]] = values[1]
    return result

def service_baseline():
    raw = run(['/bin/systemctl', 'list-units', '--type=service', '--state=running', '--no-legend', '--plain'])
    return sorted(row.split()[0] for row in raw.splitlines() if row.strip()
                  and not re.match(r'^(?:apt-daily|unattended-upgrades|user@|session-|systemd-(?:hostnamed|timedated|localed))', row.split()[0]))

def health_baseline():
    """Read the existing include graph; never publish PHP probes or read DB rows."""
    if run(['/bin/systemctl', 'is-active', 'nginx'], check=False).strip() != 'active':
        return dict(scope='service-state-only', specs=[], results=[])
    import php74_to8_routing_v10 as route
    import php74_to8_runner_v10 as php
    fs = route.FileSystem('/')
    discovery = route.Discovery(fs.root, fs, source_branch='7.4', target_branch='8.3')
    for path in Path('/etc/php').glob('*/fpm/pool.d/*.conf'):
        snap = fs.capture(str(path))
        for pool in route._pool_parse(snap.content).values():
            socket = pool.get('listen', '').strip('"\'')
            if socket.startswith(('/run/', '/var/run/')):
                discovery.socket_map[socket] = socket
                alternate = '/var' + socket if socket.startswith('/run/') else socket[4:]
                discovery.socket_map[alternate] = alternate
    route._nginx(discovery)
    specs = php.health_specs(discovery)
    return dict(scope='discovered-local-PHP-Nginx-vhosts', specs=specs, results=php.health(specs))

def check_health(before):
    if before['specs']:
        import php74_to8_runner_v10 as php
        php.comparable_health(before['results'], php.health(before['specs']))

def config_tests():
    if shutil.which('nginx'):
        run(['/usr/sbin/nginx', '-t'])
    if shutil.which('sshd'):
        run(['/usr/sbin/sshd', '-t'])
    for binary in Path('/usr/sbin').glob('php-fpm*'):
        need(re.fullmatch(r'php-fpm\d+\.\d+', binary.name), 'unknown_PHP_FPM_executable')
        run([str(binary), '-t'])
    return True

def boot_targets():
    need(Path('/boot/grub/grub.cfg').is_file() and bool(list(Path('/boot').glob('vmlinuz-*'))), 'GRUB_kernel_boot_targets_missing')
    need(run(['/usr/bin/findmnt', '-n', '-o', 'OPTIONS', '/']).strip().split(',')[0] != 'ro', 'root_filesystem_read_only')
    return True

def current_target_kernel():
    cache = apt_cache()
    name = 'linux-image-' + os.uname().release
    need(name in cache and cache[name].installed is not None, 'running_kernel_not_package_owned')
    installed = cache[name].installed
    need(any(origin.origin == 'Ubuntu' and origin.codename == identity()['codename'] and origin.trusted
             for origin in installed.origins), 'running_kernel_not_verified_for_target_release')
    return True

def assert_services(before):
    missing = [name for name in before if run(['/bin/systemctl', 'is-active', name], check=False).strip() != 'active']
    need(not missing, 'previously_running_services_inactive:' + ','.join(missing))

def stale_process(pid):
    """Compare mapped packaged-system files to disk without reading app memory."""
    root = Path('/proc') / str(pid)
    before = unattended.proc_stat((root / 'stat').read_text())
    loaded, binary = (root / 'exe').stat(), os.readlink(root / 'exe')
    if binary.endswith(' (deleted)'):
        return True
    disk = os.stat(binary)
    stale = (loaded.st_dev, loaded.st_ino) != (disk.st_dev, disk.st_ino)
    for row in (root / 'maps').read_text().splitlines():
        columns = row.split(None, 5)
        if len(columns) != 6 or not columns[5].startswith(('/usr/', '/lib/', '/lib64/')):
            continue
        path = columns[5]
        if path.endswith(' (deleted)'):
            stale = True; continue
        inode = int(columns[4])
        if not inode:
            continue
        info = os.stat(path)
        major, minor = (int(v, 16) for v in columns[3].split(':'))
        if (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino) != (major, minor, inode):
            stale = True
    after = unattended.proc_stat((root / 'stat').read_text())
    need(before['start'] == after['start'], 'service_process_changed_during_runtime_check')
    return stale

def refresh_live_services(services):
    def stale_units():
        found = []
        for unit in services:
            raw = run(['/bin/systemctl', 'show', unit, '-p', 'MainPID', '--value']).strip()
            need(raw.isdecimal(), 'cannot_inspect_service_main_PID')
            if int(raw) and stale_process(int(raw)):
                found.append(unit)
        return found
    stale = stale_units()
    restartable = re.compile(r'^(?:nginx|apache2|mysql|mysqld|mariadb|redis-server|ssh|php\d+\.\d+-fpm)\.service$')
    need(all(restartable.fullmatch(unit) for unit in stale), 'other_services_require_reviewed_restart:' + ','.join(stale))
    for unit in stale:
        validate_native_service(unit)
        # Restart only previously running, identified services with native unit
        # stop/start semantics. No process-group signals or application builds.
        run(['/bin/systemctl', 'restart', '--no-block', unit])
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            status = run(['/bin/systemctl', 'is-active', unit], check=False).strip()
            if status == 'active':
                raw = run(['/bin/systemctl', 'show', unit, '-p', 'MainPID', '--value']).strip()
                if raw.isdecimal() and int(raw):
                    try:
                        if not stale_process(int(raw)):
                            break
                    except (FileNotFoundError, ProcessLookupError):
                        pass
            need(status != 'failed', 'service_restart_failed:' + unit)
            time.sleep(1)
        need(run(['/bin/systemctl', 'is-active', unit], check=False).strip() == 'active', 'service_restart_still_pending:' + unit)
    need(not stale_units(), 'stale_service_processes_remain_after_restart')
    return stale

def validate_native_service(unit):
    raw = run(['/bin/systemctl', 'show', unit, '-p', 'FragmentPath', '-p', 'DropInPaths', '-p', 'MainPID'])
    properties = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
    fragment = properties.get('FragmentPath', '')
    aliases = {unit}
    if unit in ('mysql.service', 'mysqld.service', 'mariadb.service'):
        aliases |= {'mysql.service', 'mysqld.service', 'mariadb.service'}
    need(fragment in {prefix + name for prefix in ('/lib/systemd/system/', '/usr/lib/systemd/system/') for name in aliases}
         and not properties.get('DropInPaths'), 'custom_service_unit_requires_review:' + unit)
    info = Path(fragment).lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, 'unsafe_native_service_unit')
    pid = properties.get('MainPID', '')
    need(pid.isdecimal() and int(pid) > 0, 'native_service_main_PID_missing')
    executable = os.readlink('/proc/' + pid + '/exe').removesuffix(' (deleted)')
    binaries = {'nginx.service': {'/usr/sbin/nginx'}, 'apache2.service': {'/usr/sbin/apache2'},
                'ssh.service': {'/usr/sbin/sshd'}, 'redis-server.service': {'/usr/bin/redis-server'}}
    if unit in ('mysql.service', 'mysqld.service', 'mariadb.service'):
        expected = {'/usr/sbin/mysqld', '/usr/sbin/mariadbd'}
    elif re.fullmatch(r'php\d+\.\d+-fpm\.service', unit):
        expected = {'/usr/sbin/php-fpm' + unit[3:].split('-')[0]}
    else:
        expected = binaries.get(unit, set())
    need(executable in expected, 'noncanonical_service_executable_requires_review:' + unit)
    owned = run(['/usr/bin/dpkg-query', '-S', executable]).splitlines()
    need(len(owned) == 1 and owned[0].split(': ', 1)[-1] == executable,
         'native_service_executable_not_package_owned')

def old_workflow():
    for unit in ('ubuntu-php-upgrade-part1.service', 'ubuntu-php-upgrade-part2.service'):
        state = run(['/bin/systemctl', 'show', unit, '-p', 'ActiveState', '--value'], check=False).strip()
        need(state not in ('active', 'activating', 'deactivating', 'reloading'), 'another_upgrade_service_running')
    path = Path('/var/lib/ubuntu-php-upgrade/progress.json')
    if path.exists() or path.is_symlink():
        need(legacy.allowed(legacy.read_state(path)), 'old_upgrade_failed_or_unfinished_checkpoint_preserved')

def snapshot():
    value = identity()
    value.update(packages=packages(), dpkg_clean=not run(['/usr/bin/dpkg', '--audit']).strip(),
                 reboot_required=Path('/var/run/reboot-required').exists(),
                 holds=run(['/usr/bin/apt-mark', 'showhold']).splitlines(),
                 active_package_work=bool(unattended.System().locks()), services=service_baseline())
    path = Path('/var/lib/ubuntu-php-upgrade/progress.json')
    if path.exists() or path.is_symlink():
        value['old_progress'] = legacy.read_state(path)
    return value

def apt_cache():
    import apt
    import apt_pkg
    apt_pkg.init_config()
    for key in ('APT::Get::AllowUnauthenticated', 'Acquire::AllowInsecureRepositories', 'Acquire::AllowDowngradeToInsecureRepositories', 'Acquire::AllowWeakRepositories'):
        need(not apt_pkg.config.find_b(key, False), 'insecure_APT_global_configuration')
    need(apt_pkg.config.find_b('Acquire::Check-Valid-Until', True), 'expired_APT_metadata_allowed_by_configuration')
    for path in [Path('/etc/apt/sources.list')] + list(Path('/etc/apt/sources.list.d').glob('*')):
        if path.suffix not in ('.list', '.sources') and path.name != 'sources.list':
            continue
        raw = path.read_text()
        active = '\n'.join(line for line in raw.splitlines() if not line.lstrip().startswith('#'))
        need(not re.search(r'(?i)(?:trusted\s*=\s*yes|allow-insecure\s*=\s*yes|^\s*(?:Trusted|Allow-Insecure):\s*yes)', active, re.M), 'insecure_APT_source_option')
    return apt.Cache()

def authenticated(candidate, codename):
    origins = candidate.origins
    need(origins and all(o.trusted for o in origins), 'unauthenticated_package_origin')
    for origin in origins:
        if origin.origin == 'Ubuntu':
            need(origin.codename == codename, 'cross_release_Ubuntu_repository')
        elif origin.archive not in (codename, codename + '-main', 'nodistro', 'main', 'stable'):
            raise UpdateError('third_party_repository_release_requires_review')
    need(candidate.downloadable, 'candidate_not_downloadable_from_repository')

def apt_plan(phase='patch', node_version=None):
    cache = apt_cache()
    before = packages()
    if phase == 'node':
        need('nodejs' in cache and cache['nodejs'].candidate.version == node_version, 'node_candidate_changed')
        cache['nodejs'].mark_install(auto_fix=True, auto_inst=True, from_user=True)
    else:
        cache.upgrade(dist_upgrade=False)
        # Node is handled in its own source/major/consumer-aware stage.
        if 'nodejs' in cache:
            cache['nodejs'].mark_keep()
    changes = []
    pins = {}
    baseline = dict(packages=before, machine_id=identity()['machine_id'], phase=phase)
    if phase == 'node':
        baseline['node_target_major'] = node.node_major(node_version)
    for package in cache.get_changes():
        old = package.installed.version if package.installed else None
        if package.marked_delete:
            changes.append(dict(name=package.name, old=old, new=None, action='remove'))
            continue
        candidate = package.candidate
        authenticated(candidate, identity()['codename'])
        changes.append(dict(name=package.name, old=old, new=candidate.version, action='upgrade' if old else 'install'))
        pins[package.name] = candidate.version
    guard.validate_actions(changes, baseline, phase)
    baseline['approved_actions'] = changes
    if phase == 'node':
        need(set(pins) <= {'nodejs'}, 'node_dependency_changes_require_review')
    return dict(baseline=baseline, changes=changes, pins=pins)

def install_guard(baseline):
    write_json(BASE / 'guard.json', baseline)
    content = ('DPkg::Pre-Install-Pkgs { "/usr/bin/python3 ' + str(PAYLOAD / 'ubuntu_global_guard.py') + ' hook ' + str(BASE / 'guard.json') + '"; };\n'
               'DPkg::Tools::Options::/usr/bin/python3::Version "2";\n')
    # APT identifies the hook by the complete command's first token. The exact
    # protocol setting is also supplied on each direct APT invocation below.
    if GUARD_CONF.exists() or GUARD_CONF.is_symlink():
        need(GUARD_CONF.read_text() == content and GUARD_CONF.lstat().st_uid == 0, 'foreign_global_APT_guard')
    else:
        fd = os.open(GUARD_CONF, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(content)
    return dict(path=str(PAYLOAD / 'ubuntu_global_guard.py'), sha256=digest((PAYLOAD / 'ubuntu_global_guard.py').read_bytes()),
                configpath=str(GUARD_CONF), configsha256=digest(content.encode()),
                baselinepath=str(BASE / 'guard.json'), baselinesha256=digest((BASE / 'guard.json').read_bytes()))

def remove_guard(proof):
    need(GUARD_CONF.is_file() and not GUARD_CONF.is_symlink() and digest(GUARD_CONF.read_bytes()) == proof['configsha256'], 'APT_guard_changed_preserve_for_review')
    GUARD_CONF.unlink()

def package_update(phase='patch', node_version=None):
    plan = apt_plan(phase, node_version)
    path = BASE / ('plan-' + phase + '-' + str(time.time_ns()) + '.json')
    write_json(path, plan)
    if not plan['pins']:
        return plan
    proof = install_guard(plan['baseline'])
    try:
        args = ['/usr/bin/apt-get', '--yes', '--no-remove', '--no-install-recommends'] + APT_OPTIONS
        exact = [name + '=' + version for name, version in sorted(plan['pins'].items())]
        run(args + ['--simulate', 'install'] + exact, timeout=120)
        need(packages() == plan['baseline']['packages'], 'package_baseline_changed_before_install')
        package_command(args + ['install'] + exact, phase)
        after = packages()
        expected = dict(plan['baseline']['packages'], **plan['pins'])
        need(after == expected, 'package_delta_differs_from_exact_plan')
        need(not run(['/usr/bin/dpkg', '--audit']).strip(), 'dpkg_audit_failed')
    finally:
        remove_guard(proof)
    return plan

def refresh():
    package_command(['/usr/bin/apt-get'] + APT_OPTIONS + ['-o', 'APT::Update::Error-Mode=any', 'update'], 'refresh')

def php_stage():
    import php74_to8_runner_v10 as php
    import php74_to8_packages_v10 as pkg
    current = packages()
    branches = sorted({guard.php_branch(n) for n in current if guard.php_branch(n)})
    need(not any(branch not in ('7.4', '8.2', '8.3', '8.4', '8.5') for branch in branches),
         'PHP_branch_needs_separate_migration_profile')
    if '7.4' in branches:
        job = BASE / 'php-migration'
        need(not job.exists(), 'partial_PHP_migration_requires_review_no_blind_retry')
        job.mkdir(mode=0o700)
        # The migration's own reviewed transaction hooks are stricter than the
        # general updater: exact packages, origins, hashes, routes and workers.
        return php.migrate(job)
    findings = []
    for branch in branches:
        import php74_to8_routing_v10 as routing
        discovery = routing.audit_existing_target_nginx('/', branch)
        specs = php.health_specs(discovery)
        before_health = php.health(specs)
        pkg.verify_installed_target(pkg.Backend(), branch)
        unit = 'php' + branch + '-fpm'
        if run(['/bin/systemctl', 'is-active', unit], check=False).strip() == 'active':
            run(['/usr/sbin/php-fpm' + branch, '-t'])
            run(['/bin/systemctl', 'reload', unit])
            php.wait_reloaded_runtime(branch)
        php.comparable_health(before_health, php.health(specs))
        findings.append(dict(branch=branch, installed_security_version_verified=True))
    return dict(branches=findings)

def node_stage():
    cache = apt_cache()
    if 'nodejs' not in cache or not cache['nodejs'].installed:
        return dict(status='not-installed', scope='APT nodejs')
    package = cache['nodejs']
    candidate = package.candidate
    authenticated(candidate, identity()['codename'])
    installed = package.installed.version
    target = node.node_major(installed) if node.node_major(installed) in node.SUPPORTED_MAJORS else node.REPLACEMENT_MAJOR
    if node.node_major(candidate.version) != target:
        preflight = node.collect_apt_snapshot(dict(installed=installed, candidate=candidate.version))
        need(preflight.get('inventory_complete') is True and
             preflight.get('compatibility', {}).get('checked') is True and
             not preflight.get('compatibility', {}).get('blockers'),
             'Node_major_migration_consumer_review_required_before_source_change')
        # Only an already trusted NodeSource installation can reuse its pinned
        # signing key. Ubuntu packages need a separate trust bootstrap.
        need(any('nodesource' in origin.site for origin in candidate.origins), 'NodeSource_trust_bootstrap_required')
        source_plans = []
        for source in list(Path('/etc/apt/sources.list.d').glob('*.list')) + list(Path('/etc/apt/sources.list.d').glob('*.sources')):
            content = source.read_text()
            if re.search(r'https://deb\.nodesource\.com/node_' + str(node.node_major(installed)) + r'\.x', content):
                source_plans.append(node.plan_nodesource_migration(str(source), content, node.node_major(installed),
                                    '6F71F525282841EEDAF851B42F59B5F99B1BE0B4', old_origin_authenticated=True))
        need(len(source_plans) == 1, 'one_explicit_NodeSource_repository_required')
        node.apply_nodesource_migration(source_plans[0])
        refresh()
        cache = apt_cache(); package = cache['nodejs']; candidate = package.candidate
        authenticated(candidate, identity()['codename'])
        need(node.node_major(candidate.version) == target, 'authenticated_Node24_candidate_unavailable')
    simulation = apt_plan('node', candidate.version)
    evidence = dict(installed=installed, candidate=candidate.version, authenticated=True, source_approved=True,
                    metadata_fresh=True, held='nodejs' in run(['/usr/bin/apt-mark', 'showhold']).splitlines(),
                    candidate_newer=run(['/usr/bin/dpkg', '--compare-versions', candidate.version, 'gt', installed], check=False, capture=False) == 0,
                    simulation=dict(ok=True, removals=[], changes=simulation['pins']))
    snap = node.collect_apt_snapshot(evidence)
    plan = node.plan_node(snap)
    write_json(BASE / 'node-plan.json', dict(snapshot=snap, plan=plan))
    need(plan['ready'], 'node_runtime_review_required:' + ';'.join(plan['blockers']))
    if plan['actions']:
        package_update('node', candidate.version)
    return dict(status='package-verified', plan=plan, running_workers_verified=not snap.get('running_worker_paths'))

def state_update(state, **values):
    state.update(values)
    state['updated_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    write_json(BASE / 'state.json', state)

def work_stage(state, name, callback):
    state_update(state, operation=name, operation_running=True)
    emit(name, 'started')
    result = callback()
    write_json(BASE / ('result-' + name + '.json'), result if result is not None else {})
    if name == 'php' and isinstance(result, dict) and result.get('status') == 'PHP74_REPLACED_WITH_SECURE_PHP8':
        target = 'php' + result['target_branch'] + '-fpm.service'
        expected = state.get('expected_services', state['services'])
        state['expected_services'] = sorted({target if unit == 'php7.4-fpm.service' else unit for unit in expected})
    state_update(state, operation_running=False, completed=state['completed'] + [name])
    emit(name, 'complete')
    return result

def worker():
    need(os.geteuid() == 0, 'root_required')
    private_directory(BASE)
    fd = os.open(BASE / 'worker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    shared = Path('/run/visionline-php-patch-v6')
    private_directory(shared)
    php_lock = os.open(shared / 'worker.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    fcntl.flock(php_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    state = guard.read_private(BASE / 'state.json')
    need(identity()['machine_id'] == state['identity']['machine_id'] and droplet_id() == state['droplet_id'], 'host_identity_drift')
    need(state.get('status') in ('queued', 'waiting-reboot'), 'no_automatic_retry_after_failure')
    need(not state.get('operation_running'), 'interrupted_package_operation_requires_review')
    old_workflow()
    saved = BASE / 'unattended-state.json'
    try:
        if saved.exists():
            unattended.restore_timers(unattended.System(), unattended.load_state(saved))
            saved.rename(BASE / ('unattended-state-' + str(time.time_ns()) + '.json'))
        unattended.prepare(unattended.System(), saved, 60, True)
        state_update(state, status='running')
        snap = snapshot()
        need(snap['dpkg_clean'] and not snap['holds'], 'unclean_dpkg_or_held_packages')
        need(not any(n.startswith('libapache2-mod-php') for n in snap['packages']), 'Apache_PHP_requires_separate_migration_profile')
        # OS adapter is responsible for signed next-LTS frontend and precommit
        # validation; its durable receipt gates every reboot and next hop.
        os_result = run_os(state, snap)
        if os_result == 'waiting-reboot':
            return
        if 'packages' not in state['completed']:
            refresh()
            work_stage(state, 'packages', package_update)
            config_tests(); assert_services(state['services']); check_health(state['health'])
        if 'php' not in state['completed']:
            work_stage(state, 'php', php_stage)
        if 'node' not in state['completed']:
            work_stage(state, 'node', node_stage)
        need(not run(['/usr/bin/dpkg', '--audit']).strip(), 'final_dpkg_audit_failed')
        assert_services(state.get('expected_services', state['services']))
        config_tests(); check_health(state['health'])
        after = snapshot()
        need(after['release'] == '24.04', 'target_OS_not_reached')
        if after['reboot_required']:
            previous = state.get('final_reboot')
            need(not previous or previous['boot_id'] != after['boot_id'], 'final_reboot_not_completed')
            state_update(state, status='waiting-reboot', final_reboot=dict(boot_id=after['boot_id']))
            return
        if state.get('final_reboot'):
            need(state['final_reboot']['boot_id'] != after['boot_id'], 'final_new_boot_not_verified')
            current_target_kernel()
        restarted = refresh_live_services(state.get('expected_services', state['services']))
        config_tests(); check_health(state['health'])
        report = dict(status='completed', before=state['identity'], after=after,
                      completed=state['completed'], reboot_required=after['reboot_required'], restarted_services=restarted,
                      coverage='Ubuntu and configured APT packages; supported PHP profile; APT Node',
                      excluded='Application dependencies, WordPress/plugins/themes, containers and custom runtimes',
                      additional_PHP_advisory='2026-10-23 session upload progress configuration advisory requires separate effective-setting verification')
        write_json(BASE / 'report.json', report)
        state_update(state, status='completed')
        run(['/bin/systemctl', 'disable', UNIT])
        emit('updater', 'completed', report=str(BASE / 'report.json'))
    except Exception as error:
        code = str(error) if isinstance(error, (UpdateError, guard.PolicyError, unattended.HandoffError)) else type(error).__name__
        state_update(state, status='failed-needs-review', error=code)
        emit('updater', 'failed-needs-review', reason=code)
        run(['/bin/systemctl', 'disable', UNIT], check=False)
        raise UpdateError(code)
    finally:
        if saved.exists():
            unattended.restore_timers(unattended.System(), unattended.load_state(saved))
        os.close(php_lock); os.close(fd)
        if state.get('status') == 'waiting-reboot':
            emit('reboot', 'scheduled-after-saved-checkpoint')
            run(['/bin/systemctl', '--no-block', 'reboot'])

def run_os(state, snap):
    if state.get('os_complete'):
        need(snap['release'] == '24.04', 'completed_OS_target_drift')
        return 'complete'
    receipt = state.get('os_receipt')
    decision = os_upgrade.plan(snap, receipt)
    if decision['action'] == 'verify-hop':
        capture_path = Path(state['os_capture'])
        preserved = support.restore_verify(guard.read_private(capture_path / 'manifest.json'), capture_path, snap['codename'])
        need(preserved['configuration_preserved'] and preserved['vendor_sources_restored'], 'OS_postboot_configuration_or_sources_require_review')
        assert_services(state['services']); config_tests(); check_health(state['health'])
        accepted = os_upgrade.accept_boot(receipt, snap, dict(configuration_preserved=True, services=True,
                   boot_targets=boot_targets(), target_kernel=current_target_kernel(), vendor_sources_restored=True))
        state_update(state, os_receipt=accepted)
        receipt = accepted
        decision = os_upgrade.plan(snapshot(), receipt)
    if decision['action'] == 'complete':
        state_update(state, os_complete=True)
        return 'complete'
    need(decision['action'] in ('upgrade', 'reboot'), 'OS_upgrade_held:' + decision.get('reason', 'unknown'))
    if decision['action'] == 'reboot':
        prior = state.get('prerequisite_reboot')
        if prior:
            need(prior['boot_id'] != snap['boot_id'], 'prerequisite_reboot_not_completed')
        state_update(state, status='waiting-reboot', prerequisite_reboot=dict(boot_id=snap['boot_id'], release=snap['release']))
        return 'waiting-reboot'
    # Bring the source release current before invoking its next LTS upgrader.
    stage = 'prepare-Ubuntu-' + snap['release']
    if stage not in state['completed']:
        refresh()
        work_stage(state, stage, package_update)
        config_tests(); assert_services(state['services']); check_health(state['health'])
        snap = snapshot()
        decision = os_upgrade.plan(snap, receipt)
        if decision['action'] == 'reboot':
            state_update(state, status='waiting-reboot', prerequisite_reboot=dict(boot_id=snap['boot_id'], release=snap['release']))
            return 'waiting-reboot'
        need(decision['action'] == 'upgrade', 'OS_prerequisites_not_ready')
    capture_path = BASE / ('config-before-' + snap['release'])
    need(not capture_path.exists(), 'existing_OS_configuration_capture_no_blind_retry')
    capture_path.mkdir(mode=0o700)
    manifest = support.capture(capture_path)
    write_json(capture_path / 'manifest.json', manifest)
    need(not manifest['gaps'], 'configuration_backup_coverage_gap_before_OS_commit')
    state_update(state, os_capture=str(capture_path))
    proof = install_guard(dict(packages=packages(), machine_id=snap['machine_id'], phase='os'))
    state_update(state, operation='OS-' + snap['release'], operation_running=True)
    post = {}
    def preflight(_):
        current = snapshot()
        need(current['machine_id'] == state['identity']['machine_id'], 'OS_preflight_identity_changed')
        assert_services(state['services']); config_tests(); check_health(state['health'])
        need(shutil.disk_usage('/').free >= 6 * 1024**3 and shutil.disk_usage('/boot').free >= 512 * 1024**2, 'OS_disk_space_insufficient')
        os_upgrade.guard_files(proof)
        return dict(identity=True, configuration_backup=True, package_guard=True, boot_targets=boot_targets(),
                    disk_space=True, services=True, no_active_installer=not unattended.System().locks())
    def postinstall(current_decision):
        post.update(support.restore_verify(manifest, capture_path, current_decision['to_codename']))
        need(post['configuration_preserved'] and post['vendor_sources_restored'], 'OS_configuration_or_vendor_sources_need_review')
        run(['/bin/systemctl', 'daemon-reload'])
        config_tests(); assert_services(state['services']); check_health(state['health'])
        return dict(identity=identity()['machine_id'] == state['identity']['machine_id'], configuration_preserved=True,
                    services=True, boot_targets=boot_targets(), vendor_sources_restored=True)
    try:
        backend = os_upgrade.NativeBackend(snapshot, preflight, postinstall)
        result = os_upgrade.execute(decision, BASE / ('OS-' + snap['release']), backend, proof)
        state_update(state, operation_running=False, os_receipt=result, status='waiting-reboot')
    finally:
        remove_guard(proof)
    return 'waiting-reboot'

def launch():
    need(os.geteuid() == 0, 'root_required')
    current = identity()
    need(digest(current['hostname'].lower().split('.', 1)[0].encode()) != '2c828ee62ed7f0f6ba7da40f2cabedb4b1744f78bdb94115daf502dae4079df5', 'host_marked_for_replacement')
    need(current['os_id'] == 'ubuntu' and current['release'] in ('20.04', '22.04', '24.04'), 'supported_Ubuntu_20_22_24_required')
    old_workflow()
    private_directory(BASE)
    need(not (BASE / 'state.json').exists(), 'existing_job_use_status_no_blind_retry')
    need(not GUARD_CONF.exists() and not GUARD_CONF.is_symlink(), 'existing_APT_guard_requires_review')
    snap = snapshot()
    need(snap['dpkg_clean'], 'unclean_dpkg_before_launch')
    config_tests()
    health = health_baseline()
    write_json(BASE / 'state.json', dict(schema=1, status='queued', identity=current, droplet_id=droplet_id(),
               services=snap['services'], health=health, completed=[], operation_running=False))
    unit = ('[Unit]\nDescription=VisionLine host Ubuntu and runtime updater\nAfter=network-online.target\nWants=network-online.target\n'
            '[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B ' + str(PAYLOAD / 'ubuntu_global.py') + ' --worker\n'
            'TimeoutStartSec=infinity\nTimeoutStopSec=infinity\nKillMode=process\nRestart=no\nUMask=0077\n'
            '[Install]\nWantedBy=multi-user.target\n')
    path = Path('/etc/systemd/system') / UNIT
    need(not path.exists() and not path.is_symlink(), 'existing_service_requires_review')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, 'w') as stream:
        stream.write(unit)
    run(['/bin/systemctl', 'daemon-reload'])
    run(['/bin/systemctl', 'enable', UNIT])
    run(['/bin/systemctl', 'start', '--no-block', UNIT])
    print('Updater started. Status: ubuntu-global-updater.sh --status')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group()
    mode.add_argument('--plan', action='store_true')
    mode.add_argument('--apply', action='store_true')
    mode.add_argument('--worker', action='store_true')
    mode.add_argument('--status', action='store_true')
    args = p.parse_args()
    if args.apply:
        launch()
    elif args.worker:
        worker()
    elif args.status:
        print(json.dumps(guard.read_private(BASE / 'state.json'), indent=2))
        run(['/bin/systemctl', '--no-pager', 'status', UNIT], check=False)
    else:
        value = snapshot()
        print(json.dumps(dict(mode='plan', production_changes=0, inventory=value,
                             OS=os_upgrade.plan(value), node=node.collect_snapshot()), indent=2))

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps(dict(status='stopped', reason=str(error) if isinstance(error, UpdateError) else type(error).__name__)))
        raise SystemExit(1)
