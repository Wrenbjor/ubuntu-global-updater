"""Shared pre-commit policy for APT and the native Ubuntu release frontend.

No network access, lock deletion, process signalling, or application execution.
The baseline is private, host-bound and supplied by the updater, never stdin.
"""
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

class PolicyError(Exception):
    pass

PROTECTED = re.compile(r'^(?:openssh-(?:server|sftp-server)|sudo|systemd(?:-|$)|ubuntu-(?:server|minimal)|linux-(?:generic|image-generic)|nginx(?:-|$)|apache2(?:-|$)|libapache2-mod-php|libphp|mysql(?:-|$)|mariadb(?:-|$)|postgresql(?:-|$)|redis(?:-|$)|php\d+\.\d+-fpm$|nodejs$|docker(?:-|\.)|containerd(?:-|$))')
DATABASE = re.compile(r'^(?:mysql|mariadb|postgresql|redis)(?:-|$)')
RUNTIME = re.compile(r'^php(\d+\.\d+)(?:-|$)')
def php_branch(name):
    match = re.match(r'^(?:php|libapache2-mod-php|libphp)(\d+\.\d+)(?:-|$)', name)
    return match.group(1) if match else None

def php_package(name):
    return name.startswith(('php', 'libphp', 'libapache2-mod-php'))

def need(value, code):
    if not value:
        raise PolicyError(code)

def engine_package(name):
    if name.startswith(('mysql-', 'mariadb-')):
        return bool(re.match(r'^(?:mysql|mariadb)-(?:community-)?(?:server|client)(?:-|$)', name))
    if name.startswith('postgresql'):
        return bool(re.fullmatch(r'postgresql(?:-client)?(?:-\d+)?', name))
    return name in ('redis', 'redis-server', 'redis-tools')

def major(name, version):
    """Engine compatibility line, not an Ubuntu packaging revision."""
    upstream = version.split(':', 1)[-1].split('-', 1)[0]
    numbers = re.match(r'^(\d+)(?:\.(\d+))?', upstream)
    need(numbers is not None, 'unparseable_database_version')
    parts = numbers.groups()
    # PostgreSQL uses major-only compatibility from 10; MySQL/MariaDB use x.y.
    if name.startswith('postgresql') and int(parts[0]) >= 10:
        return parts[0]
    if name.startswith('redis'):
        return parts[0]
    need(parts[1] is not None, 'ambiguous_database_version')
    return '.'.join(parts)

def validate_actions(actions, baseline, phase='patch'):
    """Pure policy API, also called before release-upgrader confirmChanges.

    actions: name, old (installed version or None), new (candidate or None),
    action in install/upgrade/remove. Unknown actions fail closed.
    """
    need(phase in ('patch', 'os', 'node', 'php'), 'invalid_policy_phase')
    installed = baseline['packages']
    seen = set()
    approved = baseline.get('approved_actions')
    if approved is not None:
        exact = {a['name']: (a.get('old'), a.get('new'), a['action']) for a in approved}
        need(len(exact) == len(approved), 'duplicate_approved_action')
    database_families = {n.split('-', 1)[0] for n in installed if engine_package(n)}
    for item in actions:
        name = item['name'].split(':', 1)[0]
        need(name not in seen, 'duplicate_package_action')
        seen.add(name)
        action, old, new = item['action'], item.get('old'), item.get('new')
        if php_package(name):
            need(not baseline.get('defer_php') or old == new and action == 'upgrade',
                 'PHP_package_changes_deferred_until_Ubuntu_24_04')
        if approved is not None:
            need(exact.get(name) == (old, new, action), 'package_action_outside_exact_plan')
        need(action in ('install', 'upgrade', 'remove'), 'unsupported_package_action')
        known = installed.get(name)
        if isinstance(known, dict):
            known = known['version']
        need(old == known, 'installed_package_baseline_changed')
        if action == 'remove':
            permitted_legacy = phase == 'php' and name.startswith('php7.4-')
            need(phase != 'os' or not php_package(name), 'PHP_removal_during_OS_upgrade_forbidden')
            need(phase != 'patch' and (permitted_legacy or not PROTECTED.match(name)), 'protected_package_removal')
            need(new is None and old is not None, 'malformed_removal')
            continue
        need(new is not None, 'missing_candidate_version')
        if old is not None:
            need(subprocess.run(['/usr/bin/dpkg', '--compare-versions', new, 'ge', old],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=5).returncode == 0, 'package_downgrade_refused')
        if engine_package(name):
            # Introducing a different DB engine or major alongside the old one
            # is a migration too. Compare family lines, including new subpackages.
            family = name.split('-', 1)[0]
            lines = {major(n, v['version'] if isinstance(v, dict) else v)
                     for n, v in installed.items() if n.split('-', 1)[0] == family and engine_package(n)}
            need(family in database_families and len(lines) == 1 and major(name, new) in lines,
                 'database_major_change_requires_separate_migration')
        if name == 'nodejs' and old is not None:
            before = old.split(':', 1)[-1].split('.')[0]
            after = new.split(':', 1)[-1].split('.')[0]
            expected = str(baseline.get('node_target_major', before)) if phase == 'node' else before
            need(after == expected, 'unplanned_node_major_change')
        branch = php_branch(name)
        if branch and old is None:
            branches = {php_branch(n) for n in installed if php_branch(n)}
            allowed = set(baseline.get('php_target_branches', [])) if phase == 'php' else branches
            need(branch in allowed, 'unplanned_php_branch_install')
    return True

def read_private(path):
    path = Path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        need(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o077
             and info.st_nlink == 1 and info.st_size <= 8 * 1024 * 1024, 'unsafe_guard_baseline')
        raw = stream.read(8 * 1024 * 1024 + 1)
    need(len(raw) <= 8 * 1024 * 1024, 'oversized_guard_baseline')
    return json.loads(raw)

def protocol_actions(raw, baseline):
    lines = raw.splitlines()
    need(lines and lines[0] == 'VERSION 2' and '' in lines[1:], 'APT_protocol_2_required')
    rows = lines[lines.index('', 1) + 1:]
    result = []
    for line in rows:
        if not line:
            continue
        fields = line.split()
        need(len(fields) == 5, 'malformed_APT_package_action')
        name, old, direction, new, artifact = fields
        need(direction in ('<', '=', '>'), 'invalid_APT_version_direction')
        need(direction != '>', 'package_downgrade_refused')
        if artifact == '**CONFIGURE**':
            configure = dict(name=name, old=None if old == '-' else old, new=None if new == '-' else new,
                             action='install' if old == '-' else 'upgrade')
            validate_actions([configure], baseline, baseline['phase'])
            continue
        if artifact == '**REMOVE**':
            result.append(dict(name=name, old=None if old == '-' else old, new=None, action='remove'))
            continue
        need(artifact.startswith('/') and artifact.endswith('.deb') and new != '-', 'unverifiable_APT_archive')
        proc = subprocess.run(['/usr/bin/dpkg-deb', '-f', artifact, 'Package', 'Version'],
                              stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
        need(proc.returncode == 0, 'cannot_inspect_APT_archive')
        values = proc.stdout.decode().splitlines()
        values = [v.split(': ', 1)[-1] for v in values]
        need(values == [name.split(':', 1)[0], new], 'APT_archive_identity_mismatch')
        result.append(dict(name=name, old=None if old == '-' else old, new=new,
                           action='install' if old == '-' else 'upgrade'))
    return result

def main():
    try:
        need(len(sys.argv) == 3 and sys.argv[1] == 'hook', 'guard_hook_usage')
        baseline = read_private(sys.argv[2])
        need(Path('/etc/machine-id').read_text().strip() == baseline['machine_id'], 'guard_host_identity_changed')
        raw = sys.stdin.read(16 * 1024 * 1024 + 1)
        need(len(raw) <= 16 * 1024 * 1024, 'oversized_APT_protocol')
        validate_actions(protocol_actions(raw, baseline), baseline, baseline['phase'])
        return 0
    except Exception as error:
        code = str(error) if isinstance(error, PolicyError) else 'local_guard_error'
        print('VisionLine package transaction stopped: ' + code, file=sys.stderr)
        return 42

if __name__ == '__main__':
    raise SystemExit(main())
