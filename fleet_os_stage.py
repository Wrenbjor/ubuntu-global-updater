"""Separate PHP-first OS lifecycle. No installer is selected by this module.

A production backend must authenticate a target-suite package plan, preserve the
PHP runtime and database majors, and use the authenticated Ubuntu upgrader.
Backend methods are deliberately mandatory; this is not a shell-command escape
hatch. Existing install.sh retains its legacy 24.04-only semantics.
"""
import copy
import fcntl
import hashlib
import json
import os
import stat
from pathlib import Path

TARGET_PHP = '8.5.12'
HOPS = {'22.04': ('24.04', 'noble'), '24.04': ('26.04', 'resolute')}
SUITES = {'22.04': 'jammy', '24.04': 'noble', '26.04': 'resolute'}
PREFLIGHT = ('backup_verified', 'boot_recovery_verified', 'disk_space_verified',
             'packages_fully_updated', 'database_majors_preserved',
             'native_adapter_verified', 'configuration_backup_verified')
POSTFLIGHT = ('configuration_preserved', 'database_majors_preserved',
              'vendor_sources_restored', 'services_healthy', 'application_health_verified')


class Hold(RuntimeError):
    pass


def require(value, reason):
    if not value:
        raise Hold(reason)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def php_ready(snapshot, suite):
    """Require runtime, routing AND package provenance, not merely `php -v`."""
    php = snapshot.get('php', {})
    require(php.get('cli_version') == TARGET_PHP, 'CLI_not_exact_PHP_8_5_12')
    versions = php.get('active_fpm_versions')
    require(isinstance(versions, dict) and bool(versions)
            and all(v == TARGET_PHP for v in versions.values()), 'FPM_not_exact_PHP_8_5_12')
    require(php.get('all_nginx_routes_verified') is True, 'Nginx_PHP_routes_not_verified')
    require(php.get('modules_verified') is True, 'PHP_modules_not_verified')
    require(php.get('package_suite') == suite and php.get('packages_authenticated') is True,
            'PHP_same_suite_authenticated_packages_required')


def clean(snapshot):
    require(snapshot.get('dpkg_clean') is True, 'dpkg_not_clean')
    require(snapshot.get('active_package_work') is False, 'package_work_active_or_unknown')
    require(snapshot.get('holds') == [], 'package_holds_require_review')


def plan(snapshot, state=None):
    """Pure next step; target 26.04 never means skip the 24.04 checkpoint."""
    require(snapshot.get('ubuntu') is True and snapshot.get('release') in SUITES,
            'supported_Ubuntu_22_24_26_required')
    require(snapshot.get('machine_id') and snapshot.get('boot_id'), 'host_and_boot_identity_required')
    release = snapshot['release']
    if state is not None:
        require(state.get('schema') == 1 and state.get('stage') == 'fleet-os-php-first',
                'legacy_or_unknown_checkpoint_preserved')
        require(state.get('machine_id') == snapshot['machine_id'], 'checkpoint_machine_mismatch')
        require(state.get('from_release') in HOPS
                and state.get('to_release') == HOPS[state['from_release']][0], 'checkpoint_path_invalid')
        status = state.get('status')
        require(status in ('pending-reboot', 'boot-verified'), 'interrupted_or_failed_job_preserved')
        require(release == state['to_release'], 'checkpoint_release_drift')
        if status == 'pending-reboot':
            if snapshot['boot_id'] == state['boot_id']:
                return {'action': 'reboot-required', 'to_release': release}
            return {'action': 'verify-boot', 'to_release': release}
        require(state.get('accepted_boot_id'), 'verified_boot_receipt_invalid')
        # Further ordinary reboots are allowed, but never bypass fresh health checks.
    require(snapshot.get('legacy_workflow_clear') is True, 'legacy_partial_workflow_requires_review')
    clean(snapshot)
    php_ready(snapshot, SUITES[release])
    if snapshot.get('reboot_required') is not False:
        return {'action': 'reboot-required', 'to_release': release}
    if release == '26.04':
        return {'action': 'complete', 'release': release, 'php': TARGET_PHP, 'OS_only': True}
    target, suite = HOPS[release]
    return {'action': 'prepare-hop', 'from_release': release, 'to_release': target,
            'target_suite': suite, 'snapshot_sha256': digest(snapshot), 'OS_only': True}


def proofs(values, keys):
    require(isinstance(values, dict) and all(values.get(k) is True for k in keys),
            'missing_verified_backend_proof')


def preservation(prepared, snapshot, decision):
    """Every currently installed versioned PHP package needs a target candidate.

    Independent extensions have their own versions; the backend must distinguish
    them from core packages. No guessed apt package revision or PPA filename.
    """
    require(prepared.get('target_suite') == decision['target_suite'], 'target_suite_mismatch')
    require(prepared.get('snapshot_sha256') == digest(snapshot), 'package_plan_baseline_changed')
    installed = snapshot.get('php', {}).get('installed_packages')
    candidates = prepared.get('php_candidates')
    require(isinstance(installed, list) and bool(installed)
            and len(set(installed)) == len(installed), 'PHP_package_inventory_required')
    require(isinstance(candidates, dict) and set(candidates) == set(installed),
            'complete_PHP_package_preservation_required')
    require({'php8.5-cli', 'php8.5-common', 'php8.5-fpm'} <= set(installed), 'PHP_core_packages_missing')
    for name, value in candidates.items():
        require(name.startswith('php8.5-') and isinstance(value, dict), 'unexpected_PHP_package')
        require(value.get('authenticated') is True and value.get('suite') == decision['target_suite']
                and value.get('version'), 'target_PHP_package_unavailable_or_untrusted')
        require(type(value.get('core')) is bool, 'PHP_package_classification_required')
        if value['core'] or name in ('php8.5-cli', 'php8.5-common', 'php8.5-fpm'):
            require(value.get('upstream_version') == TARGET_PHP, 'target_PHP_not_exact_8_5_12')
    proofs(prepared, PREFLIGHT)


class Store:
    """Private durable, locked state. Caller must hold lock for the whole run."""
    def __init__(self, directory):
        self.directory = Path(directory)
        require(self.directory.is_absolute(), 'absolute_state_directory_required')
        self.lockfd = None

    def __enter__(self):
        # Do not create arbitrary root hierarchies or follow symlinks.
        require(self.directory.parent.resolve() == self.directory.parent, 'unsafe_state_parent')
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        require(self.directory.resolve() == self.directory and self.directory.is_dir()
                and info.st_uid == os.geteuid() and not info.st_mode & 0o077, 'unsafe_state_directory')
        self.lockfd = os.open(str(self.directory / 'lock'), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            lockinfo = os.fstat(self.lockfd)
            require(stat.S_ISREG(lockinfo.st_mode) and lockinfo.st_uid == os.geteuid()
                    and not lockinfo.st_mode & 0o077 and lockinfo.st_nlink == 1, 'unsafe_state_lock')
            fcntl.flock(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(self.lockfd)
            self.lockfd = None
            raise
        return self

    def __exit__(self, *args):
        os.close(self.lockfd)
        self.lockfd = None

    def read(self):
        require(self.lockfd is not None, 'state_lock_required')
        path = self.directory / 'state.json'
        try:
            fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        with os.fdopen(fd, 'r') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077
                    and info.st_nlink == 1 and info.st_size < 1048576, 'unsafe_state_file')
            return json.load(stream)

    def write(self, value):
        require(self.lockfd is not None, 'state_lock_required')
        path = self.directory / 'state.next'
        # An interrupted write is not silently replaced or retried.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(path), str(self.directory / 'state.json'))
        fd = os.open(str(self.directory), os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def advance(backend, store, apply=False):
    """One action per invocation. Never reboot or start the next hop here.

    Backend.prepare is read-only and authenticates the next suite in an isolated
    apt cache. Backend.upgrade owns the durable native worker and same-suite PHP
    restoration. No built-in production backend is provided until VM validation.
    """
    before = backend.snapshot()
    state = store.read()
    decision = plan(before, state)
    if decision['action'] == 'verify-boot':
        clean(before)
        require(before.get('reboot_required') is False, 'postboot_reboot_still_required')
        php_ready(before, SUITES[before['release']])
        proofs(backend.verify(state), POSTFLIGHT + ('target_kernel_verified',))
        if apply:
            accepted = dict(state, status='boot-verified', accepted_boot_id=before['boot_id'])
            store.write(accepted)
        return dict(decision, verified=True, saved=apply, next_hop_requires_new_invocation=True)
    if decision['action'] != 'prepare-hop':
        return decision
    prepared = backend.prepare(decision)
    preservation(prepared, before, decision)
    if not apply:
        return dict(decision, preflight='verified', package_plan_sha256=digest(prepared))
    require(digest(backend.snapshot()) == digest(before), 'live_baseline_changed')
    previous = copy.deepcopy(state)
    state = dict(schema=1, stage='fleet-os-php-first', status='installing',
                 machine_id=before['machine_id'], boot_id=before['boot_id'],
                 from_release=before['release'], to_release=decision['to_release'],
                 package_plan_sha256=digest(prepared), previous_checkpoint=previous)
    store.write(state)  # Fail closed on interruption BEFORE the first mutation.
    try:
        backend.upgrade(decision, prepared)
        after = backend.snapshot()
        require(after.get('machine_id') == before['machine_id']
                and after.get('boot_id') == before['boot_id']
                and after.get('release') == decision['to_release'], 'hop_exit_identity_or_release_mismatch')
        clean(after)
        php_ready(after, decision['target_suite'])
        proofs(backend.verify(state), POSTFLIGHT)
        state.update(status='pending-reboot')
        store.write(state)
        return {'action': 'reboot-required', 'to_release': decision['to_release'],
                'automatic_reboot': False, 'next_hop_requires_new_invocation': True}
    except BaseException:
        state.update(status='failed-preserve-no-retry')
        store.write(state)
        raise
