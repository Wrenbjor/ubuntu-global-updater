"""Read-only Ubuntu/native-WSL planning; compatible with Python 3.6.

No service, bootloader, package or host-control commands are executed here.
The orchestrator persists returned checkpoints before requesting user action.
Native boot verification remains the existing native updater's responsibility.
"""
import hashlib
import json
import os
import re
from pathlib import Path

HOPS = {'18.04': '20.04', '20.04': '22.04', '22.04': '24.04'}
SUPPORTED_RELEASES = tuple(HOPS) + ('24.04',)
BOOT_ID = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


class PlatformError(ValueError):
    pass


def _require(condition, code):
    if not condition:
        raise PlatformError(code)


def _read(root, name, optional=False):
    path = Path(root) / name.lstrip('/')
    try:
        with path.open('rb') as stream:
            data = stream.read(16385)
    except FileNotFoundError:
        if optional:
            return ''
        raise PlatformError('missing_platform_evidence')
    _require(len(data) <= 16384 and b'\0' not in data, 'invalid_platform_evidence')
    try:
        return data.decode('utf-8').strip()
    except UnicodeDecodeError:
        raise PlatformError('invalid_platform_encoding')


def _os_release(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        _require('=' in line, 'invalid_os_release')
        key, value = line.split('=', 1)
        _require(key not in values, 'duplicate_os_release_key')
        if value[:1] in ('"', "'"):
            _require(len(value) >= 2 and value[-1:] == value[:1], 'invalid_os_release_quote')
            value = value[1:-1]
        values[key] = value
    _require(values.get('ID') == 'ubuntu', 'ubuntu_required')
    release = values.get('VERSION_ID')
    _require(release in SUPPORTED_RELEASES, 'unsupported_ubuntu_release')
    return release


def _instance(root):
    stat = _read(root, '/proc/1/stat')
    _require(stat.startswith('1 (') and ')' in stat, 'invalid_pid1_stat')
    fields = stat.rsplit(')', 1)[1].split()
    _require(len(fields) > 19 and fields[19].isdigit() and int(fields[19]) > 0,
             'invalid_pid1_start_ticks')
    proof = dict(pid1_start_ticks=fields[19])
    for kind in ('pid', 'mnt'):
        try:
            link = os.readlink(str(Path(root) / 'proc/1/ns' / kind))
        except OSError:
            raise PlatformError('missing_wsl_instance_namespace')
        _require(re.match(r'^' + kind + r':\[[0-9]+\]$', link) is not None,
                 'invalid_wsl_instance_namespace')
        proof[kind + '_namespace'] = link
    proof['sha256'] = _instance_digest(proof)
    return proof


def _instance_digest(proof):
    _require(isinstance(proof, dict), 'wsl_instance_required')
    fields = {key: proof.get(key) for key in ('pid1_start_ticks', 'pid_namespace', 'mnt_namespace')}
    _require(isinstance(fields['pid1_start_ticks'], str) and fields['pid1_start_ticks'].isdigit()
             and int(fields['pid1_start_ticks']) > 0, 'invalid_pid1_start_ticks')
    for kind in ('pid', 'mnt'):
        _require(isinstance(fields[kind + '_namespace'], str) and
                 re.match(r'^' + kind + r':\[[0-9]+\]$', fields[kind + '_namespace']) is not None,
                 'invalid_wsl_instance_namespace')
    return hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(',', ':')).encode('ascii')).hexdigest()


def _wsl_local_marker(root):
    # Custom WSL kernels can omit Microsoft text. Their real local interop
    # artifacts are a reason to HOLD, never a reason to trust environment or
    # waive native proof under an otherwise unclassified kernel.
    for name in ('/proc/sys/fs/binfmt_misc/WSLInterop', '/run/WSL'):
        try:
            (Path(root) / name.lstrip('/')).lstat()
            return True
        except FileNotFoundError:
            pass
    return False


def detect(root='/'):
    """Read kernel/OS evidence. WSL environment variables are never consulted."""
    _require(Path(root).is_absolute(), 'absolute_fixture_root_required')
    kernel = _read(root, '/proc/sys/kernel/osrelease')
    version = _read(root, '/proc/version', optional=True)
    boot_id = _read(root, '/proc/sys/kernel/random/boot_id').lower()
    _require(BOOT_ID.match(boot_id) is not None, 'invalid_boot_id')
    release = _os_release(_read(root, '/etc/os-release'))
    low = kernel.lower()
    if 'microsoft' in low:
        variant = 'wsl2' if ('wsl2' in low or 'microsoft-standard' in low) else 'wsl1'
    else:
        # A token only in /proc/version or the environment is insufficient to
        # waive native boot proof. Ambiguous kernel evidence fails closed.
        _require(not _wsl_local_marker(root) and
                 not re.search(r'(?i)microsoft|\bwsl[12]?\b', version + ' ' + kernel),
                 'ambiguous_wsl_kernel_evidence')
        variant = 'native'
    machine = _read(root, '/etc/machine-id', optional=True).lower()
    _require(not machine or re.match(r'^[0-9a-f]{32}$', machine), 'invalid_machine_id')
    return dict(schema=1, platform=variant, is_wsl=variant != 'native',
                ubuntu_release=release, boot_id=boot_id, machine_id=machine,
                kernel_release=kernel, instance=_instance(root) if variant != 'native' else None,
                kernel_owned_by_host=variant != 'native',
                skip_grub=variant != 'native',
                skip_ubuntu_running_kernel_proof=variant != 'native',
                automatic_reboot_allowed=variant == 'native',
                detection='local-kernel-and-os-release')


def _validate(profile):
    _require(isinstance(profile, dict), 'platform_profile_required')
    variant = profile.get('platform')
    _require(variant in ('native', 'wsl1', 'wsl2'), 'unknown_platform')
    _require(profile.get('ubuntu_release') in SUPPORTED_RELEASES, 'unsupported_ubuntu_release')
    _require(BOOT_ID.match(str(profile.get('boot_id', ''))) is not None, 'invalid_boot_id')
    if variant != 'native':
        proof = profile.get('instance')
        digest = _instance_digest(proof)
        _require(proof.get('sha256') == digest, 'wsl_instance_digest_mismatch')
    return variant


def workload_profile(web_servers=(), php_branches=(), apache_mode=None):
    """Validate caller's nonsecret inventory; not a workload compatibility proof.

    Apache route/handler validation and PHP migration remain separate modules.
    Paths, settings, environment, application source and customer rows are absent.
    """
    servers = sorted(set(web_servers))
    branches = sorted(set(php_branches))
    _require(all(x in ('nginx', 'apache2') for x in servers), 'unknown_web_server')
    _require(all(isinstance(x, str) and re.match(r'^\d+\.\d+$', x) for x in branches),
             'invalid_php_branch')
    _require(apache_mode in (None, 'fpm', 'mod_php', 'mixed', 'unknown'), 'unknown_apache_mode')
    _require('apache2' in servers or apache_mode is None, 'apache_mode_without_apache')
    return dict(web_servers=servers, php_branches=branches, apache_mode=apache_mode,
                compatibility_verified=False, runtime_changes_deferred_until='24.04')


def restart_checkpoint(profile, target_release):
    """WSL-only receipt: persist this before waiting for a manual WSL restart."""
    variant = _validate(profile)
    _require(variant != 'native', 'native_reboot_uses_existing_native_handler')
    _require(target_release in SUPPORTED_RELEASES, 'unsupported_restart_target')
    _require(target_release in (profile['ubuntu_release'], HOPS.get(profile['ubuntu_release'])),
             'nonsequential_restart_target')
    return dict(schema=1, stage='wsl-manual-restart', status='manual-restart-required',
                platform=variant, before_boot_id=profile['boot_id'],
                before_instance=dict(profile['instance']),
                machine_id=profile.get('machine_id', ''),
                from_release=profile['ubuntu_release'], target_release=target_release,
                automatic_reboot=False, host_shutdown_requested=False)


def accept_restart(profile, checkpoint):
    """Require a new distro instance and exact target, even on a shared kernel."""
    variant = _validate(profile)
    _require(isinstance(checkpoint, dict) and checkpoint.get('schema') == 1 and
             checkpoint.get('stage') == 'wsl-manual-restart' and
             checkpoint.get('status') == 'manual-restart-required', 'invalid_restart_checkpoint')
    _require(variant != 'native' and checkpoint.get('platform') == variant, 'restart_platform_changed')
    _require(checkpoint.get('automatic_reboot') is False and
             checkpoint.get('host_shutdown_requested') is False, 'invalid_restart_control_claim')
    before = checkpoint.get('before_boot_id', '')
    _require(BOOT_ID.match(str(before)) is not None, 'invalid_checkpoint_boot_id')
    _require(checkpoint.get('machine_id', '') == profile.get('machine_id', ''), 'restart_machine_changed')
    start, target = checkpoint.get('from_release'), checkpoint.get('target_release')
    _require(start in SUPPORTED_RELEASES and target in (start, HOPS.get(start)),
             'nonsequential_restart_target')
    old_instance = checkpoint.get('before_instance')
    old_digest = _instance_digest(old_instance)
    _require(old_instance.get('sha256') == old_digest, 'wsl_instance_digest_mismatch')
    _require(profile['instance']['sha256'] != old_digest, 'manual_restart_still_required')
    _require(profile['ubuntu_release'] == target, 'restart_target_release_not_reached')
    return dict(status='manual-restart-verified', platform=variant,
                before_boot_id=before, boot_id=profile['boot_id'], ubuntu_release=target,
                before_instance=old_instance, instance=profile['instance'],
                kernel_boot_id_changed=profile['boot_id'] != before,
                skip_grub=True, skip_ubuntu_running_kernel_proof=True)


def next_action(profile, checkpoint=None, workload=None):
    """Pure next step. No package work or restart is performed by this module."""
    variant = _validate(profile)
    is_wsl = variant != 'native'
    if checkpoint is not None:
        _require(isinstance(checkpoint, dict), 'invalid_restart_checkpoint')
        if profile.get('instance') == checkpoint.get('before_instance'):
            # Validate all fields even while waiting; do not conceal tampering.
            try:
                accept_restart(profile, checkpoint)
            except PlatformError as error:
                _require(str(error) == 'manual_restart_still_required', str(error))
            action = 'manual-restart-required'
        else:
            accept_restart(profile, checkpoint)
            action = 'resume-after-manual-restart'
    else:
        action = 'release-upgrade' if profile['ubuntu_release'] in HOPS else 'runtime-and-package-patch'
    if workload is None:
        safe_workload = workload_profile()
    else:
        _require(isinstance(workload, dict) and set(workload).issubset(
            {'web_servers', 'php_branches', 'apache_mode', 'compatibility_verified',
             'runtime_changes_deferred_until'}), 'invalid_workload_profile')
        safe_workload = workload_profile(workload.get('web_servers', ()),
                                        workload.get('php_branches', ()), workload.get('apache_mode'))
    return dict(action=action, platform=variant, current_release=profile['ubuntu_release'],
                next_release=HOPS.get(profile['ubuntu_release']),
                restart_mode='manual-wsl-restart' if is_wsl else 'existing-native-reboot',
                skip_grub=is_wsl, skip_ubuntu_running_kernel_proof=is_wsl,
                automatic_reboot_allowed=not is_wsl,
                workload=safe_workload)


def plan(profile, checkpoint=None, workload=None):
    return next_action(profile, checkpoint, workload)
