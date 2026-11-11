"""Supported-command OS backend, with mandatory host policy integration.

Uses Ubuntu's public do-release-upgrade entry point, never private DistUpgrade
classes, development releases, direct distro source rewrites or automatic reboots.
The host policy owns authenticated isolated APT planning, per-transaction guards,
PHP restoration and evidence collection. See README-fleet-os.md before integration.
"""
import os
from pathlib import Path
import re
import stat
import subprocess

from fleet_os_stage import digest, preservation, require

UPGRADER = '/usr/bin/do-release-upgrade'
ENVIRONMENT = dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME='/root', LANG='C', LC_ALL='C',
                   DEBIAN_FRONTEND='noninteractive', UCF_FORCE_CONFFOLD='1',
                   APT_LISTCHANGES_FRONTEND='none', NEEDRESTART_MODE='l',
                   RELEASE_UPGRADER_NO_SCREEN='1')


def open_native_log(path):
    """Create a new log relative to a verified, pinned private directory.

    Walk descriptors without following ancestor symlinks. Root-owned sticky
    directories such as /tmp may contain the private directory, but ordinary
    group/world-writable ancestors and non-private final directories are refused.
    """
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) > 1,
            'unsafe_native_log_path')
    directory = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        components = path.parts[1:-1]
        for index, component in enumerate(components):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory)
            os.close(directory)
            directory = child
            info = os.fstat(directory)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.geteuid()),
                    'unsafe_native_log_parent_owner')
            if index == len(components) - 1:
                require(info.st_uid == os.geteuid() and not info.st_mode & 0o077,
                        'private_native_log_parent_required')
            else:
                require(not info.st_mode & 0o022
                        or (info.st_uid == 0 and info.st_mode & stat.S_ISVTX),
                        'unsafe_native_log_ancestor')
        require(bool(components), 'private_native_log_parent_required')
        return os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                       0o600, dir_fd=directory)
    finally:
        os.close(directory)


class Commands:
    """The package-changing child deliberately has no timeout or kill path."""
    def __init__(self, log):
        self.log = Path(log)
        require(self.log.is_absolute(), 'absolute_native_log_required')

    def check(self, arguments):
        result = subprocess.run(arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=120, env=ENVIRONMENT)
        require(result.returncode == 0, 'native_readonly_check_failed')
        return result.stdout.decode('utf-8', errors='replace')

    def run_upgrade(self, arguments):
        fd = open_native_log(self.log)
        with os.fdopen(fd, 'wb') as output:
            child = subprocess.Popen(arguments, stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=subprocess.STDOUT, env=ENVIRONMENT)
            while True:
                try:
                    result = child.wait()
                    break
                except KeyboardInterrupt:
                    # Do not terminate dpkg. A retained service must own this worker.
                    continue
            output.flush()
            os.fsync(output.fileno())
        require(result == 0, 'native_release_upgrade_failed_preserve_no_retry')


def verify_installed_upgrader(commands):
    info = Path(UPGRADER).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            'unsafe_native_release_upgrader')
    owner = commands.check(['/usr/bin/dpkg-query', '-S', UPGRADER]).strip()
    require(owner == 'ubuntu-release-upgrader-core: ' + UPGRADER, 'unexpected_upgrader_package_owner')
    # dpkg --verify may exit zero even when it prints mismatched file checksums.
    require(not commands.check(['/usr/bin/dpkg', '--verify', 'ubuntu-release-upgrader-core']).strip(),
            'release_upgrader_package_modified')


def offered_release(output):
    matches = re.findall(r"New release ['\"](\d+\.\d+)(?:\.\d+)?(?: LTS)?['\"] available", output)
    require(len(matches) == 1, 'next_LTS_not_offered_or_unrecognized_response')
    return matches[0]


class SupportedReleaseBackend:
    """Concrete native execution; host policy cannot be omitted.

    policy.snapshot()/prepare()/verify() implement the lifecycle evidence contract.
    policy.guard(prepared) returns a context manager that protects EVERY native
    APT transaction and database major before invoking dpkg, including removals.
    policy.restore_php(prepared) restores only authenticated target-suite packages
    at the exact planned versions, and preserves Nginx/pools/INI/module settings.
    policy.retained_worker() must establish that systemd owns the long-running job.
    These methods must perform checks, not accept user-supplied evidence files.
    """
    def __init__(self, policy, commands, verifier=verify_installed_upgrader):
        self.policy = policy
        self.commands = commands
        self.verifier = verifier
        self.prepared_digest = None

    def snapshot(self):
        return self.policy.snapshot()

    def prepare(self, decision):
        self.verifier(self.commands)
        offered = offered_release(self.commands.check([UPGRADER, '--check-dist-upgrade-only']))
        require(offered == decision['to_release'], 'offered_release_not_expected_next_LTS')
        prepared = self.policy.prepare(decision)
        # Public command availability alone does NOT prove safe package migration.
        require(prepared.get('full_native_transaction_preflight_verified') is True,
                'native_full_transaction_preflight_required')
        require(prepared.get('native_reboot_policy_verified') is True,
                'native_frontend_no_automatic_reboot_proof_required')
        require(prepared.get('php_restore_plan_verified') is True,
                'PHP_target_restore_plan_required')
        prepared = dict(prepared, native_adapter_verified=True)
        preservation(prepared, self.snapshot(), decision)
        self.prepared_digest = digest(prepared)
        return prepared

    def upgrade(self, decision, prepared):
        require(self.prepared_digest == digest(prepared), 'native_prepared_plan_changed_or_missing')
        require(self.policy.retained_worker() is True, 'native_upgrade_requires_retained_worker')
        self.verifier(self.commands)
        require(offered_release(self.commands.check([UPGRADER, '--check-dist-upgrade-only']))
                == decision['to_release'], 'offered_release_changed')
        require(digest(self.snapshot()) == prepared['snapshot_sha256'], 'native_host_baseline_changed')
        # Never use -d. The release upgrader handles repositories and signed
        # release metadata. The guard blocks unplanned PHP/database changes.
        with self.policy.guard(prepared):
            self.commands.run_upgrade([UPGRADER, '--mode=server',
                                       '--frontend=DistUpgradeViewNonInteractive'])
            current = self.snapshot()
            require(current.get('release') == decision['to_release'], 'native_target_not_reached')
            self.policy.restore_php(prepared)
        # fleet_os_stage.advance performs exact CLI/FPM/provenance/health checks
        # and persists pending-reboot. No automatic reboot is requested here.

    def verify(self, state):
        return self.policy.verify(state)
