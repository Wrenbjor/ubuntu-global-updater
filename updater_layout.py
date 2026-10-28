"""Read-only, Python 3.6-compatible updater namespace compatibility.

Selection is not an installation safety approval.  The installer must still
validate ownership, exact old payload/wrapper bytes and absence of job state.
No environment variable influences namespace selection.
"""
import os
from pathlib import Path

GENERIC_BASE = '/var/lib/ubuntu-global-updater'
LEGACY_BASE = '/var/lib/visionline-global-updater'
GENERIC_UNIT = 'ubuntu-global-updater.service'
LEGACY_UNIT = 'visionline-global-updater.service'
GENERIC_GUARD_CONF = '/etc/apt/apt.conf.d/99ubuntu-global-updater-guard'
LEGACY_GUARD_CONF = '/etc/apt/apt.conf.d/99visionline-global-guard'
GENERIC_ENVKEY = 'UBUNTU_UPDATER_INSTALLER_FD'
LEGACY_ENVKEY = 'VISIONLINE_INSTALLER_FD'
GENERIC_SHARED_LOCK = '/run/ubuntu-php-updater/worker.lock'
LEGACY_SHARED_LOCK = '/run/visionline-php-patch-v6/worker.lock'


class LayoutError(ValueError):
    pass


def layout(base=GENERIC_BASE):
    """Return a new structured layout for one of the two exact known bases."""
    base = str(base)
    if base == GENERIC_BASE:
        unit, guard, envkey = GENERIC_UNIT, GENERIC_GUARD_CONF, GENERIC_ENVKEY
    elif base == LEGACY_BASE:
        unit, guard, envkey = LEGACY_UNIT, LEGACY_GUARD_CONF, LEGACY_ENVKEY
    else:
        raise LayoutError('unknown_updater_base')
    return dict(base=base, unit=unit, guard=guard, envkey=envkey,
                shared_lock_paths=[GENERIC_SHARED_LOCK, LEGACY_SHARED_LOCK])


def runtime_layout(module_path=None):
    """Use only the exact deployment directory; development paths are generic.

    Do not resolve a caller-controlled symlink into a legacy deployment.  File
    integrity and symlink rejection belong to the payload verifier.
    """
    path = os.path.abspath(str(__file__ if module_path is None else module_path))
    parent = os.path.dirname(path)
    for base in (GENERIC_BASE, LEGACY_BASE):
        if parent == base + '/payload':
            return layout(base)
    return layout()


def _physical(root, absolute):
    root = Path(root)
    if not root.is_absolute():
        raise LayoutError('absolute_fixture_root_required')
    return root / absolute.lstrip('/')


def _present(path):
    """lstat treats dangling symlinks as artifacts; unexpected errors propagate."""
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def namespace_artifacts(base, root='/'):
    """Return logical artifact paths, without following final symlinks/writing."""
    chosen = layout(base)
    paths = [chosen['base'], chosen['guard']]
    for directory in ('/etc/systemd/system', '/run/systemd/system'):
        unit = directory + '/' + chosen['unit']
        paths.extend((unit, unit + '.d'))
    return [path for path in paths if _present(_physical(root, path))]


def installer_layout(root='/'):
    """Refuse mixed namespaces before writes; otherwise retain legacy in place."""
    generic = namespace_artifacts(GENERIC_BASE, root)
    legacy = namespace_artifacts(LEGACY_BASE, root)
    if generic and legacy:
        raise LayoutError('mixed_updater_namespaces')
    return layout(LEGACY_BASE if legacy else GENERIC_BASE)


def existing_shared_lock_paths(root='/'):
    """New lock is mandatory; also lock old namespace if its directory exists.

    The caller must open/validate/flock each returned path, then recheck layout
    before every stage.  This helper never creates the legacy directory.  Its
    dangling symlink/unsafe type is deliberately included for caller rejection.
    Checking its parent also covers an old worker that has not opened its lock.
    """
    paths = [GENERIC_SHARED_LOCK]
    old = _physical(root, LEGACY_SHARED_LOCK)
    if _present(old) or _present(old.parent):
        paths.append(LEGACY_SHARED_LOCK)
    return paths


def shared_lock_paths(root='/'):
    """Integration alias: mandatory new lock and any existing legacy lock."""
    return existing_shared_lock_paths(root)


def wrapper(base=GENERIC_BASE):
    """Known exact wrapper bytes, preserving the legacy deployment in place."""
    chosen = layout(base)
    return ('#!/bin/bash\nset -euo pipefail\nexec /usr/bin/python3 -B ' +
            chosen['base'] + '/payload/ubuntu_global.py "$@"\n').encode('ascii')
