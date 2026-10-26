"""Private, bounded configuration preservation across Ubuntu release upgrades.

No network, package operations, service changes or general /etc restore. Manifest
and backups contain sensitive configuration; callers should emit only proof flags
and gap identifiers, never serialize their contents to a shared console.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from urllib.parse import urlsplit

TREES = ("/etc/nginx", "/etc/php", "/etc/mysql", "/etc/postgresql", "/etc/postgresql-common", "/etc/redis", "/etc/ssh", "/etc/systemd/system")
MAX_FILES = 100000
MAX_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


def _job(job):
    if isinstance(job, dict):
        job = job.get("directory") or job.get("path") or job.get("job_dir")
    return Path(job)


def _at(root, path):
    if not path.startswith("/") or ".." in Path(path).parts:
        raise ValueError("Invalid captured path")
    return Path(root) / path.lstrip("/")


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_dir(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise ValueError("Backup directory cannot be a symlink")
    os.chmod(path, 0o700)


def _safe_parents(path, root):
    """Never restore through a parent symlink into another configuration tree."""
    current = path.parent
    limit = Path(root).absolute()
    while current != limit:
        if current.is_symlink():
            raise ValueError("Configuration parent is a symlink")
        metadata = current.stat()
        if metadata.st_uid != limit.stat().st_uid or metadata.st_mode & 0o022:
            raise ValueError("Configuration parent ownership or permissions are unsafe")
        if current == current.parent:
            raise ValueError("Configuration path escaped fixture root")
        current = current.parent


def capture(job, *, root="/"):
    root = Path(root).absolute()
    store = _job(job).absolute() / "configuration-preservation"
    _private_dir(_job(job).absolute())
    if store.exists():
        raise ValueError("Configuration capture already exists; refusing to replace baseline")
    _private_dir(store)
    _private_dir(store / "objects")
    manifest = {"schema": 1, "store": str(store), "entries": [], "sources": [], "gaps": [], "source_codename": None}
    try:
        release = _at(root, "/etc/os-release").read_text()
        match = re.search(r"^VERSION_CODENAME=[\"']?([a-z]+)", release, re.M)
        manifest["source_codename"] = match.group(1) if match else None
    except OSError:
        manifest["gaps"].append("os_release_unreadable")
    paths = []
    for tree in TREES:
        base = _at(root, tree)
        if not base.exists() and not base.is_symlink():
            continue
        paths.append(tree)
        if base.is_dir() and not base.is_symlink():
            def failed(_error):
                manifest["gaps"].append("configuration_tree_unreadable:" + tree)
            for directory, dirs, files in os.walk(base, followlinks=False, onerror=failed):
                for name in dirs + files:
                    paths.append("/" + str((Path(directory) / name).relative_to(root)))
                if len(paths) > MAX_FILES:
                    raise ValueError("Configuration capture exceeds file limit")
    source_dir = _at(root, "/etc/apt/sources.list.d")
    source_paths = ["/etc/apt/sources.list"]
    if source_dir.exists():
        source_paths += ["/" + str(path.relative_to(root)) for path in sorted(source_dir.iterdir()) if path.suffix in (".list", ".sources")]
    for name in source_paths:
        source = _at(root, name)
        try:
            if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_BYTES:
                continue
            content, source_gaps = vendor_source_content(source.read_text(), source.suffix, manifest["source_codename"], manifest["source_codename"])
            manifest["gaps"].extend(gap + ":" + name for gap in source_gaps)
            if content:
                keys = re.findall(r"(?:signed-by=|^Signed-By:\s*)(/[^\s\]]+)", content, re.M | re.I)
                for key in keys:
                    if re.fullmatch(r"/(?:etc/apt/keyrings|usr/share/keyrings)/[A-Za-z0-9_.-]+\.(?:gpg|asc)", key):
                        if _at(root, key).is_file():
                            paths.append(str(Path(key).parent))
                            paths.append(key)
                        else:
                            manifest["gaps"].append("vendor_signing_key_missing:" + key)
                    else:
                        manifest["gaps"].append("vendor_signing_key_path_needs_review")
        except (OSError, UnicodeError):
            manifest["gaps"].append("source_capture_unreadable:" + name)
    total_bytes = 0
    for name in sorted(set(paths + source_paths)):
        source = _at(root, name)
        try:
            _safe_parents(source, root)
            info = source.lstat()
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            manifest["gaps"].append("configuration_path_unreadable:" + name)
            continue
        item = {"path": name, "uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
        if os.listxattr(source, follow_symlinks=False):
            manifest["gaps"].append("configuration_acl_or_xattrs_need_preservation:" + name)
            continue
        if stat.S_ISLNK(info.st_mode):
            item.update(kind="symlink", target=os.readlink(source))
        elif stat.S_ISDIR(info.st_mode):
            item["kind"] = "directory"
        elif stat.S_ISREG(info.st_mode):
            if info.st_nlink != 1:
                manifest["gaps"].append("configuration_hardlink_needs_review:" + name)
                continue
            if info.st_size > MAX_BYTES:
                manifest["gaps"].append("configuration_file_too_large:" + name)
                continue
            data = source.read_bytes()
            total_bytes += len(data)
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError("Configuration capture exceeds total byte limit")
            digest = _digest(data)
            obj = store / "objects" / digest
            if not obj.exists():
                with obj.open("xb") as stream:
                    os.chmod(obj, 0o600)
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            item.update(kind="file", sha256=digest)
        else:
            manifest["gaps"].append("configuration_special_file:" + name)
            continue
        manifest["sources" if name in source_paths else "entries"].append(item)
    target = store / "manifest.json"
    with target.open("x") as stream:
        os.chmod(target, 0o600)
        json.dump(manifest, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    for directory in (store / "objects", store, store.parent):
        _sync_directory(directory)
    return manifest


def _same_symlink_target(root, name, first, second):
    if first == second:
        # Identical existing link text is preserved, including baseline deliberate
        # masks/dangling links. Equivalence of changed link text needs actual files.
        return True
    if "/dev/null" in (first, second):
        return False
    def actual(target):
        parent = _at(root, name).parent
        return (_at(root, target) if target.startswith("/") else parent / target).resolve()
    left, right = actual(first), actual(second)
    return left.is_file() and right.is_file() and left == right


def _restore_item(item, root, store):
    path = _at(root, item["path"])
    _safe_parents(path, root)
    if item["kind"] == "directory":
        if path.is_symlink() or (path.exists() and not path.is_dir()):
            raise ValueError("Configuration directory type changed")
        path.mkdir(parents=True, exist_ok=True)
    elif item["kind"] == "symlink":
        same = path.is_symlink() and _same_symlink_target(root, item["path"], os.readlink(path), item["target"])
        if not same:
            if item["target"] == "/dev/null":
                raise ValueError("Refusing to create service mask")
            if path.exists() and path.is_dir() and not path.is_symlink():
                raise ValueError("Configuration symlink became directory")
            if path.exists() or path.is_symlink():
                path.unlink()
            path.symlink_to(item["target"])
        os.chown(path, item["uid"], item["gid"], follow_symlinks=False)
        _sync_directory(path.parent)
        return
    elif item["kind"] == "file":
        data = (store / "objects" / item["sha256"]).read_bytes()
        if _digest(data) != item["sha256"]:
            raise ValueError("Configuration backup digest mismatch")
        if path.is_dir() and not path.is_symlink():
            raise ValueError("Configuration file became directory")
        if path.is_file() and not path.is_symlink():
            metadata = path.stat()
            if path.read_bytes() == data:
                if (stat.S_IMODE(metadata.st_mode) != item["mode"]
                        or (metadata.st_uid, metadata.st_gid) != (item["uid"], item["gid"])):
                    os.chmod(path, item["mode"])
                    os.chown(path, item["uid"], item["gid"])
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                    try:
                        os.fsync(descriptor)
                    finally:
                        os.close(descriptor)
                    _sync_directory(path.parent)
                return
        fd, temporary = tempfile.mkstemp(prefix=".preserve-", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, item["mode"])
            os.chown(temporary, item["uid"], item["gid"])
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    os.chmod(path, item["mode"])
    os.chown(path, item["uid"], item["gid"])
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _sync_directory(path.parent)


def _vendor(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
        return None
    host, path = parsed.hostname, parsed.path.rstrip("/")
    if host in ("ppa.launchpadcontent.net", "ppa.launchpad.net") and path in ("/ondrej/php/ubuntu", "/ondrej/nginx/ubuntu"):
        return "ondrej"
    if host == "ppa.setup-php.com" and path == "/ondrej/php/ubuntu":
        return "ondrej"
    if host == "ppa.launchpadcontent.net" and path in ("/shivammathur/php/ubuntu", "/shivammathur/php-ubuntu/ubuntu"):
        return "setup_php"
    if host == "deb.nodesource.com" and re.fullmatch(r"/node_\d+\.x", path):
        return "nodesource"
    if host == "nginx.org" and path in ("/packages/ubuntu", "/packages/mainline/ubuntu"):
        return "nginx"
    if host == "packages.redis.io" and path == "/deb":
        return "redis"
    if host == "repo.mysql.com" and path == "/apt/ubuntu":
        return "mysql80"
    if (host, path) in (("repos.insights.digitalocean.com", "/apt/do-agent"), ("repos-droplet.digitalocean.com", "/apt/droplet-agent")):
        return "digitalocean_agent"
    if host and (host == "archive.ubuntu.com" or host.endswith(".archive.ubuntu.com") or host in ("security.ubuntu.com", "ports.ubuntu.com") or (host == "mirrors.digitalocean.com" and path == "/ubuntu")):
        return "ubuntu"
    return None


def insecure_source_options(content):
    active = '\n'.join(line for line in content.splitlines() if not line.lstrip().startswith('#'))
    return bool(re.search(r'(?:\b(?:trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)\s*=\s*(?:yes|true|1)\b|^\s*(?:Trusted|Allow-Insecure|Allow-Weak|Allow-Downgrade-To-Insecure):\s*(?:yes|true|1)\b)', active, re.I | re.M))

def vendor_source_content(content, suffix, old_codename, target_codename):
    """Return restorable known-vendor-only content and explicit coverage gaps."""
    if insecure_source_options(content):
        return None, ['insecure_source_options']
    if not re.fullmatch(r"[a-z]+", target_codename or "") or not re.fullmatch(r"[a-z]+", old_codename or ""):
        return None, ["source_codename_unavailable"]
    selected, gaps = [], []
    if suffix == ".list":
        for line in content.splitlines():
            active = line.strip()
            if not active or active.startswith("#"):
                continue
            match = re.fullmatch(r"(deb(?:-src)?\s+(?:\[[^\]]+\]\s+)?)(\S+)\s+(\S+)(\s+.+)", active)
            if not match:
                gaps.append("unrecognized_source_line")
                continue
            vendor = _vendor(match.group(2))
            if vendor == "ubuntu":
                continue
            if vendor is None:
                gaps.append("unknown_third_party_source")
                continue
            suite = match.group(3)
            expected = "nodistro" if vendor == "nodesource" else "main" if vendor == "digitalocean_agent" else old_codename
            if suite != expected or (vendor == "mysql80" and match.group(4).split() != ["mysql-8.0"]):
                gaps.append("vendor_source_suite_needs_review:" + vendor)
                continue
            selected.append(match.group(1) + match.group(2) + " " + (expected if vendor in ("nodesource", "digitalocean_agent") else target_codename) + match.group(4))
        return ("\n".join(selected) + "\n" if selected else None), sorted(set(gaps))
    for block in re.split(r"\n\s*\n", content):
        fields = {}
        invalid = False
        for line in block.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if ":" not in line or line.startswith((" ", "\t")):
                invalid = True
                break
            key, value = line.split(":", 1)
            if key in fields:
                invalid = True
            fields[key] = value.strip()
        if not fields or fields.get("Enabled", "yes").lower() == "no":
            continue
        urls = fields.get("URIs", "").split()
        vendor = _vendor(urls[0]) if len(urls) == 1 else None
        if vendor == "ubuntu":
            continue
        if invalid or vendor is None:
            gaps.append("unknown_or_complex_third_party_source")
            continue
        expected = "nodistro" if vendor == "nodesource" else "main" if vendor == "digitalocean_agent" else old_codename
        if fields.get("Suites") != expected or (vendor == "mysql80" and fields.get("Components") != "mysql-8.0"):
            gaps.append("vendor_source_suite_needs_review:" + vendor)
            continue
        fields["Suites"] = expected if vendor in ("nodesource", "digitalocean_agent") else target_codename
        fields.pop("Enabled", None)
        selected.append("\n".join(key + ": " + value for key, value in fields.items()))
    return ("\n\n".join(selected) + "\n" if selected else None), sorted(set(gaps))


def _disable_restored_vendor_entries(content, suffix, vendor_content):
    """Disable only known URLs being restored, preserving unrelated source text."""
    urls = set(re.findall(r"https?://[^\s\]]+", vendor_content))
    def known(line):
        return any(url in line.split() for url in urls)
    if suffix == ".list":
        return "".join("# global-preserved vendor: " + line if line.lstrip().startswith(("deb ", "deb-src ")) and known(line) else line for line in content.splitlines(keepends=True))
    blocks = []
    for block in re.split(r"(\n\s*\n)", content):
        uri = next((line for line in block.splitlines() if line.startswith("URIs:")), "")
        if known(uri):
            block = "\n".join("# global-preserved vendor: " + line for line in block.splitlines())
        blocks.append(block)
    return "".join(blocks)


def restore_verify(manifest, job, targetcodename, *, root="/"):
    root, store = Path(root).absolute(), Path(manifest["store"])
    if store != _job(job).absolute() / "configuration-preservation":
        raise ValueError("Configuration manifest belongs to another job")
    gaps, restored_sources = list(manifest["gaps"]), []
    for item in manifest["entries"]:
        try:
            _restore_item(item, root, store)
        except (OSError, ValueError) as error:
            gaps.append("configuration_restore_failed:" + item["path"] + ":" + type(error).__name__)
    config_gaps = list(gaps)
    for item in manifest["sources"]:
        if item["kind"] != "file":
            gaps.append("source_symlink_or_special_needs_review:" + item["path"])
            continue
        data = (store / "objects" / item["sha256"]).read_bytes()
        if _digest(data) != item["sha256"]:
            raise ValueError("Source backup digest mismatch")
        content, source_gaps = vendor_source_content(data.decode(), Path(item["path"]).suffix, manifest["source_codename"], targetcodename)
        gaps.extend(source_gaps)
        if not content:
            continue
        # Dedicated restored source avoids clobbering upgrader-managed Ubuntu or
        # unknown source stanzas in the original mixed source file.
        digest = _digest(item["path"].encode())[:16]
        destination = "/etc/apt/sources.list.d/global-preserved-" + digest + Path(item["path"]).suffix
        blob = content.encode()
        object_path = store / "objects" / _digest(blob)
        if not object_path.exists():
            with object_path.open("xb") as stream:
                os.chmod(object_path, 0o600)
                stream.write(blob)
                stream.flush()
                os.fsync(stream.fileno())
        source_item = dict(item, path=destination, sha256=_digest(blob), mode=0o644)
        try:
            original = _at(root, item["path"])
            if original.exists():
                if original.is_symlink():
                    raise ValueError("Current source became a symlink")
                current = original.read_text()
                disabled = _disable_restored_vendor_entries(current, original.suffix, content)
                if disabled != current:
                    # Preserve the post-upgrade source too, before the narrow edit.
                    saved = store / "objects" / _digest(current.encode())
                    if not saved.exists():
                        with saved.open("xb") as stream:
                            os.chmod(saved, 0o600)
                            stream.write(current.encode())
                            stream.flush()
                            os.fsync(stream.fileno())
                    changed = disabled.encode()
                    obj = store / "objects" / _digest(changed)
                    if not obj.exists():
                        with obj.open("xb") as stream:
                            os.chmod(obj, 0o600)
                            stream.write(changed)
                            stream.flush()
                            os.fsync(stream.fileno())
                    metadata = original.stat()
                    _restore_item(dict(item, sha256=_digest(changed), uid=metadata.st_uid, gid=metadata.st_gid, mode=stat.S_IMODE(metadata.st_mode)), root, store)
            _restore_item(source_item, root, store)
            if _at(root, destination).read_bytes() != blob:
                raise ValueError("Restored vendor source verification failed")
            restored_sources.append(destination)
        except (OSError, ValueError):
            gaps.append("vendor_source_restore_failed:" + item["path"])
    for item in manifest["entries"]:
        path = _at(root, item["path"])
        try:
            info = path.lstat()
            correct = (info.st_uid, info.st_gid) == (item["uid"], item["gid"])
            correct &= not os.listxattr(path, follow_symlinks=False)
            if item["kind"] == "file":
                correct &= path.is_file() and not path.is_symlink() and _digest(path.read_bytes()) == item["sha256"] and stat.S_IMODE(info.st_mode) == item["mode"]
            elif item["kind"] == "directory":
                correct &= path.is_dir() and not path.is_symlink() and stat.S_IMODE(info.st_mode) == item["mode"]
            else:
                correct &= path.is_symlink() and _same_symlink_target(root, item["path"], os.readlink(path), item["target"])
            if not correct:
                config_gaps.append("configuration_verification_failed:" + item["path"])
        except OSError:
            config_gaps.append("configuration_verification_unreadable:" + item["path"])
    gaps.extend(config_gaps)
    return {"configuration_preserved": not config_gaps, "vendor_sources_restored": not gaps,
            "restored_source_files": restored_sources, "coverage_gaps": sorted(set(gaps)),
            "requires_apt_refresh_and_candidate_authentication": bool(restored_sources)}


def pause_php_sources_for_os(manifest, job, *, root='/'):
    """Disable only captured, known external PHP sources during OS preparation.

    Old PPA suites can have disappeared. Ubuntu repositories remain untouched;
    immutable original source bytes are used by restore_verify after each hop.
    This performs no network or package action and is Python3.6 compatible.
    """
    root, job = Path(root).absolute(), _job(job).absolute()
    store = Path(manifest['store'])
    if store != job / 'configuration-preservation':
        raise ValueError('Source capture belongs to another job')
    if manifest['gaps']:
        raise ValueError('Source capture has unresolved coverage gaps')
    originals = {item['path']: item for item in manifest['sources']}
    def verify_sources(paused):
        files = set()
        if _at(root, '/etc/apt/sources.list').exists() or _at(root, '/etc/apt/sources.list').is_symlink():
            files.add('/etc/apt/sources.list')
        directory = _at(root, '/etc/apt/sources.list.d')
        if directory.exists():
            files.update('/etc/apt/sources.list.d/' + p.name for p in directory.iterdir() if p.suffix in ('.list', '.sources'))
        if files != set(originals):
            raise ValueError('APT source file set changed since capture')
        for name, item in originals.items():
            if item['kind'] != 'file':
                raise ValueError('Captured APT source is not a regular file')
            path = _at(root, name);_safe_parents(path, root);info = path.lstat()
            expected = paused.get(name, item['sha256'])
            if (item['kind'] != 'file' or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != item['uid'] or info.st_gid != item['gid']
                    or stat.S_IMODE(info.st_mode) != item['mode'] or _digest(path.read_bytes()) != expected):
                raise ValueError('Captured APT source changed')
    receipt = job / 'paused-php-sources.json'
    if receipt.exists():
        saved = json.loads(receipt.read_text())
        paused = {}
        for item in saved['files']:
            if item['path'] not in originals or item['before_sha256'] != originals[item['path']]['sha256']:
                raise ValueError('Paused PHP source receipt baseline changed')
            paused[item['path']] = item['after_sha256']
            path = _at(root, item['path'])
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != item['uid']
                    or info.st_gid != item['gid'] or stat.S_IMODE(info.st_mode) != item['mode']
                    or _digest(path.read_bytes()) != item['after_sha256']):
                raise ValueError('Previously paused PHP source changed')
        verify_sources(paused)
        return saved
    verify_sources({})

    def is_php(url):
        return _vendor(url) in ('ondrej', 'setup_php') and urlsplit(url).path.rstrip('/') in (
            '/ondrej/php/ubuntu', '/shivammathur/php/ubuntu', '/shivammathur/php-ubuntu/ubuntu')

    plans = []
    for item in manifest['sources']:
        if item['kind'] != 'file':
            raise ValueError('Source snapshot is not a regular file')
        original = (store / 'objects' / item['sha256']).read_bytes()
        if _digest(original) != item['sha256']:
            raise ValueError('Source backup checksum changed')
        content = original.decode()
        if insecure_source_options(content):
            raise ValueError('Insecure source options in capture')
        pieces = []
        if Path(item['path']).suffix == '.list':
            for line in content.splitlines(keepends=True):
                match = re.fullmatch(r'(deb(?:-src)?\s+(?:\[[^\]]+\]\s+)?)(\S+)\s+(\S+)(\s+.+)', line.strip())
                if match and is_php(match.group(2)):
                    if match.group(3) != manifest['source_codename'] or re.search(r'trusted\s*=\s*yes|allow-insecure\s*=\s*yes', line, re.I):
                        raise ValueError('Unsafe or foreign PHP source before OS upgrade')
                    pieces.append('# PHP deferred until Ubuntu24.04: ' + line)
                else:
                    pieces.append(line)
        else:
            for block in re.split(r'(\n\s*\n)', content):
                fields = dict(re.findall(r'^([A-Za-z-]+):\s*(.*)$', block, re.M))
                urls = fields.get('URIs', '').split()
                if any(is_php(url) for url in urls) and fields.get('Enabled', 'yes').lower() != 'no':
                    if len(urls) != 1 or fields.get('Suites') != manifest['source_codename']:
                        raise ValueError('Mixed or foreign PHP source stanza')
                    if any(fields.get(key, 'no').lower() == 'yes' for key in ('Trusted', 'Allow-Insecure')):
                        raise ValueError('Insecure PHP source stanza')
                    block = re.sub(r'^Enabled:.*$', 'Enabled: no', block, flags=re.M) if 'Enabled' in fields else block.rstrip('\n') + '\nEnabled: no'
                pieces.append(block)
        replacement = ''.join(pieces).encode()
        if replacement == original:
            continue
        path = _at(root, item['path'])
        _safe_parents(path, root)
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != item['uid']
                or info.st_gid != item['gid'] or stat.S_IMODE(info.st_mode) != item['mode']
                or _digest(path.read_bytes()) != item['sha256']):
            raise ValueError('PHP source changed since immutable capture')
        sha = _digest(replacement)
        obj = store / 'objects' / sha
        if not obj.exists():
            fd = os.open(str(obj), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(replacement); stream.flush(); os.fsync(stream.fileno())
        plans.append((dict(item, sha256=sha), dict(path=item['path'], uid=item['uid'], gid=item['gid'], mode=item['mode'],
                                                 before_sha256=item['sha256'], after_sha256=sha)))
    # Validate all source plans before modifying the first source file.
    verify_sources({})
    for changed, _ in plans:
        _restore_item(changed, root, store)
    result = dict(status='known-PHP-sources-paused', files=[record for _, record in plans],
                  Ubuntu_repositories_changed=False, PHP_packages_changed=False)
    verify_sources({item['path']: item['after_sha256'] for item in result['files']})
    fd = os.open(str(receipt), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(result, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
    directory = os.open(str(job), os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return result
