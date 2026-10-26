"""Node runtime policy for the global Ubuntu updater; no network or writes on import.

Policy date: 2026-10-25. Source: https://nodejs.org/en/about/previous-releases
An APT package change does not update running Node workers. Application dependency,
native-module rebuild, service path migration and container rebuild work stays explicit.
The caller owns authenticated APT metadata and the package transaction engine.
"""
from __future__ import annotations

import glob
import json
import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

POLICY_DATE = "2026-10-25"
LTS_MAJORS = (22, 24)
CURRENT_MAJORS = (26,)
SUPPORTED_MAJORS = LTS_MAJORS + CURRENT_MAJORS
REPLACEMENT_MAJOR = 24
NODESOURCE_FINGERPRINT = "6F71F525282841EEDAF851B42F59B5F99B1BE0B4"


def node_major(version: str | None) -> int | None:
    """Accept Node semver and Debian epoch/revision versions; reject missing values."""
    match = re.fullmatch(r"(?:\d+:)?v?(\d+)\.\d+\.\d+(?:[-+~][A-Za-z0-9.+:~_-]+)?", version or "")
    return int(match.group(1)) if match else None


def plan_node(snapshot: dict) -> dict:
    """Pure, deterministic snapshot -> plan. Unknown evidence blocks automation.

    Snapshot keys: os_id, os_version, inventory_complete, runtimes, apt.
    Runtime keys: path, manager (apt/nvm/custom/container), version, package.
    APT keys: candidate, installed, authenticated, source_approved, metadata_fresh,
    simulation {ok, removals, changes}, held, compatibility_approved.
    Simulation changes are {package: exact_version}; only nodejs may change here.
    These booleans are evidence supplied by the enclosing updater, never inferred
    from a repository URL or a successful apt-cache invocation.
    """
    blockers, findings, actions = [], [], []
    if (snapshot.get("os_id"), snapshot.get("os_version")) != ("ubuntu", "24.04"):
        blockers.append("node_policy_requires_ubuntu_24_04")
    if snapshot.get("inventory_complete") is not True:
        blockers.append("runtime_inventory_incomplete")
    runtimes = sorted(snapshot.get("runtimes", []), key=lambda x: (x.get("path", ""), x.get("manager", "")))
    apt_runtimes = []
    for runtime in runtimes:
        manager, version = runtime.get("manager"), runtime.get("version")
        major = node_major(version)
        status = "unknown" if major is None else "supported" if major in SUPPORTED_MAJORS else "eol" if major < 26 else "unrecognized"
        findings.append({"path": runtime.get("path", ""), "manager": manager,
                         "version": version, "policy": status,
                         "production_lts": major in LTS_MAJORS})
        if manager != "apt" or runtime.get("package") != "nodejs":
            if snapshot.get("scope") != "apt_nodejs":
                blockers.append("manual_runtime_review:" + runtime.get("path", "unknown"))
        else:
            apt_runtimes.append(runtime)
        if status in ("unknown", "unrecognized") and (manager == "apt" or snapshot.get("scope") != "apt_nodejs"):
            blockers.append("unknown_runtime_version:" + runtime.get("path", "unknown"))
    if len(apt_runtimes) > 1:
        blockers.append("multiple_apt_runtime_paths_require_review")
    if apt_runtimes:
        apt = snapshot.get("apt", {})
        installed, candidate = apt.get("installed"), apt.get("candidate")
        major, candidate_major = node_major(installed), node_major(candidate)
        if installed != apt_runtimes[0].get("version"):
            blockers.append("apt_inventory_version_mismatch")
        for key in ("authenticated", "source_approved", "metadata_fresh"):
            if apt.get(key) is not True:
                blockers.append("apt_" + key + "_not_verified")
        if apt.get("insecure_source_options") is True:
            blockers.append("apt_insecure_source_options")
        if apt.get("source_inventory_unreadable") is True:
            blockers.append("apt_source_inventory_unreadable")
        if apt.get("held") is not False:
            blockers.append("apt_hold_state_not_clear")
        target = major if major in SUPPORTED_MAJORS else REPLACEMENT_MAJOR
        if candidate_major != target:
            blockers.append("approved_candidate_major_unavailable:" + str(target))
        if major is not None and major not in SUPPORTED_MAJORS:
            compatibility = snapshot.get("compatibility", {})
            if compatibility.get("checked") is True:
                blockers.extend(compatibility.get("blockers", []))
            elif apt.get("compatibility_approved") is not True:
                blockers.append("node24_application_and_native_module_compatibility_required")
        if major is not None and candidate_major == target and candidate != installed:
            simulation = apt.get("simulation", {})
            if (simulation.get("ok") is not True or simulation.get("removals") != []
                    or simulation.get("changes") != {"nodejs": candidate}):
                blockers.append("node_transaction_simulation_not_exact")
            if apt.get("candidate_newer") is not True:
                blockers.append("candidate_not_verified_newer_by_dpkg")
            actions.append({"kind": "apt_install", "package": "nodejs", "version": candidate,
                            "major_change": major != candidate_major,
                            "requires_worker_restart_and_health_verification": True})
        elif candidate is None:
            blockers.append("node_candidate_missing")
    return {"policy_date": POLICY_DATE, "findings": findings, "actions": actions,
            "blockers": sorted(set(blockers)), "ready": not blockers,
            "running_workers_verified": False,
            "scope": "APT nodejs only; application npm dependencies and service paths excluded"}


def collect_snapshot(run: Callable | None = None) -> dict:
    """Read-only local inventory. Never executes discovered Node/npm binaries.

    Does not read process command lines, environments, app configuration or source
    credentials. Custom binaries have unknown versions until independently vetted.
    The bounded inventory deliberately reports incompleteness: arbitrary home,
    mount, container and service namespaces require the enclosing host inventory.
    APT authentication and simulation must be supplied by that engine as evidence.
    """
    if run is None:
        def run(argv):
            return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=30).stdout
    os_release = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip('"')
    result = {"os_id": os_release.get("ID"), "os_version": os_release.get("VERSION_ID"),
              "inventory_complete": False, "runtimes": [], "apt": {},
              "inventory_gaps": ["container_images", "service_specific_paths", "unsearched_mounts_and_homes"],
              "running_worker_paths": []}
    installed = None
    try:
        value = run(["dpkg-query", "-W", "-f=${db:Status-Status}\t${Version}", "nodejs"]).strip().split("\t")
        if len(value) == 2 and value[0] == "installed":
            installed = value[1]
    except (subprocess.SubprocessError, OSError):
        pass
    for pattern in ("/usr/bin/node", "/usr/bin/nodejs", "/usr/local/bin/node", "/opt/node*/bin/node",
                    "/root/.nvm/versions/node/*/bin/node", "/home/*/.nvm/versions/node/*/bin/node"):
        for path in sorted(glob.glob(pattern)):
            # /usr/bin/nodejs is commonly an alias, not a separate runtime.
            if any(os.path.realpath(item["path"]) == os.path.realpath(path) for item in result["runtimes"]):
                continue
            owned = False
            try:
                owner = run(["dpkg-query", "-S", path]).strip()
                owned = bool(re.fullmatch(r"nodejs(?::[a-z0-9-]+)?: " + re.escape(path), owner))
            except (subprocess.SubprocessError, OSError):
                pass
            manager = "apt" if owned and installed else "nvm" if "/.nvm/" in path else "custom"
            result["runtimes"].append({"path": path, "manager": manager,
                                       "package": "nodejs" if manager == "apt" else None,
                                       "version": installed if manager == "apt" else None})
    for proc in glob.glob("/proc/[0-9]*/exe"):
        try:
            path = os.readlink(proc)
            if os.path.basename(path).removesuffix(" (deleted)") in ("node", "nodejs"):
                result["running_worker_paths"].append(path)
        except OSError:
            continue
    result["running_worker_paths"] = sorted(set(result["running_worker_paths"]))
    candidate, held = None, None
    try:
        policy = run(["apt-cache", "policy", "nodejs"])
        match = re.search(r"^\s*Candidate:\s*(\S+)\s*$", policy, re.MULTILINE)
        if match and node_major(match.group(1)) is not None:
            candidate = match.group(1)
        held = "nodejs" in run(["apt-mark", "showhold"]).splitlines()
    except (subprocess.SubprocessError, OSError):
        pass
    source_paths = ["/etc/apt/sources.list"] + sorted(glob.glob("/etc/apt/sources.list.d/*.list")) + sorted(glob.glob("/etc/apt/sources.list.d/*.sources"))
    sources, insecure, unreadable = [], False, False
    for name in source_paths:
        source = Path(name)
        if not source.exists():
            continue
        sources.append(name)
        try:
            if source.stat().st_size > 1024 * 1024:
                unreadable = True
                continue
            # Report flags only. Source URLs may contain credentials.
            contents = source.read_text()
            active = "\n".join(line for line in contents.splitlines() if not line.lstrip().startswith("#"))
            insecure |= bool(re.search(r"(?:trusted\s*=\s*yes|allow-insecure\s*=\s*yes|^\s*(?:Trusted|Allow-Insecure):\s*yes)", active, re.I | re.M))
        except (OSError, UnicodeError):
            unreadable = True
    result["apt"] = {"installed": installed, "candidate": candidate, "held": held,
                      "source_files": sources, "insecure_source_options": insecure,
                      "source_inventory_unreadable": unreadable, "authenticated": False,
                      "source_approved": False, "metadata_fresh": False}
    return result


def check_engine_range(expression: str, major: int) -> bool | None:
    """Conservative major compatibility check; unsupported syntax needs review.

    Handles common major-only ranges and x/caret/tilde alternatives. Patch/minor
    boundaries deliberately need review because a major-only decision is unsafe.
    """
    answers = []
    for alternative in expression.split("||"):
        terms = alternative.strip().split()
        if not terms:
            return None
        accepted = True
        for term in terms:
            if term in ("*", "x", "X"):
                continue
            match = re.fullmatch(r"(>=|<=|>|<|=|\^|~)?(\d+)(?:\.(?:x|X|\*))?", term)
            if not match:
                return None
            operator, value = match.group(1) or "=", int(match.group(2))
            accepted &= {">=": major >= value, "<=": major <= value,
                         ">": major > value, "<": major < value,
                         "=": major == value, "^": major == value,
                         "~": major == value}[operator]
        answers.append(accepted)
    return any(answers) if expression.strip() else None


def inspect_application(root: str, target_major: int = 24) -> dict:
    """Read only package metadata and filenames; never executes npm or app code."""
    result = {"root": root, "blockers": [], "native_addons": False}
    package = Path(root) / "package.json"
    try:
        if not package.is_file() or package.stat().st_size > 1024 * 1024:
            result["blockers"].append("application_package_metadata_unavailable:" + root)
            return result
        metadata = json.loads(package.read_text())
        engine = metadata.get("engines", {}).get("node")
        result["engine_range"] = engine if isinstance(engine, str) else None
        if engine is not None:
            allowed = check_engine_range(engine, target_major) if isinstance(engine, str) else None
            if allowed is not True:
                result["blockers"].append(("application_engine_incompatible:" if allowed is False else "application_engine_range_needs_review:") + root)
        count = 0
        def walk_error(_error):
            result["blockers"].append("native_addon_inventory_unreadable:" + root)
        module_root = Path(root) / "node_modules"
        tree = os.walk(module_root, followlinks=False, onerror=walk_error) if module_root.exists() else ()
        if module_root.is_symlink():
            result["blockers"].append("native_addon_symlink_inventory_needs_review:" + root)
        for directory, dirs, files in tree:
            count += len(dirs) + len(files)
            if count > 100000:
                result["blockers"].append("native_addon_inventory_limit:" + root)
                break
            if any((Path(directory) / name).is_symlink() for name in dirs + files):
                result["blockers"].append("native_addon_symlink_inventory_needs_review:" + root)
            if any(name.endswith(".node") for name in files):
                result["native_addons"] = True
                result["blockers"].append("native_addon_rebuild_required:" + root)
                break
    except (OSError, ValueError, TypeError, AttributeError):
        result["blockers"].append("application_inventory_unreadable:" + root)
    return result


def collect_apt_snapshot(apt_evidence: dict, *, run: Callable | None = None,
                         application_roots: tuple[str, ...] = ()) -> dict:
    """Ready-to-call adapter for the enclosing APT transaction engine.

    `apt_evidence` comes from fresh python-apt trust/origin/candidate validation and
    exact transaction simulation under the host lock. No source URLs are returned.
    Inventory scope is the dpkg-owned system nodejs package; discovered other
    runtimes are report-only and never silently migrated. Running package workers
    need an explicitly identified systemd unit restart and application health audit.
    """
    if run is None:
        def run(argv):
            return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=30).stdout
    snapshot = collect_snapshot(run)
    snapshot["scope"] = "apt_nodejs"
    snapshot["inventory_complete"] = True
    snapshot["apt"].update(apt_evidence)
    installed = snapshot["apt"].get("installed")
    if installed and not any(item["manager"] == "apt" for item in snapshot["runtimes"]):
        # Package exists but binary is missing/diverted; do not mistake it for absence.
        snapshot["inventory_complete"] = False
        snapshot["inventory_gaps"].append("installed_nodejs_binary_missing_or_unowned")
    roots, workers, errors = set(application_roots), [], []
    # Include stopped direct systemd consumers, not just processes currently alive.
    try:
        listing = run(["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"])
        units = [line.split()[0] for line in listing.splitlines() if line.split() and re.fullmatch(r"[A-Za-z0-9_.@:-]+\.service", line.split()[0])]
        if len(units) > 4096:
            raise ValueError("unit inventory limit")
        properties = run(["systemctl", "show", "--no-pager", "-p", "Id", "-p", "ExecStart", "-p", "WorkingDirectory", *units]) if units else ""
        for block in properties.split("\n\n"):
            values = dict(line.split("=", 1) for line in block.splitlines() if "=" in line)
            command = values.get("ExecStart", "")
            if re.search(r"/usr/bin/(?:node|nodejs)(?:\s|;|$)", command):
                working = values.get("WorkingDirectory", "")
                if working.startswith("/"):
                    roots.add(working)
                else:
                    errors.append("node_service_application_root_unknown:" + values.get("Id", "unknown"))
            elif re.search(r"\b(?:node|nodejs|npm|npx|pm2|forever)\b", command):
                errors.append("node_service_wrapper_needs_review:" + values.get("Id", "unknown"))
    except (subprocess.SubprocessError, OSError, ValueError):
        errors.append("systemd_node_consumer_inventory_unavailable")
    consumer_paths = ["/etc/crontab", "/etc/supervisord.conf"]
    for pattern in ("/etc/cron.d/*", "/etc/cron.hourly/*", "/etc/cron.daily/*",
                    "/etc/cron.weekly/*", "/etc/cron.monthly/*",
                    "/var/spool/cron/crontabs/*", "/etc/supervisor/conf.d/*"):
        consumer_paths.extend(glob.glob(pattern))
    if len(consumer_paths) > 4096:
        errors.append("scheduled_node_consumer_inventory_limit")
    for name in sorted(set(consumer_paths))[:4096]:
        source = Path(name)
        if not source.exists() or not source.is_file():
            continue
        try:
            if source.stat().st_size > 1024 * 1024:
                errors.append("scheduled_node_consumer_inventory_limit:" + name)
                continue
            active = "\n".join(line for line in source.read_text().splitlines() if not line.lstrip().startswith(("#", ";")))
            if re.search(r"\b(?:node|nodejs|npm|npx|pm2|forever)\b", active):
                errors.append("scheduled_node_consumer_needs_review:" + name)
        except (OSError, UnicodeError):
            errors.append("scheduled_node_consumer_inventory_unreadable:" + name)
    for proc in sorted(glob.glob("/proc/[0-9]*")):
        try:
            executable = os.readlink(proc + "/exe")
        except FileNotFoundError:
            continue
        except PermissionError:
            errors.append("process_inventory_permission_denied")
            continue
        except OSError:
            continue
        if executable.removesuffix(" (deleted)") not in ("/usr/bin/node", "/usr/bin/nodejs"):
            continue
        try:
            cwd = os.readlink(proc + "/cwd")
            cgroup = Path(proc + "/cgroup").read_text()
            units = sorted(set(re.findall(r"/([A-Za-z0-9_.@:-]+\.service)(?:/|$)", cgroup, re.MULTILINE)))
            running_stat = os.stat(proc + "/exe")
            disk_stat = os.stat(executable.removesuffix(" (deleted)"))
            workers.append({"pid": int(Path(proc).name), "executable": executable,
                            "cwd": cwd, "systemd_units": units,
                            "restart_required": True, "inode": running_stat.st_ino,
                            "on_disk_inode": disk_stat.st_ino,
                            "running_matches_disk": (running_stat.st_dev, running_stat.st_ino) == (disk_stat.st_dev, disk_stat.st_ino)})
            roots.add(cwd)
            errors.append("node_worker_restart_and_health_verification_required:" + (units[0] if len(units) == 1 else "unmapped_worker"))
        except (OSError, ValueError):
            errors.append("node_worker_inventory_unreadable")
    applications = [inspect_application(root) for root in sorted(roots)]
    for app in applications:
        errors.extend(app["blockers"])
    snapshot["workers"] = workers
    snapshot["applications"] = applications
    snapshot["compatibility"] = {"checked": True, "blockers": sorted(set(errors)),
                                  "coverage": "explicit application roots and live dpkg Node workers"}
    # Patch transactions still need restart handling, even without a major change.
    if workers or "process_inventory_permission_denied" in errors:
        snapshot["inventory_complete"] = False
        snapshot["inventory_gaps"].extend(sorted(set(errors)))
    return snapshot


def plan_nodesource_migration(source: str, content: str, current_major: int,
                              key_fingerprint: str, *, old_origin_authenticated: bool) -> dict:
    """Pure known-repository migration plan; preserves existing Signed-By key.

    Only one NodeSource HTTPS nodistro/main source is supported. No trust bootstrap,
    scripts, key downloads, arbitrary repository rewrites or credential-bearing URLs.
    Fingerprint is pinned to the established NodeSource signing key; expiration or
    newer-key rotation needs an independently reviewed policy update, never bypass.
    """
    blockers = []
    if current_major in SUPPORTED_MAJORS or current_major < 4 or current_major > 25:
        blockers.append("nodesource_migration_requires_known_eol_major")
    if key_fingerprint.upper() != NODESOURCE_FINGERPRINT or not old_origin_authenticated:
        blockers.append("nodesource_existing_origin_and_pinned_key_must_be_authenticated")
    path = Path(source)
    if path.parent != Path("/etc/apt/sources.list.d") or path.suffix not in (".list", ".sources"):
        blockers.append("nodesource_source_path_not_supported")
    old_url = f"https://deb.nodesource.com/node_{current_major}.x"
    key = None
    active = [line for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
    if path.suffix == ".list":
        match = re.fullmatch(r"deb \[([^\]]+)\] " + re.escape(old_url) + r"/? nodistro main", active[0].strip()) if len(active) == 1 else None
        options = match.group(1).split() if match else []
        signed = [item.split("=", 1)[1] for item in options if item.startswith("signed-by=")]
        if len(signed) == 1 and all(item.startswith(("signed-by=", "arch=")) for item in options):
            key = signed[0]
    else:
        fields = {}
        for line in active:
            if ":" in line and not line.startswith((" ", "\t")):
                name, value = line.split(":", 1)
                if name in fields:
                    blockers.append("nodesource_multiple_source_stanzas")
                fields[name] = value.strip()
            else:
                blockers.append("nodesource_complex_source_needs_review")
        if (fields.get("Types") == "deb" and fields.get("URIs", "").rstrip("/") == old_url
                and fields.get("Suites") == "nodistro" and fields.get("Components") == "main"
                and set(fields) <= {"Types", "URIs", "Suites", "Components", "Signed-By", "Architectures"}):
            key = fields.get("Signed-By")
    if not key or not re.fullmatch(r"/(?:etc/apt/keyrings|usr/share/keyrings)/[A-Za-z0-9_.-]+\.(?:gpg|asc)", key):
        blockers.append("nodesource_single_signed_by_source_required")
    return {"source": source, "before_sha256": hashlib.sha256(content.encode()).hexdigest(),
            "after": "".join(line if line.lstrip().startswith("#") else line.replace(old_url, "https://deb.nodesource.com/node_24.x") for line in content.splitlines(keepends=True)) if not blockers else None,
            "key_path": key, "blockers": sorted(set(blockers)), "ready": not blockers,
            "requires_apt_refresh_and_authenticated_node24_candidate": True}


def apply_nodesource_migration(plan: dict, *, run: Callable | None = None) -> dict:
    """Atomic narrow source migration. Caller holds updater host lock.

    Fresh APT update + authenticated candidate validation is mandatory afterwards;
    this function cannot authorize package installation. Existing trust is checked
    again from the local pinned key, never downloaded or loosened.
    """
    if not plan.get("ready"):
        raise ValueError("NodeSource migration plan is blocked")
    if run is None:
        def run(argv):
            return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=30).stdout
    source, key = Path(plan["source"]), Path(plan["key_path"])
    for path in (source, key, source.parent, key.parent):
        info = path.lstat()
        if path.is_symlink() or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("NodeSource source/key path must be root owned and non-writable to others")
    content = source.read_text()
    if hashlib.sha256(content.encode()).hexdigest() != plan["before_sha256"]:
        raise ValueError("NodeSource source changed since planning")
    key_output = run(["gpg", "--batch", "--no-options", "--with-colons", "--show-keys", str(key)]).splitlines()
    fingerprints = [line.split(":")[9] for line in key_output if line.startswith("fpr:")]
    if sum(line.startswith("pub:") for line in key_output) != 1 or not fingerprints or fingerprints[0] != NODESOURCE_FINGERPRINT:
        raise ValueError("NodeSource pinned signing key mismatch")
    # Rebuild rather than trusting caller-provided replacement bytes.
    old = re.search(r"https://deb\.nodesource\.com/node_(\d+)\.x", content)
    fresh = plan_nodesource_migration(str(source), content, int(old.group(1)) if old else 0,
                                     fingerprints[0], old_origin_authenticated=True)
    if not fresh["ready"] or fresh["after"] != plan["after"]:
        raise ValueError("NodeSource replacement validation failed")
    backup = source.with_name(source.name + ".pre-node24-" + plan["before_sha256"][:16])
    with backup.open("x") as stream:
        os.chmod(backup, 0o600)
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor, name = tempfile.mkstemp(prefix=".node24-", dir=source.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(fresh["after"])
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, source.stat().st_mode & 0o777)
        os.replace(name, source)
        parent = os.open(source.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        if os.path.exists(name):
            os.unlink(name)
    return {"source_changed": True, "backup": str(backup), "package_install_authorized": False,
            "next": "refresh APT indexes and revalidate exact authenticated Node24 candidate"}


def execute_node_plan(snapshot: dict, transaction: Callable[[dict], dict]) -> dict:
    """Delegate an exact approved package intent to the enclosing safe APT engine.

    Caller must freshly recollect evidence under the host lock before this call.
    This function never invokes a shell, changes sources or restarts applications.
    The engine must revalidate source authentication, exact simulation and version
    under its own transaction lock. Completion requires a separate worker audit.
    """
    plan = plan_node(snapshot)
    if not plan["ready"]:
        raise ValueError("Node update blocked: " + "; ".join(plan["blockers"]))
    results = [transaction(action) for action in plan["actions"]]
    return {"package_results": results, "running_workers_verified": False,
            "status": "worker_verification_required" if results else "no_package_change"}
