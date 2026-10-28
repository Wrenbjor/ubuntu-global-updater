# Ubuntu global updater v2.2.1

One host-local installer for supported Ubuntu systems across companies and hosting providers: **finish the OS upgrade to
24.04 first, then migrate legacy PHP to a patched supported PHP8 branch.**
`install.sh` embeds every required module; no separate downloads or Git checkout
are needed on the server. Readable source is included for review.

## Supported paths

| Starting system | OS path | PHP stage, after reaching24.04 |
|---|---|---|
| Ubuntu18.04 | 18.04→20.04→22.04→24.04 | Detect7.2/7.3/7.4/8.0/8.1 and migrate one unambiguous legacy branch |
| Ubuntu20.04 | 20.04→22.04→24.04 | Same legacy migration |
| Ubuntu22.04 | 22.04→24.04 | Same legacy migration |
| Ubuntu24.04 | Skip release upgrades | Migrate legacy PHP or patch a supported installed8.x branch |

Every LTS hop has its own checkpoint and restart verification. Native systems verify the Ubuntu kernel; WSL verifies a new distro instance and exact reached Ubuntu release.
Ubuntu16.04 and unknown/newer releases hold; the updater never downgrades an OS.
There are no hostname-based replacement exclusions. Every host follows the same supported-release, package, recovery and compatibility checks.

PHP7.2/7.3/7.4/8.0/8.1 are migration **sources**, not patched destination branches.
The preferred new branch is8.3, with the reviewed supported8.x candidate/compatibility
policy and authenticated distribution-backport handling. A healthy existing higher
supported branch is preserved when retiring a dormant legacy branch. Detection does
not assume image labels, default `php -v`, or installed package presence prove the
running web version. Pools, extensions, source API/ABI, CLI, actual Nginx sockets,
workers and local application health are checked.

## Provider-neutral operation and existing installations

Fresh installations use `ubuntu-global-updater.service`,
`/var/lib/ubuntu-global-updater`, and a generic APT guard. No cloud API token,
Droplet ID, team identity, hostname allowlist, or cloud metadata request is needed.
Jobs bind to a validated local `/etc/machine-id` plus firmware UUID when usable,
and recheck that binding on resume. A cloned machine without distinct local or
firmware identity cannot be distinguished by this local binding alone.

Compatibility with old deployments is isolated in `updater_layout.py`. A recognized
preflight-only old installation can refresh its code while retaining its original
namespace and exact wrapper. Existing queued/running/failed jobs are normally preserved. The explicit recovery option below archives only a byte-identified v2.1.1 Apache preflight rejection that performed no package stages. Mixed old/new namespaces, active updater processes and unknown wrappers
hold. Use `bash /root/ubuntu-global-updater.sh --status` for either namespace.
Historical names are compatibility aliases, not a company requirement. Optional
recognized provider mirrors/agent repositories remain supported when present.

This is not universal support for every Ubuntu setup. The existing release,
architecture, bootloader, repository, database and application-layout checks still
apply. Unknown providers' repositories require an explicit reviewed source profile;
they are not enabled or rewritten speculatively. Current supported architecture is
amd64. Standard Apache same-branch patch profiles are supported; custom/container/application profiles retain compatibility limits.

## Graceful PHP reload verification hotfix (v2.2.1)

A PHP worker can exit while its executable and module mappings are being read.
Such a lifecycle-incomplete snapshot is inconclusive: it is not accepted as a
patched runtime or treated as proof of stale code. Verification makes bounded,
read-only rechecks and retains structured evidence. Persistent incomplete,
unknown or stale mappings still stop the updater. These checks never retry a
package transaction, send another reload, kill a PHP worker or resume a failed
job. All platform, Apache, repository, application and recovery limits below
continue to apply. The hotfix was fixture-tested; a live package/reload cycle is
not claimed by these release artifacts.

## WSL and native platform detection

Kernel and local WSL evidence select native, WSL1 or WSL2 handling; environment
variables alone never waive boot checks. WSL requires systemd already enabled.
APT-managed Ubuntu packages and PHP are updated inside the distro. Windows/WSL
kernel maintenance remains owned by Windows: GRUB and an Ubuntu-owned running
kernel are explicitly outside WSL verification coverage. Custom ambiguous kernels
require review. Native boot checks remain unchanged.

WSL updates do not run `reboot`, `wsl --shutdown`, Windows shutdown or automatic
distro termination. If a restart is needed, status becomes `waiting-manual-restart`
and the updater service is disabled until you deliberately restart this distro.
After saving other work, terminate this specific distro from another WSL session
or Windows terminal and open it again. Then run:

```bash
sudo bash /root/ubuntu-global-updater.sh --resume
sudo bash /root/ubuntu-global-updater.sh --status
```

Resume verifies the same machine, exact target release and a changed distro
instance (PID1 and namespaces). Shared WSL kernel boot IDs may legitimately remain
unchanged. The installed service bytes and effective command must still match.

## Standard Apache PHP support

The updater discovers native Apache modules, MPM, virtual hosts, handlers, PHP INI
and extension graphs, Unix FPM pools where applicable, local HTTP/TLS health and
live PHP/extension mappings. Supported same-branch patches preserve `mod_php`
with prefork or existing `proxy_fcgi`/FPM; no automatic SAPI or MPM conversion is
performed. Exact authenticated target package versions and current live code are
required for acceptance. No public phpinfo endpoint is created.

Legacy Apache PHP major migration produces an explicit same-SAPI compatibility
plan and remains a separate migration profile. It is not claimed as automatic
PHP7-to-8 support. The existing Nginx/FPM legacy migration path remains available.

## Existing PHP repository alignment

An existing canonical Ondrej PHP source can be aligned to the reached Ubuntu
suite and re-enabled, including an OS-upgrade-disabled deb822 source. Only that
exact PHP stanza changes; unrelated PPAs, URLs and public key bytes are preserved.
The existing explicit signing key must match the independently reviewed PHP PPA
fingerprint. Unknown/insecure/ambiguous sources require review. No key/repository
is fetched or added automatically. Sources are privately backed up and rechecked
for drift immediately before atomic replacement. Fresh authenticated same-suite
metadata and exact package plans follow; source alignment alone is not patching.

## Recover the old Apache preflight rejection

For an existing v2.1.1 job stopped specifically by
`Apache_PHP_requires_separate_migration_profile`, an explicit installer option can
archive its code, checkpoint, logs and unit before starting a new job:

```bash
wget -qO- https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/COMMIT/install.sh | sudo bash -s -- --recover-preflight
```

Recovery requires exact recognized old code/unit/wrapper, the original host,
empty completed stages, no running operation or installer, restored timer state,
private evidence and no OS/package work artifacts. Other failed jobs are never
reset. An ineligible checkpoint stays preserved. Ordinary reruns still preserve
existing job state. Status always uses the full `/root/ubuntu-global-updater.sh`
path; adding it to a user's PATH is unnecessary.

## Explicit local health exclusions

An operator may record obsolete preview hostnames in the root-owned mode0600 file
`/etc/ubuntu-global-updater/health-exclusions.json`. Schema1 contains exactly
`schema`, `host_binding` (from `host_identity.capture()` on that host), and
`excluded_hosts` (a nonempty list of unique exact lowercase DNS names). No wildcard,
URL/path expression, inherited global default or client hostname is built in.

The file is safely read and bound to this machine. Exclusions must match discovered
PHP hostnames and cannot remove every probe. They affect only HTTP health probes;
Nginx configuration/routing audits, certificates and services are not modified.
All remaining probes retain certificate/hostname verification and HTTP2xx/3xx
requirements. Early/global and PHP migration/retirement health paths share this
policy. Baselines record its hash (including absence); the worker binds that
receipt across stages and reboots. Changing policy during a job stops its next
verification instead of adopting broader exclusions. Existing jobs are never
reset to introduce an exclusion; configure it before starting a new job.

## Host eligibility

The prior operator-requested replacement exclusion has been removed. Ubuntu18.04
hosts now follow the normal18.04→20.04→22.04→24.04 path regardless of hostname.
This does not bypass existing failed jobs, database-major migration holds or other
compatibility checks. Recognized v2.0.1 preflight-only payloads can be refreshed.

## Duplicate-pool preflight fix and retry

Repeated scalar FPM pool settings are inventoried using PHP's final assignment.
All array/environment/PHP-value declarations remain in their original order and
are all audited; migration preserves the pool bytes except the reviewed socket
branch change. Duplicate sections, unsafe settings and ambiguous routes still hold.
The actual PHP-FPM configuration test remains required. Early health errors now
show their specific reason code instead of only `EarlyError`.

If the older installer stopped in preflight before creating any job state/unit,
running this installer again can refresh an exact recognized updater payload.
It archives the previous updater files and preserves generated bytecode/evidence.
It never edits the existing application pool file to suppress duplicate settings.
Unknown/modified payloads, active preflight/worker processes, any job state or unit,
unsafe wrapper paths and competing admissions refuse refresh. An existing queued,
running or failed job still requires diagnosis; no job checkpoint is deleted.

## Download and run

Use a reviewed full commit SHA for `COMMIT`, and run as root on the selected host:

```bash
(
  set -o pipefail
  wget --https-only --timeout=30 --tries=1 -qO- \
    https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/COMMIT/install.sh | bash
)
```

Apply starts immediately and includes service restarts, downtime and required
reboots on native hosts. The retained systemd worker continues after native reboot without an open console. WSL never requests Windows/VM shutdown; its manual restart checkpoint is described below.
The installed wrapper defaults to read-only plan; this installer explicitly selects
apply. A repeated installation preserves existing jobs; only recognized preflight-only updater files can be refreshed as described above.

```bash
bash /root/ubuntu-global-updater.sh --status
journalctl -fu ubuntu-global-updater.service
cat /var/lib/ubuntu-global-updater/report.json
```

Use the reviewed installer SHA256 for download-first checksum verification when
preferred. A commit-specific command is provided with publication. Never replace a
reviewed production commit with a moving `main` URL.

## OS-first behavior and preservation

- The early path runs on Ubuntu18.04's Python3.6; modern runtime/PHP modules are
  imported only after24.04. Actual extracted Canonical-authenticated Python3.6 was
  used for local bootstrap tests, without installing cross-release packages.
- Before old-release preparation, immutable private configuration/source captures
  are saved. Only captured known external PHP PPA entries are temporarily disabled,
  so retired Bionic/Focal PPA suites cannot derail Ubuntu's preparation refresh.
  Official Ubuntu repository entries are preserved. The complete source file set,
  bytes, metadata and signing-key references are checked for drift.
- PHP packages are kept during old-release preparation. Native OS transaction
  guards refuse PHP package changes/removals before24.04. Configurations and known
  repository files are restored to each reached release; fresh authentication and
  usable PHP candidates are required at24.04 before PHP installation.
- Database engine compatibility lines remain unchanged. A standard18.04 MySQL5.7
  installation needing MySQL8 to complete an OS hop **holds for a separate database
  migration**. OS support is not approval for that database/schema transition.
- Installed APT software is updated from authenticated matching-release sources;
  supported Node majors are preserved and EOL APT Node targets24 LTS when its
  existing trusted source and compatibility/consumer checks allow it.
- APT timers are paused/restored. Identified unattended-upgrade locks use the
  reviewed pidfd handoff where supported; old Python/kernel combinations without
  pidfd only wait up to60seconds and hold if still busy. They never guess with PID
  signals, delete lock files, or kill dpkg. Failed/interrupted installs never retry.
- Known stale native service main processes may restart. Unknown/custom units hold.
  Successful completion requires actual package/service/boot/health verification.

## Compatibility holds and scope

Mixed active legacy and already-installed target runtimes, multiple legacy
branches, legacy Apache major migrations/custom layouts, ambiguous sockets/units/jobs, incompatible
WordPress core and Composer applications require a reviewed additional profile.
Extensions are preserved or explicitly rejected before cutover. Removed embedded
modules such as WDDX, missing maintained replacement extensions, unsupported custom
INI settings and native addon/app incompatibilities are not silently discarded.

Unknown/insecure repositories, source drift, held/broken packages, unavailable
same-release candidates, failed legacy checkpoints or insufficient backup captures
stop the run. Old Node/vendor repositories needing trust/bootstrap changes require
their own reviewed procedure. Active Node applications need service-specific work.

WordPress/plugins/themes, Laravel/Composer/npm application dependencies, custom/nvm
runtimes and container images are outside apply coverage. No application builds,
image uploads, purge/autoremove, database-row inspection or independent schema
commands are performed. Package maintainer scripts retain their normal effects.
Configuration capture is not a database backup or tested restore; recovery remains
operator controlled. Raw private logs/backups must never be published.

## Evidence and limits

This remains a **review candidate**: no full live release upgrade or live application
migration has been exercised for the consolidated bundle. Validate a canary with
working recovery before wider execution. `validation.json` and
`publication-review.json` bind this revision's exact files and local evidence.

```bash
python3 -B verify_release.py
```

This checks hashes, embedded module equality and Bash syntax without running the
updater. On older Python it compiles only the early modules; modern modules are
checked by the full validation under a modern interpreter. Legacy v10 source files
may remain in repository history/root for reference; the active installer uses
only the twenty-one runtime/bootstrap modules listed in `release.json` and its embedded manifest.

Security floor evidence remains the reviewed October25,2026 PHP fixes for
CVE-2026-109618/109619 plus the Ubuntu backport exception. The separate October23
session-upload-progress advisory requires effective-setting review; configuration
preservation does not establish closure of that additional issue.

Primary references: [Ubuntu LTS upgrades](https://documentation.ubuntu.com/server/how-to/software/upgrade-your-release/),
[PHP migration compatibility](https://www.php.net/manual/en/migration80.incompatible.php),
[PHP advisories](https://www.php.net/index.php), [Node releases](https://nodejs.org/en/about/previous-releases).

The PHP parser behavior was checked against [official PHP7.3 FPM source](https://raw.githubusercontent.com/php/php-src/PHP-7.3/sapi/fpm/fpm/fpm_conf.c) and [PHP8.3 FPM source](https://raw.githubusercontent.com/php/php-src/PHP-8.3/sapi/fpm/fpm/fpm_conf.c).
