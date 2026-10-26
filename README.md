# Ubuntu global updater v2

One installer for a selected DigitalOcean Ubuntu host: **finish the OS upgrade to
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

Every LTS hop has its own checkpoint, reboot and target-release/kernel verification.
Ubuntu16.04 and unknown/newer releases hold; the updater never downgrades an OS.
Existing replacement-host exclusions remain in force.

PHP7.2/7.3/7.4/8.0/8.1 are migration **sources**, not patched destination branches.
The preferred new branch is8.3, with the reviewed supported8.x candidate/compatibility
policy and authenticated distribution-backport handling. A healthy existing higher
supported branch is preserved when retiring a dormant legacy branch. Detection does
not assume image labels, default `php -v`, or installed package presence prove the
running web version. Pools, extensions, source API/ABI, CLI, actual Nginx sockets,
workers and local application health are checked.

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
reboots. The retained systemd worker continues after reboot without an open console.
The installed wrapper defaults to read-only plan; this installer explicitly selects
apply. A second installation preserves an existing job rather than overwriting it.

```bash
bash /root/ubuntu-global-updater.sh --status
journalctl -fu visionline-global-updater.service
cat /var/lib/visionline-global-updater/report.json
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
branches, Apache/custom layouts, ambiguous sockets/units/jobs, incompatible
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
only the twelve modules listed in `release.json` and its embedded manifest.

Security floor evidence remains the reviewed October25,2026 PHP fixes for
CVE-2026-109618/109619 plus the Ubuntu backport exception. The separate October23
session-upload-progress advisory requires effective-setting review; configuration
preservation does not establish closure of that additional issue.

Primary references: [Ubuntu LTS upgrades](https://documentation.ubuntu.com/server/how-to/software/upgrade-your-release/),
[PHP migration compatibility](https://www.php.net/manual/en/migration80.incompatible.php),
[PHP advisories](https://www.php.net/index.php), [Node releases](https://nodejs.org/en/about/previous-releases).
