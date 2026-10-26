# Ubuntu global updater

One self-contained installer for the current Ubuntu DigitalOcean Droplet. You do
not need to download the Python modules separately: `install.sh` embeds every
required module, verifies its bundle, installs it privately, and starts apply.
Readable modules are included here for code review.

**Review candidate.** Local fixtures/mocks passed; a full live OS upgrade and live
application migration have not been exercised for this consolidated bundle.
Review the code and recovery coverage and validate a canary before wider use.

## Download and run

Use a reviewed full commit SHA in place of `COMMIT`. Run as root on the selected
Droplet. Apply includes automatic reboots, service restarts and downtime.

```bash
wget --https-only --timeout=30 --tries=1 -qO- \
  https://raw.githubusercontent.com/wrenbjor/ubuntu-global-updater/COMMIT/install.sh | bash
```

For checksum-verified execution, download first, compare its SHA256 to the
independently reviewed installer digest, then run Bash. A concrete pinned command
is provided with the publication. HTTPS certificate verification remains enabled.
Do not substitute a moving `main` URL for an approved production revision.

## Behavior

- Sequential Ubuntu20.04→22.04→24.04; Ubuntu22.04→24.04; already24.04 skips OS hops.
- Exact authenticated APT package updates, preserving modified configurations.
- Existing supported PHP8 branches patched; PHP7.4 migrated with the reviewed
  WordPress/Nginx/FPM profile, including extensions, pools, actual routes and health.
- Supported Node majors preserved; end-of-life APT Node targets24 LTS, using only
  a previously trusted NodeSource repository/key when its compatibility checks pass.
- Database engine compatibility lines preserved; no independent schema commands,
  database-row inspection, application builds, purge/autoremove or image uploads.
- Persistent systemd worker, host-bound state, installer locks, private configuration
  captures/logs, restored APT timer state and verification across required reboots.
- Identified unattended-upgrade lock owners receive a bounded handoff. Narrow force
  handling can stop a verified childless CPU loop; active dpkg is never killed and
  package lock files are never deleted. Failed package transactions never auto-retry.

The installed wrapper defaults to read-only plan; this installer explicitly starts
apply. Installing twice preserves the existing job rather than overwriting it.

```bash
bash /root/ubuntu-global-updater.sh --status
journalctl -fu visionline-global-updater.service
cat /var/lib/visionline-global-updater/report.json
```

Raw evidence stays root-private. Keep these logs and configuration backups out of
public repositories: they can contain credentials. This repository contains only
source and static release metadata, with no fleet inventories or credentials.

## Holds and coverage

Ubuntu18.04/unknown/newer releases, replacement-designated hosts, held/broken
packages, unsupported database-major transitions, unknown repositories, unsafe
configuration captures, conflicting installers and failed legacy checkpoints hold.

Mixed activePHP7.4 with already-installedPHP8, Apache/custom PHP layouts, incompatible
WordPress core, Composer applications and active legacy jobs need additional profiles.
PHP8.0/8.1 migration is not automated. Active Node applications, ambiguous consumers,
incompatible engines/native addons and unknown runtime sources need service-specific
procedures. Unrecognized stale service main processes require reviewed restart work.

WordPress/plugins/themes, Composer/npm application dependencies, container images,
custom/nvm runtimes and other software outside APT are outside apply coverage.
The configuration capture is not a database backup or a tested restore. Package
success alone is not complete application verification or proof of all CVE closure.

Security floors checked October25,2026: PHP8.2.35/8.3.36/8.4.27/8.5.12 plus the
reviewed Ubuntu Noble backport exception. The separate October23 PHP session-upload
progress advisory still requires effective-setting review; settings are preserved.

## Review and verification

`python3 -B verify_release.py` checks this repository's embedded payload, source
checksums, default modes and syntax without executing the updater. The original
consolidated bundle passed206 local unit/fixture/mock tests. `publication-review.json`
records the separate public-package review; these checks do not establish live
application compatibility. No license grant is asserted beyond GitHub's normal
repository terms.

Primary references: [Ubuntu release upgrades](https://documentation.ubuntu.com/server/how-to/software/upgrade-your-release/),
[Node releases](https://nodejs.org/en/about/previous-releases),
[PHP advisories](https://www.php.net/index.php),
[APT configuration](https://manpages.ubuntu.com/manpages/noble/man5/apt.conf.5.html).
