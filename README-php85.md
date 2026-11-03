# PHP-only updater for Ubuntu 22.04

This is a manually operated, single-host updater for an existing standard
Nginx/PHP-FPM installation on native Ubuntu 22.04 with systemd, on amd64 or arm64.
WSL and containers require a separate updater profile. It targets PHP 8.5 using
the core's exact package, extension, configuration, routing and health checks.
The host must already trust an enabled canonical Ondrej PHP PPA for Jammy.
Missing, disabled, foreign-suite or untrusted sources produce a specific hold;
the updater does not add a repository or download a signing key automatically.
The existing signed PPA metadata is checked against the pinned trusted primary
key fingerprint; candidate versions and package archives are checked again for
the sealed transaction.

The active Nginx routes must use local Unix FPM sockets owned by one PHP branch:
7.2, 7.3, 7.4, 8.0, 8.1, 8.2, 8.3, 8.4 or 8.5. The default CLI must match that
web branch. A separate dormant PHP 8.5 installation alongside an older active
source is held for review. A same-branch 8.5 patch does not rewrite Nginx routes.
The profile requires native HTTPS on port 443, literal document roots and direct
Unix-socket FastCGI routes. Variable or ambiguous routes, custom layouts, unknown
service ownership, unowned extensions and incompatible settings stop the plan.
It targets the configured web runtime and matching default CLI; it does not
rewrite cron, queue, supervisor or application references to hardcoded legacy
PHP executable paths.

Static relative Nginx includes are resolved from the main configuration directory,
`/etc/nginx`, matching native Nginx behavior. This supports standard Forge
`forge-conf/site/before/*`, `forge-conf/site/server/*`,
`forge-conf/site/after/*` and `fastcgi_params` includes. Dynamic values, parent
directory references and paths escaping the allowed configuration tree still
hold. This does not broaden the separate vendor-module exception below.

Stock `modules-enabled` symlinks to `/usr/share/nginx/modules-available` are
admitted only for read-only vendor module configuration. The configuration and
canonical `.so` library must be root-safe and match installed package ownership
and MD5 inventory; the admitted configuration contains only the module loader.
This exception does not admit arbitrary external include or library paths.

The installer contains its complete Python payload. It downloads no additional
updater code or Python libraries at runtime. System Python 3.10 and the existing
Ubuntu `python3-apt` package are required. Normal authenticated APT package
downloads occur only during an explicit apply.

For convenience, the current `main` URL can inspect the plan:

```bash
wget -qO- https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/main/php85.sh | sudo bash
```

To create a sealed local plan and apply it to this same host:

```bash
wget -qO- https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/main/php85.sh | sudo bash -s -- --apply
```

The equivalent apply command is:

```bash
curl -fsSL https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/main/php85.sh | sudo bash -s -- --apply
```

`main` can change. For a reproducible run, replace `/main/` with the published
release commit SHA and compare its recorded artifact hashes. Add `set -o pipefail`
in the invoking shell if you also want the pipeline exit status to reflect a
downloader failure.

The operator selects the host by running the command on it. There is no fleet
controller, cloud API, host list or remote execution. Keep the session open for
the foreground operation. Interruptions and failures require inspection; do not
repeatedly run an installer to retry an unknown package state.
Original PHP/Nginx configurations, the sealed plan and recovery metadata are
retained in root-private job backups under `/var/lib/ubuntu-php85-upgrade`.
Failed jobs are preserved; the exact preflight exception below is the only
automatic recovery path. Other failures are not automatically retried.
When 8.5 is already current and the sealed plan has no package changes, apply
verifies it without rewriting Nginx, acting on services or changing alternatives.
Existing APT source enabled/disabled state is preserved; this tool never enables
a disabled source as part of planning or apply.

Version 1.0.2 has two narrowly defined automatic preflight recovery cases on the
same `--apply` command: the exact byte-pinned version 1.0.0
`nginx_path_outside_config` failure, and the exact byte-pinned version 1.0.1
`absolute_nginx_include_required` failure. Each must match its original core,
three-event preflight chain and timer evidence, with empty failure details and
no recovery reference. Eligibility requires no sealed plan or package action
and restored timer activity. Cached APT indexes may already have been refreshed;
this is not a claim that nothing changed. All original evidence and the old
current-job pointer are archived durably before a new job. Partial archival and
every other failed-job shape still hold for inspection. No additional recovery
flag or host ID is needed; rerun the same apply command.

For a failure before the sealed plan, recovery metadata may not exist. Its status
diagnostic reports `recovery: null` rather than treating that missing file as a
new failure or manufacturing recovery instructions.

After creating the updater locally, the same URL supports `--status` in place of
`--apply`. `--plan-only` explicitly selects the default planning mode. Unsupported
options are rejected. Default planning and status do not write APT sources,
install packages, change routes or act on services. Bootstrap artifacts are
private temporary files under `/run`; apply may create private bootstrap files
under `/var/lib/ubuntu-php85-upgrade` before the core creates its own sealed job.

`--rollback` is a separate manual action for the current recorded migration job;
it is not available for a same-branch patch. It can
restore only its exact owned Nginx routes and CLI alternatives after drift
checks. It does not downgrade, reinstall or remove packages, and it does not
claim to undo application data changes. Inspect the saved failure and recovery
metadata first; rollback is not an automatic package retry.

The bootstrap verifies compressed bytes, payload length and SHA-256 before
executing the embedded core with isolated system Python. It validates the
complete function and final completion token before creating bootstrap files;
truncated prefixes cannot start the updater. Embedded checksums detect damaged
downloads; obtain the installer from the reviewed immutable URL, since a hash
inside a script cannot authenticate a maliciously replaced script itself.
The verifier and core run with a fixed minimal environment. The bootstrap
explicitly rejects inherited `APT_CONFIG`, Python-path, loader and shell-startup
override variables instead of silently honoring them. Download-time options
belong to the operator's trusted shell and downloader.

Apply-time FPM validation uses a random, nonsecret PHP probe under `/run`, outside
the webroot. It is sent directly to each approved Unix FPM socket; no customer
application file or database is read. The proof checks the nonce, PHP version,
SAPI, peer process lineage and current executable/extension mappings. Cleanup
checks the exact probe inode and content before removing that file.

This updater changes PHP only within its explicit core policy. It does not
upgrade Ubuntu, change database majors or schemas, update application code,
WordPress/plugins/themes or Composer dependencies, or claim universal PHP 8.5
application compatibility. Apache, containers, custom runtime/service layouts
and ambiguous routing require a separate reviewed path. Test the application
and retain independently usable backups before a runtime major migration.
HTTP/TLS smoke checks verify only the configured endpoints, not all application
behavior. Legacy PHP packages and source FPM configuration/services are retained;
this tool does not retire, purge or automatically decommission the old branch.

Local packaging fixtures are not a production migration test. The existing
global `install.sh` is a separate updater and is not replaced by `php85.sh`.
