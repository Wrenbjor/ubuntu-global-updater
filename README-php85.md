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

From version 1.0.5, the updater recognizes one precise dual-signature case. The current pinned
primary fingerprint `B8DC7E53946656EFBCE4C1DD71DAEAAB4AD4CAB6` must have a good,
strong signature. An aggregate `gpgv` exit status of 2 is admitted only when its
other signature is the known missing legacy key
`14AA40EC0831756756D7F66C4F4EA0AAE5267A6C`. The proof records both that aggregate
status and the missing legacy signer. This does not fetch a key, change trust,
enable a source or accept arbitrary nonzero verifier results; other signature
failures still hold.

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

Standard merged-`/usr` layouts are supported only for the exact root-level
`/bin`, `/sbin`, `/lib` and `/lib64` aliases to their matching `usr/<name>`
directories. The real directories must be root-owned and safe. Alias identity
and target changes are checked and recorded in configuration snapshots; this
does not relax permissions or admit arbitrary parent symlinks. Unsafe-parent
diagnostics identify the requested path, parent path, UID, GID, mode and type.

The standard Forge ACME exception is also recognized: a static
`location /.well-known/acme-challenge` prefix, optionally with a trailing slash
or `^~`, may use a literal absolute alias such as `/home/forge/.letsencrypt`.
Only the explicit static directive allowlist is admitted. The alias bytes are
preserved and its target is untouched. Traversal, variables, control characters,
rewrites, nested locations and alternate routing or handlers still hold. Other
aliases require a separate health profile; this is not general alias support.

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
Failed jobs are preserved. Only the exact, evidence-bound recovery and
configuration-continuation exceptions described below run automatically. Other
failures are not automatically retried.
When 8.5 is already current and the sealed plan has no package changes, apply
verifies it without rewriting Nginx, acting on services or changing alternatives.
Existing APT source enabled/disabled state is preserved; this tool never enables
a disabled source as part of planning or apply.

Version 1.0.7 retains five narrowly defined automatic preflight recovery cases on the
same `--apply` command: the exact byte-pinned version 1.0.0
`nginx_path_outside_config` failure, and the exact byte-pinned version 1.0.1
`absolute_nginx_include_required` failure, plus the exact byte-pinned version
1.0.2 `Nginx_alias_requires_separate_health_profile` failure, plus the exact
byte-pinned version 1.0.3 `unsafe_file_parent` failure, and the exact byte-pinned
version 1.0.4 `command_failed_gpgv` failure. Each must match its original core,
three-event preflight chain and timer evidence, with empty failure details and
no recovery reference. Eligibility requires no sealed plan or package action
and restored timer activity. Cached APT indexes may already have been refreshed;
this is not a claim that nothing changed. All original evidence and the old
current-job pointer are archived durably before a new job. Partial archival and
every other failed-job shape still hold for inspection. No additional recovery
flag or host ID is needed; rerun the same apply command.
The version 1.0.3 exception still requires empty details exactly. A new version
1.0.4 failure carrying path diagnostics is not automatically reset.

For a failure before the sealed plan, recovery metadata may not exist. Its status
diagnostic reports `recovery: null` rather than treating that missing file as a
new failure or manufacturing recovery instructions.

Version 1.0.6 separately addresses the exact version 1.0.5 APT hook protocol
failure during `installing_packages`. APT 2.4 identifies hook options by the
executable command key; a dedicated root-private job wrapper now selects protocol
version 2 unambiguously. APT stdout/stderr are streamed to private job logs; after
exit, their byte counts and SHA-256 hashes are bound into the event chain. A
running native package transaction is not killed by a wrapper timeout.

This installation-stage failure is not treated as a preflight rejection. Its
distinct recovery requires the exact pinned old core and six-stage event chain,
no accepted hook proof, and no package changes beyond the saved baseline. The full old package,
source, configuration, identity and health baselines must still match, with
clean package state, no active package writer, restored timer activity and no
temporary service policy. Original CLI-alternative values and automatic/manual
modes must be restored with a durable receipt before a fresh plan. All old
evidence and the old current-job pointer remain archived. Any other state or a
partial recovery holds; this is not a blind APT retry. Earlier index refresh and
alternative preparation are acknowledged rather than described as zero changes.

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

Version 1.0.7 omits an explicitly disabled `mysqli.reconnect` setting when the
PHP 8.5 registry no longer defines it. Enabled or unknown values still hold,
and unrelated removed settings keep their existing checks. Diagnostics identify
the directive and configuration filenames without printing its value. Both SAPI
settings and pool directives are validated before target pool, global FPM or
migration INI files are written.

A separate, one-use v1.0.7 configuration continuation recognizes only the exact
byte-pinned v1.0.6 migration failure after successful APT installation, accepted
hook proof and the known disabled `mysqli.reconnect` case. It validates the
eight-event chain, private package logs, sealed plan, exact post-install package
table, original source/configuration/health baselines, unchanged old CLI
selection, inactive target FPM, package-proven target INI defaults and the exact
partially copied pools/global configuration. Extra target settings or prior
migration INIs hold. It pauses and restores the recorded timers, preserves the
old source, plan, backups and failure-pointer bytes, and records a durable
continuation receipt before configuration writes. It does not rerun APT or
create a fresh installation job. Interrupted continuation remains blocked for
inspection; it is not automatically replayed.
