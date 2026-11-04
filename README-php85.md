# PHP 8.5 updater

One operator-selected host: native Ubuntu 22.04, Nginx, one standard `www`
PHP-FPM pool and a literal Unix socket. Supported source web branches are
7.2–7.4 and 8.0–8.5. The existing trusted Ondrej Jammy repository is required;
the updater does not add sources, change keys or convert database vendors.

Run a cached, read-only plan:

```sh
wget -qO- https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/main/php85.sh | sudo bash -s -- --plan-only
```

Apply on the host where the command runs:

```sh
wget -qO- https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/main/php85.sh | sudo bash -s -- --apply
```

The short URL follows the published main branch. For immutable bytes, replace
`main` with the verified release commit. Keep the foreground session open.
The one-file bootstrap verifies its complete embedded payload before execution.

## What apply does

1. Check the host, native Nginx configuration, source pool/INI profile and
   homepage/login HTTPS baseline. The web route determines the source branch;
   an already-updated default CLI is supported.
2. Create a separate private manual-run receipt, capture the CLI selection and
   pause only the previously active APT timers.
3. Refresh APT indexes once. Pin the matching PHP 8.5 packages and protected
   installed packages, simulate with no removals, then verify the actual native
   archive set. An already-current target skips package installation.
4. Reuse a compatible configured PHP 8.5 pool/INI profile. A proven untouched
   package-default pool can be configured from the source. Fresh setup preserves
   pool permissions and supported settings, with separate CLI/FPM overlays.
5. Test native PHP-FPM, start/restart it when needed and check its executable,
   Unix-socket owner and loaded PHP API. A deprecation warning alone does not
   fail a native configuration test that exits successfully.
6. Back up and change only the identified Nginx socket operands. Test Nginx,
   reload it when routes changed, then check the primary homepage and login URL.
7. Select the default PHP 8.5 CLI when needed, verify timer restoration, and
   record completion. An unchanged healthy 8.5 route needs no new cutover.

Stock Nginx modules and relative Forge includes are handled by native Nginx;
they are not rewritten. Files-based session paths and serialization settings
are preserved. Custom session backends, executable INI hooks, unknown pool
layouts, mixed web branches, TCP/variable routes and incompatible existing
8.5 settings require a separate profile. CLI-only 8.5 does not count as a ready
FPM target. Missing extension candidates hold before installation.

There are no OS upgrades, database-major changes, WordPress/schema changes,
package removals or autoremove operations. Native package installation has no
wrapper kill timeout; its APT lock wait is bounded without killing the owner.
Old PHP packages and the source FPM service are retained for manual rollback.
Hardcoded CLI jobs and queue workers are not rewritten. HTTP smoke checks do
not establish compatibility of every application, plugin or theme.

## Status, evidence and manual rollback

```sh
wget -qO- https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/main/php85.sh | sudo bash -s -- --status
wget -qO- https://raw.githubusercontent.com/Wrenbjor/ubuntu-global-updater/main/php85.sh | sudo bash -s -- --rollback
```

Use `--rollback --run run-YYYYMMDDTHHMMSSZ-xxxxxxxx` (or the full saved run
path) to select an older run after a later failure. Rollback requires unchanged
owned routes and an active retained source FPM service. It restores backed-up
Nginx routes and the saved CLI selection; it does not downgrade packages or
remove target INIs. A restored older CLI selection may need manual alternative
mode because the newly installed version has higher priority.

Receipts, private command logs and backups live under
`/var/lib/php85-updater`. Each rollback gets fresh logs. Old updater checkpoints
remain unchanged and are not treated as recovered. A failed or interrupted
installation in this new workflow requires inspection of its saved logs before
another install attempt. Structured summaries omit configuration values;
private plans/backups may contain them.

Local fixture tests use temporary files and mocked package/service commands.
One check runs PHP with `-n` against synthetic registry facts to test omission
of non-files session credentials; it does not load application code or connect
to a database. The tests do not perform production upgrades. Historical release
and reference files in the repository are not embedded by this entry point.
