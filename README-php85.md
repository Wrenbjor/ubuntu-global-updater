# PHP 8.5.12 — standalone recipe (local review candidate)

The single downloaded shell file embeds Python 3 helpers for discovery and
configuration checks. Python 3 must be installed. Run as root on the selected
native Ubuntu 22.04 or 24.04 Nginx/PHP-FPM host:

```sh
sudo bash php85.sh --plan-only
sudo bash php85.sh --apply
sudo bash php85.sh --status
```

No option means plan-only. Status reads native versions, service state and Nginx
configuration. Apply uses ordinary repository, APT and service commands. It
refreshes indexes and installs matching PHP 8.5 extensions, migrates source
pools and verified common settings, backs up the affected routes,
and switches their literal Unix sockets. Native configuration, version and HTTP
checks determine success; deprecation stderr alone is not a failed native test.
The supported layout has one active web PHP branch and one pool per `.conf`
file (multiple pools supported). Direct literal Unix sockets under `/run/php`
or `/var/run/php` are matched to pool ownership rather than a filename convention.
Custom sockets receive distinct `.php85.sock` destinations; old pools remain intact.
Include-aware HTTP health discovery associates routes with their server blocks and
uses each literal hostname with the configured HTTP/TLS listener and port.

The script does not read legacy updater checkpoints or perform OS upgrades,
database-major changes, WordPress changes, purge or autoremove. Keep the SSH
session open and retain the printed backup location. Unknown layouts and failed
checks require inspection. Existing PHP packages are retained; package-lock
failure stops the run without killing the lock owner. Homepage HTTP
checks must return 2xx or 3xx after the change. HTTP checks are smoke tests, not a compatibility
audit of every plugin, theme, job or application.

## Exact target and current fleet limits

Core CLI/FPM/common packages are selected at exactly upstream **8.5.12**, even if
APT's candidate is newer. Independently versioned extensions use their matching
Ubuntu-release candidates. If the exact core packages are absent from enabled
repository indexes, apply stops before PHP package installation. It never silently
substitutes a newer patch. CLI and FPM must report exactly 8.5.12 before completion.
This is not a permanent APT hold: later package maintenance can change PHP.

This candidate is **not yet a general 135-server fleet migration**. Same-branch
multiple/custom pools and sockets are supported. Source global FPM values are
preserved with target PID and branch-local include paths; external/nested FPM
includes and mixed active PHP branches stop for review. An existing customized
8.5 target pool stops before APT; identity/socket equality is not sufficient.
Shared Nginx route includes are supported for health discovery. Route rewriting
still requires standalone, unquoted literal Unix `fastcgi_pass` directives.
Common custom INI settings are migrated. Other active source directives must
match installed package baselines or stop for review; custom loaders and unsafe
pool overrides stop. Target configuration must match its own package baseline
before migration. Per-SAPI module links are synchronized and enabled source
modules are checked in target CLI/FPM module output. Built-in module identity
and changed PHP default semantics are not claimed equivalent across major versions.
Health checks use each discovered primary HTTP/TLS homepage, not WordPress-specific
paths. A successful homepage is only a smoke test, not full application validation.
Cutover/health failures restore unchanged-by-others route files, the original CLI
alternative and the post-package/pre-migration target configuration. Package
installation itself is **not** rolled back. Concurrent edits are preserved and
cause rollback to stop. `/root/php85-active-run` retains the backup path after an
unrecoverable interruption or incomplete rollback and blocks another apply until
an operator reconciles the recorded state. It is not an automatic resume feature.
The earlier silent INI omissions and custom-target reuse now fail closed. CLI
rollback restores automatic mode only when it still selects the original binary;
otherwise it retains that binary in manual mode and reports incomplete rollback.
Real package/service/VM validation remains required. Do not deploy this candidate
as the completed fleet updater.

The OS installer remains a separate, older OS-first path ending at 24.04. It is
not yet suitable for PHP-first 22.04→24.04→26.04. See `FLEET-UPGRADE-PLAN.md`.

Source PHP configuration and the full active Nginx dump are checked for drift
again after taking the worker lock, after APT, and before route replacement.
Unexpected edits stop migration; the updater does not silently apply a stale
route or configuration plan. Source configuration symlinks must resolve to files
inside the source branch. Nginx packages themselves are protected, not upgraded.

Run the offline suite on Linux with real fixture Unix sockets:

```sh
python3 -B -m unittest discover -v
bash -n php85.sh
bash -n forge-php85-recipe.sh
sha256sum --check PHP85-SHA256SUMS
python3 -B verify_release.py
```

The CI workflow repeats this on Ubuntu 22.04 and 24.04. It mocks package/service
commands and does not replace real PHP/Nginx or OS-upgrade integration tests.
For an environment that prohibits sockets, explicit
`PHP85_TEST_MOCK_SOCKET=1` substitutes regular files. That mode does not validate
Unix sockets and is not the CI default.

## Forge deployment recipe

`forge-php85-recipe.sh` downloads only `php85.sh`, verifies a full commit SHA and
expected SHA256, runs Bash syntax validation, then executes the chosen mode.
Select **root** as the Forge recipe user. Set `UPDATER_COMMIT` and `UPDATER_SHA256`
to a published, reviewed revision before use. Placeholders intentionally fail.
Default mode is `--plan-only`; set `UPDATER_MODE=--apply` only for an authorized
maintenance run. This does not invoke the OS installer or reboot the machine.
This WIP branch is published for development review, not approved deployment.
The template pins remain placeholders until a fleet-ready release is validated.
