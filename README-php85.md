# PHP 8.5.12 — Bash (local review candidate)

Run as root on the selected native Ubuntu 22.04 or 24.04 Nginx/PHP-FPM host:

```sh
sudo bash php85.sh --plan-only
sudo bash php85.sh --apply
sudo bash php85.sh --status
```

No option means plan-only. Status reads native versions, service state and Nginx
configuration. Apply uses ordinary repository, APT and service commands. It
refreshes indexes and installs matching PHP 8.5 extensions, reuses a configured 8.5 pool
or prepares the standard pool/common settings, backs up the affected routes,
and switches their literal Unix sockets. Native configuration, version and HTTP
checks determine success; deprecation stderr alone is not a failed native test.
The supported layout has one standard `www.conf` pool, one active web PHP branch,
literal Unix socket routes and primary HTTPS hostnames in the route files.

The script does not read previous updater checkpoints or perform OS upgrades,
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
substitutes a newer patch. CLI and FPM must report exactly8.5.12 before completion.
This is not a permanent APT hold: later package maintenance can change PHP.

This candidate is **not yet a general 135-server fleet migration**. Multiple/custom
pools and sockets, shared Nginx includes without a hostname, and custom FPM
globals still require implementation work.
Health checks use each discovered primary HTTPS homepage, not WordPress-specific
paths. A successful homepage is only a smoke test, not full application validation.
Failure after changing Nginx does not roll back automatically. Do not deploy this candidate as the completed fleet updater.

The OS installer remains a separate, older OS-first path ending at24.04. It is
not yet suitable for PHP-first22.04→24.04→26.04. See `FLEET-UPGRADE-PLAN.md`.

Focused checks: `PHP85_TEST_MOCK_SOCKET=1 python3 -B -m unittest test_php85_shell`.
This mode explicitly substitutes a regular file for the fixture's Unix socket
when the test environment prohibits sockets; it does not validate real sockets.

## Forge deployment recipe

`forge-php85-recipe.sh` downloads only `php85.sh`, verifies a full commit SHA and
expected SHA256, runs Bash syntax validation, then executes the chosen mode.
Select **root** as the Forge recipe user. Set `UPDATER_COMMIT` and `UPDATER_SHA256`
to a published, reviewed revision before use. Placeholders intentionally fail.
Default mode is `--plan-only`; set `UPDATER_MODE=--apply` only for an authorized
maintenance run. This does not invoke the OS installer or reboot the machine.
The current local candidate has not been published, so its commit cannot yet be
used as a GitHub download target.
