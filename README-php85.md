# PHP 8.5 — Bash

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
failure stops the run without killing the lock owner. Homepage and login HTTP
checks must return 2xx or 3xx after the change. HTTP checks are smoke tests, not a compatibility
audit of every plugin, theme, job or application.
