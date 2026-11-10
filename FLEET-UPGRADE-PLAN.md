# Two-phase fleet upgrade: implementation status

Requested: one Forge-deployable updater that dynamically migrates each eligible
Ubuntu22.04 host to exactly PHP8.5.12, then separately upgrades the OS to26.04.
Forge metadata synchronization is secondary. No production execution performed.

## Current candidate

Local patch selects exact8.5.12 core packages and verifies exact CLI/FPM versions.
The existing Bash runner is intentionally not presented as fleet-complete: it
supports one standard www pool. Health probes are now application-neutral HTTPS
homepage checks; a commit/checksum-pinned Forge recipe template is included.

## PHP phase still required

- Discover effective Nginx routes and FPM pools, including included route files,
  custom sockets and multiple pools. Associate host/health probes with server
  blocks rather than filenames. Refuse only genuinely ambiguous layouts.
- Preserve source global FPM configuration, custom INI settings, enabled/disabled
  modules and pool identities; adapt PID/include/socket paths for the target.
- Existing source binary may be absent; distinguish stale configurations from
  actual active routes, not CLI version or a filename convention.
- Do not assume repository filename; validate actual enabled same-suite packages.
- Snapshot route/CLI state and restore on cutover or health failure; preserve
  old runtime. Package installation rollback is a separate concern.
- Broader application health checks, runtime module verification, explicit
  per-host result/status, resumable interrupted-state handling, and rerun tests.
- Publish a reviewed commit and fill its SHA/hash into the included download-first
  Forge recipe only after the required validation passes.

## OS phase still required

Supported Ubuntu path:22.04→24.04→26.04, with a reboot/checkpoint per hop.
Canonical enabled24.04→26.04.1 on September29,2026.

Sources:
- https://documentation.ubuntu.com/release-notes/26.04/
- https://lists.ubuntu.com/archives/ubuntu-announce/2026-September/000328.html
- https://ubuntu.com/server/docs/how-to/software/upgrade-your-release/

The current OS coordinator always runs PHP/Node/package maintenance after its
24.04 target. Add an explicit OS-only phase rather than just changing TARGET.
Update ubuntu_global_os.py HOPS, ubuntu_global.py target gates, php_repository.py
suite mapping, and the embedded installer/release manifest together. Preserve
existing failed/interrupted checkpoints; completed24.04 is not completed26.04.

The current defer_php guard freezes existing PHP packages. Jammy PHP8.5 packages
may depend on libraries unavailable after the next OS hop. Define and test
same-branch, same-suite PHP preservation/rebuild for each hop; don't waive the
guard without a replacement. Preserve database-major compatibility holds.

Verify the private DistUpgradeController/MyCache/SafeProgress adapter against
the actual authenticated Resolute upgrader. Existing APIs may have changed.
Regenerate install.sh's21 embedded modules and matching hashes only after
source changes pass. Most historical OS test modules named in validation.json
are not present in this checkout.

## Required validation before fleet-ready claim

Fixtures for multi-pool routing, missing old binary, customized globals, package
absence, exact target, failure rollback, rerun/drift,22/24/26 sequential plans,
reboot proof, old checkpoints, database holds and per-hop source restoration.
Then disposable-VM PHP/Nginx migration and22.04→24.04→26.04 integration with
real packages and application checks. Existing stored review approvals do not
cover new changes. No live upgrade has been tested by this patch.
