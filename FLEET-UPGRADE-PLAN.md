# Two-phase fleet upgrade: integration candidate

Goal: deploy one pinned Forge recipe across eligible Ubuntu 22.04 hosts, migrate
PHP to exactly **8.5.12**, then run a separate **22.04 → 24.04 → 26.04** OS phase.
Forge metadata synchronization is secondary. No production hosts were changed.

## PHP implementation

- Exact core package selection and exact CLI/FPM runtime-version checks.
- Same-source-branch multiple FPM pools and custom local Unix sockets; source
  global configuration and pool identities preserved with target paths.
- Include-aware Nginx health discovery associates PHP routes with server blocks,
  configured HTTP/TLS listeners, local addresses, ports and literal hostnames.
- Atomic route cutover, guarded configuration/CLI rollback, concurrent-edit
  preservation and durable failed/interrupted checkpoints. Packages themselves
  are not rolled back. Incomplete rollback blocks retries rather than guessing.
- Download-first, commit/SHA256-pinned Forge recipe template, default plan-only.

The candidate is not fleet-certified. Mixed active PHP branches, nested/external
FPM includes, nonliteral/inline/multiline Nginx routes and health listeners that
cannot be safely probed stop rather than partially migrating. Homepage responses
are smoke checks, not evidence that an application executed PHP. Queue workers,
schedulers, hardcoded PHP paths and Forge metadata need separate verification.

Independent review found silent INI/module loss and unsafe custom-target reuse
in the earlier candidate. Targeted fail-closed source/target configuration guards, runtime module checks
and custom-target rejection are now integrated;
passing mocked fixtures alone is not proof of full application compatibility.
See README-php85.md and the current validation report for scope and remaining
configuration/module limitations. Do not use the recipe placeholders as a
published deployment pin.

## OS implementation and remaining blocker

`fleet_os_stage.py` implements the separate PHP-first lifecycle, exact-version
and same-suite package contracts, durable failure/reboot checkpoints, one hop
per invocation and no automatic reboot. `fleet_os_native.py` implements the
public `do-release-upgrade` command boundary without development-release flags.
The legacy `install.sh` remains unchanged, OS-first and targeted at 24.04; it is
**not** the new second phase.

**The new OS phase is not a usable production recipe yet.** A concrete host
policy adapter must provide authenticated target-suite package resolution,
native transaction protection, database-major preservation, exact PHP restore
and actual runtime/application verification. A command boundary and fixture
backend do not provide these guarantees. Do not run an unguarded release upgrade
as a substitute. See README-fleet-os.md.

Ubuntu supports sequential 22.04 → 24.04 → 26.04, with a reboot/checkpoint per
hop. Canonical enabled the 24.04 → 26.04.1 upgrade on September 29, 2026.

Sources:
- https://documentation.ubuntu.com/release-notes/26.04/
- https://lists.ubuntu.com/archives/ubuntu-announce/2026-September/000328.html
- https://ubuntu.com/server/docs/how-to/software/upgrade-your-release/

## Before any fleet-ready claim

Run disposable-VM PHP/Nginx migrations with real sockets/packages and custom
configuration/module cases, failures and reruns. Then validate the complete
22.04 → 24.04 → 26.04 path with a real guarded backend, package provenance,
database holds, reboot proof and application checks. Historical stored approvals
and legacy installer hash verification do not approve these new changes.
