# PHP-first OS stage: lifecycle implementation, not a deployment release

`fleet_os_stage.py` is a separate backend interface and tested state machine for
**22.04 → 24.04 → 26.04** after the PHP migration. It does not invoke the legacy
installer, change its target, run commands, or provide a production backend.
Do not deploy this module as an OS-upgrade Forge recipe yet.

The existing `install.sh` remains an **OS-first, 24.04-targeted** legacy workflow;
it is **not** the second phase for the new PHP-first fleet rollout. Existing
embedded release hashes remain unchanged and verify independently.

## Implemented behavior

- Exact PHP 8.5.12 CLI and every active FPM pool, verified Nginx routing and modules,
  plus authenticated current-suite PHP packages are prerequisites.
- Each hop must provide authenticated candidates for every installed versioned
  PHP package from the **target** suite. Core candidates must be exactly 8.5.12;
  independent extensions retain their own version numbering.
- Candidate completeness, database-major preservation, full current-release
  updates, backups/recovery, free space and a verified native adapter are
  mandatory. Missing/unknown evidence blocks the upgrade.
- One hop per apply invocation. No automatic reboot. A separately observed new
  boot, target kernel and fresh PHP/application health proof are required before
  recording acceptance. Accepting a boot never starts the next hop in the same run.
- Private locked/fsynced checkpoints record `installing` before mutation. Failures
  and interrupted installs never automatically retry. Legacy/unknown checkpoints
  are not silently adopted or overwritten. Completed 24.04 is not completed 26.04.
- A plan invocation does not save checkpoints or call the mutating backend.

## Backend contract and remaining work

A host adapter must implement `snapshot()`, read-only `prepare(decision)`,
`upgrade(decision, prepared)` and read-only `verify(state)`. Evidence must come from
actual host/package observations, not supplied booleans or a saved approval file.
The target package candidate plan is bound to the initial snapshot and persisted
by hash. `upgrade` must enforce that exact plan during **every** apt transaction,
not simply rely on a preflight that can drift.

Required before connecting a Forge OS recipe:

1. Read-only host inventory and isolated authenticated target-suite APT resolver.
   Verify exact 8.5.12 and all extension availability for architecture and suite.
   Never rewrite all APT sources or carry Jammy packages forward by assumption.
2. Native release-upgrader adapter verified against Noble and Resolute, including
   source disablement/restoration, safe PHP rebuilding, database-major protection,
   configuration preservation, and failure recovery. The existing private
   DistUpgrade APIs are not assumed compatible with Resolute.
3. Durable service launcher, configuration backup and rollback/recovery procedure,
   retained logs, and concrete FPM/socket/Nginx/application/kernel health probes.
4. Disposable VM upgrades through **both** hops, rebooting each time, with actual
   PHP/Nginx applications and injected failure/interruption cases.
5. Versioned bundle/manifest integration and a reviewed pinned Forge deployment
   recipe. Do not reuse legacy release approvals for this new stage.

Run offline tests:

```sh
python3 -m unittest -v test_fleet_os_stage.py
python3 verify_release.py
```

These tests use a fake backend and temporary checkpoint files. They do not prove
package availability, native upgrade compatibility, service health or fleet
readiness. No packages, production hosts or reboots are involved.
