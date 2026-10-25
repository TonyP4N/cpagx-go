# Round 6 isolated executor stability

Baseline: `2f08784`. Default Worker/deployment remain unchanged. The new behavior is opt-in and synthetic-only. Round 5 evidence is retained separately.

## Recovery failure isolation

Baseline reproduction in `validation-round6/recovery-reproduction.log` shows a corrupt local execution, foreign daemon record, or missing container aborting the whole scan. The revised scanner isolates each job/history row/attempt. Non-object JSON, path traversal, directory/identity mismatch, foreign daemon/scope, missing containers and missing destroy events produce explicit pending reasons; they do not hide later healthy attempts. Job IDs are validated before filesystem/API use, and local record IDs/attempts must match their containing directory.

Whole Docker connection, API/coordinator connection, authentication or database failures return a global retry result. A subsequent scan can resume after the dependency returns; no scan renews leases. A dedicated coordinator-only discovery endpoint identifies this executor's DB attempts without requiring local job files. Location is `docker:<daemon ID>:<hash of resolved shared/control roots>`, with matching container scope labels. Previously known local Round 5 records with the same bare `docker:<daemon ID>` remain recoverable; unknown bare records from other roots are not automatically adopted.

## Creation and removal windows

Before Docker creation the host fsyncs an identity-bound create intent and random nonce. Docker gets a deterministic name and matching managed/execution/scope labels. If creation succeeds but the controller dies before writing execution identity or registering it, discovery combines those labels with authoritative DB attempt identity. It never starts an orphan. The fresh-running registration gate remains required before start, followed by a fresh heartbeat check.

`isolated-v2` claim atomically records executor/location in DB. Coordinator `not-started` revokes an unregistered start gate and records non-start evidence; a later registration cannot reopen it. This covers capacity rejection before create and a lost claim response without inventing a removed-container proof. Legacy claims never gain this inference. If registration won the race, actual Docker stop/removal evidence is still required.

Before removal the host fsyncs stopped inspection and a removal intent with exact container identity, labels and event time. After successful removal it fsyncs the exit receipt. If the controller dies in between, recovery requires the matching real Docker `destroy` event plus the prior stopped inspection before committing the removed receipt. If the event is no longer retained (for example after daemon restart), evidence stays pending. Missing-container status by itself is never accepted as exit. Docker's bounded event retention means this window is reduced, not eliminated under every daemon failure.

## Ownership and storage admission

An exclusive nonblocking per-attempt owner lock precedes input copying and budget mutation. A duplicate controller returns `reconcile_required`; it cannot fail the active attempt or shrink its storage reservation. Terminal API completion with a lost response, or failure writing the local publication marker after accepted completion, similarly preserves handoff evidence and never sends a terminal failure.

Host storage admission uses a shared `flock` ledger for a given control/shared-root pair. Defaults are a 1 GiB executor budget and a 64 MiB minimum free threshold (`CPAG_HOST_BUDGET_BYTES`, `CPAG_MIN_FREE_BYTES`). Reservations include staged input bytes, bounded output and transfer allowance, and metadata. Existing files outside per-attempt namespaces count toward admission. Free capacity is checked on both shared and control filesystems; they may be different filesystems. Active/crashed attempts retain reservations. Only after removal proof and safe partial-stage cleanup may recovery settle to measured retained bytes; an active host owner prevents settlement.

If the capacity ledger disappears while any prior attempt state/input remains, admission fails closed and requires restore/rebuild; absence is not treated as zero usage. Capacity and owner locks protect cooperating executors using the same roots. These are application admission limits, not kernel host-filesystem quotas. External programs, API input ingestion, root administrators, or other control roots can still consume disk. Admission rechecks free space before handoff and filesystem ENOSPC remains a failure, never a successful publication. Retention/deletion policy and operator-led capacity-ledger rebuild are not automated here.

## Commands and exit status

Run independent unit tests:

```sh
PYTHONPATH=services/worker:services/analysis/src python3 -m unittest discover -s tests/isolated -v
```

Run actual isolated Docker/API/PostgreSQL integration, retaining Round 6 output:

```sh
CPAG_VALIDATION_DIR="$PWD/docs/refactor/validation-round6" bash scripts/m4/isolated/validate-isolated.sh
```

The existing prerequisites remain Python standard library, Go, Linux Docker daemon and Compose. The test temporarily pauses only its dedicated PostgreSQL container; Docker outage injection changes the test process's `DOCKER_HOST`, without stopping the user's daemon.

Single-pass recovery exits 0 for a resolved/skipped scan, 2 for individual pending evidence, and 75 for a globally unavailable dependency. Periodic recovery is explicitly enabled with `--recover --recovery-interval 5`; it waits between passes and handles SIGTERM/SIGINT. Ordinary isolated execution exits 0 for success/idle/cancelled, 1 for failed computation, and 75 for infrastructure/ownership reconciliation. This does not enable periodic recovery by default.

## Evidence boundary

`validation-round6/recovery-unit.log`, `isolated-integration.log`, `mixed-recovery-outcomes.json`, token-redacted exit receipts and final multi-attempt DB status record the checks. Actual integration covers original publication/cancellation cases plus create-before-record/register crashes, stopped-before-remove and removed-before-receipt crashes, mixed bad/good attempts, real connection/database interruptions with restored scans, capacity refusal and lost-claim cancellation, old same-control bare-location upgrade, and ambiguous completion outcomes. Storage-budget contention and corrupt/missing ledger cases use controlled local filesystem/unit tests; durable host ENOSPC remains explicitly simulated, while compute tmpfs ENOSPC is actual.

These tests do not establish industrial validation, kernel escape resistance, arbitrary host power-loss safety or production readiness. Docker daemon identity/events and the host coordinator remain trusted authorities.

## Final observed acceptance

The final run passed 28 actual Docker/API/PostgreSQL integration cases and 16 isolated unit tests. Mixed fixture ordering is explicit: `00-missing-*`, `01-corrupt`, `02-foreign` precede the healthy `isolated-after_create-*` attempt. Three consecutive scans each assert those three precise pending reasons appear before the healthy exited outcome; the healthy stop-call counter is cleared and checked on every pass. The saved mixed JSON contains all three scans. A same-job unit regression makes attempt 1 a damaged directory and proves attempt 2 is still rebuilt and handled. A separate periodic CLI regression makes the first pass globally unavailable and the next successful, asserting an intervening wait and exit 0 rather than an early exit 75. The final multi-attempt DB state is cancelled with both attempts exited.
