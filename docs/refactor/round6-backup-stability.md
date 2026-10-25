# Round 6 — backup/restore stability, verified scope

Baseline: `2f08784`. Scope is `scripts/backup`, `tests/backup` and this report;
protocol, UI/replay, isolated execution and Go behavior are not changed here.
All sources/tasks below are synthetic. No production backup/recovery acceptance.

## Reproduced before changing the affected logic

Evidence: `validation-round6/backup-before.json`.

- `audit([], missing_directory)` returned `valid: true`; a missing tree looked
  like an empty inventory.
- A failed terminal task with `payload: {}` returned `valid: true`, omitting all
  mandatory input references.
- One malformed job payload (string), or one malformed attempt (`null`), raised
  `AttributeError` and aborted auditing later entries instead of recording that
  item's error.

Evidence: `backup-before-concurrent-restore.json`. Two real Python threads and
real filesystem operations, with database calls explicitly mocked, demonstrated
that a second invocation could pass the initial existence checks while the first
was running. The first returned success, then the second's createdb failure
replaced the same report with `valid: false`. This was a report terminal-state
race, not a demonstrated overwrite of an existing PostgreSQL database.

Evidence: `backup-before-file-database-race.json`. Database snapshot/dump calls
were mocked, and a real source input was changed between the first reference
audit and the inventory used for copying. Source/destination inventories then
agreed on the new bytes, so backup returned success while auditing its copied
files against its own saved job rows failed. The original shared DB lock cannot
freeze source filesystem writes.

## Fixes

Inventory now traverses with `scandir`, rejecting a missing root, symlink,
nonregular entry, disappeared path or unreadable subtree. It does not silently
skip a failed traversal. File-tree failure is recorded with
`inventory_complete: false`; it cannot produce a valid empty result.

Audits require an object job payload and all three mandatory network/process/
profile references for every terminal state. Malformed jobs and history items
produce per-item errors while later items are still checked. A report includes
per-job outcomes and a verified-attempt count, so a failed item cannot hide the
remaining batch. Duplicate identities and malformed attempt counts are rejected.

Restore atomically reserves its own private report with exclusive creation before
any DB mutation. A concurrent or repeated invocation cannot take ownership of or
replace that report. Final reports use a temporary file, flush/fsync and atomic
replacement. On copy failure, DB/file mismatch or capacity failure, success is
not written. If even the failure update cannot be written, the reserved report
remains invalid and the original operation raises. Existing target DB/directory
and partial restores remain protected/retained for inspection.

Backup now re-audits the copied references against the exported task rows, and
rechecks both source/destination inventories after the DB dump. A change in the
first-audit→copy interval or during the dump cannot publish a valid bundle marker.
`bundle.json` is written atomically only after these checks; partial backup failures
retain `backup-failure.json` when storage permits, and do not publish a valid bundle.

## Verification

`backup-tests.log`: **20 unit tests passed**. They include malformed-first/valid-
later batches, missing/unreadable trees, repeated and concurrent restore report
ownership, changed database metadata, copied artifact truncation, mutation before
copy inventory and during the dump, and injected `ENOSPC` during backup/restore and
failure-report writing. Capacity tests are deterministic exception injection;
this does not claim that a real host disk was filled or that power-loss behavior
was exercised. Existing raw packet/source/hash/field tampering tests also pass.

`backup-after.json` repeats the initial malformed/missing-input cases: each now
returns `valid: false` with an inspectable error, without an unhandled batch abort.

`backup-integration.log` and `backup-integration-summary.json`: **independent real
Docker PostgreSQL + host worker/API integration passed**, with dedicated PG 55443
and API 18098. It applies all current migrations, including `005_exit_diagnostics`.
Both jobs and complete attempt rows use `row_to_json` snapshots; restoration
compares every column, preserving exit diagnostics without interpreting missing
proof as an exit. The frozen 005 schema also preserves `executor_kind` and
`start_revoked_at`. The integration actually claims an isolated-v2 task, cancels
it, records the coordinator's not-started proof and acknowledges cancellation
before taking the snapshot. Audit accepts this proof only for isolated-v2 with a
nonempty revoked timestamp, empty container ID, `start_revoked: true` and exact
identity/location. A later identity-bound inspected/removed-container cleanup
receipt may retain revocation, including cleanup of an unregistered legacy orphan;
a revoked attempt can never be audited as published. Dump, files, inputs, published artifacts and evidence references
are audited as a set in a fresh `m4_restore_validation` database and fresh directory.

The restored API reads legacy success/failure/cancellation and packet success, plus a real isolated-v2 never-started cancellation;
the restored packet query verifies original field bytes. Missing/tampered capture
and publication files remain rejected, and orphans remain retained. Further real
integration checks:

- `backup-repeat-restore-audit.json`: repeat to the same destination preserves the
  terminal report; repeat to a new directory refuses the existing target DB;
  saved target DB rows remain identical. The expected createdb refusal appears in
  the log; the overall validation exits successfully.
- `backup-mixed-batch-audit.json`: an injected malformed task is reported invalid,
  while all five real restored tasks are still audited valid.
- `backup-mixed-history-audit.json`: an injected malformed history item is reported,
  while all four real attempt rows are still verified.

Run from repository root:

```sh
.venv/bin/python -m unittest discover -s tests/backup -v
.venv/bin/python scripts/backup/validate.py
```

The integration runner defaults to `validation-round6`; set
`CPAG_BACKUP_REPORT_DIR` to choose another report directory. It cleans only its
own disposable container/volume and temporary bundles. Saved reports contain no
actual worker/attempt tokens, full task rows or database dump.

## Not established by this round

There was no reproduced silent-success case for an actual full host filesystem,
PostgreSQL power loss, corrupted WAL, cross-version restore, or active production
multi-table application writes. Those remain outside the test boundary. The
utility handles terminal synthetic M4 tasks, not resumption of nonterminal work.
PostgreSQL/file checks are not an OS snapshot or an authenticity signature; they
check the captured content/metadata set. Backup/restore never automatically deletes
an invalid or preexisting target to make a later run pass.
