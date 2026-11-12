# Round 4 — disposable synthetic backup and restore

Baseline 06984b8; this is an explicit validation utility, not production backup
acceptance or a disaster-recovery SLA. No default deployment is changed.

## Bundle behavior

`scripts/backup/bundle.py` only permits source database `m4_validation` and restore
target `m4_restore_validation`. Backup requires terminal tasks, holds a PostgreSQL
SHARE lock on m4_jobs, exports a transaction snapshot and gives that snapshot to
pg_dump. Writers are blocked while metadata and shared files are copied. Source
and destination inventories are hashed before/after copying; the dump hash,
complete file inventory and exact task rows are recorded in `bundle.json`.
The new bundle directory is private (0700). Bundles include worker control files
and task credentials and must be handled as private operational material.

Restore verifies dump/file integrity and evidence references **before** creating
the target DB. `createdb` refuses an existing database. A new file directory and
new audit-report path are mandatory; existing targets are never replaced. After
pg_restore, exact task rows, inventory and publication/evidence chains are audited
again. Failure reports record their phase; partial destinations/DBs are retained
for inspection. The utility never silently removes a failed restore.

Audit covers every input SHA-256, wrapper artifacts and byte sizes, exact core
artifact membership, schemas, profile/config/input/result fingerprints, dataset
roles/sizes, original logical JSONL/CSV records and timestamps, graph event
coverage and node kind/evidence, claim/counterevidence references, edge endpoints,
claim IDs and graph statistics. The logical-record resolver preserves multiline
CSV positions. This utility audits the existing M1 worker artifact shape; it does
not accept the experimental packet sidecar as an M4 worker artifact.

Missing files and changed bytes produce explicit errors. Unreferenced files are
retained and listed (including prior attempt logs/diagnostics/original uploads).
On an invalid task, later refs may not be traversed, so unreferenced lists from a
failed audit are diagnostic candidates, not deletion instructions. Symlinks,
nonregular files and escaping paths are rejected. No archive extraction occurs.
Bundle hash manifests establish internal integrity, not authenticity against an
attacker who can replace the bundle and its hash manifest together.

## Verified local integration

`python3 scripts/backup/validate.py` uses its own Docker PostgreSQL container
`cpag-m4-backup-validation`, port 55443, and host API port 18098. Name/port collisions
fail rather than attaching to an existing environment. A real host worker runs a
successful synthetic task and a malformed-input failed task; a third task is
cancelled while queued. The runner backs up, restores into a **new**
`m4_restore_validation` database plus a new directory, then restarts the API against
that restored pair and reads all three terminal states. It verifies original
record/graph refs, all bytes and all task metadata; injects missing artifact and
immutable-input tampering on separate restored copies; and retains an orphan.
The disposable container/volume and temporary bundles are cleaned up by the test
runner only. No current deployment or other integration container is touched.

Confirmed PASS locally on 2026-10-25. Evidence in `validation-round4/`:
- `backup-integration-summary.json` and `backup-integration.log`
- `backup-restore-audit.json` (valid; metadata/inventory equal)
- `backup-missing-audit.json` and `backup-tamper-audit.json` (invalid as expected)
- `backup-tests.log`: seven passing unit tests, including rehashed forged logical
  record and graph references, traversal/symlink, pre-DB restore rejection and
  a restore-time inventory mismatch which must fail and preserve its report.

Commands:

```sh
python3 -m unittest discover -s tests/backup -v
python3 scripts/backup/validate.py
python3 scripts/backup/bundle.py backup --container CONTAINER --source SHARED_ROOT --destination NEW_BUNDLE
python3 scripts/backup/bundle.py restore --container CONTAINER --source BUNDLE --destination NEW_RESTORED_ROOT
```

Real industrial data, production storage, external/object-store copies, key
management, cross-version PostgreSQL restore, PITR/WAL retention, nonterminal job
resumption and application-wide multi-table snapshots are outside this validation.
The SHARE lock covers m4_jobs only; the current bundle contains terminal M4 tasks.
