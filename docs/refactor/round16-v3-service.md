# Round 16 unified local service

This is an explicit new entry. The existing `cmd/cpagx` and V1/V2 deployments keep their previous startup and behavior. V3 accepts datasets and immutable inputs; it runs the existing synthetic dual-source core through the M4 queue. Real files receive metadata and integrity preflight only. A report marked ready for manual review is not proof of authorization, clock alignment, correct parsing, or industrial validity.

## Configuration and startup

Apply `internal/jobs/migrations/001_jobs.sql` through `007_v3_preflight_snapshots.sql` in numeric order to the dedicated PostgreSQL database. Use a private shared root and a separate private control root. The v3 process starts two different loopback listeners: public UI/API and internal M4 Worker/coordinator. Do not publish the internal listener or forward its Bearer credentials to the browser.

Create a JSON file with permissions `0600`:

```json
{
  "database_url": "postgres://USER:PASSWORD@127.0.0.1:5432/cpag?sslmode=disable",
  "shared_root": "/absolute/private/cpag/shared",
  "control_root": "/absolute/private/cpag/control",
  "public_addr": "127.0.0.1:8095",
  "internal_addr": "127.0.0.1:8094",
  "worker_token": "REPLACE_WITH_A_DISTINCT_RANDOM_SECRET_OF_AT_LEAST_24_CHARACTERS",
  "coordinator_token": "REPLACE_WITH_ANOTHER_DISTINCT_RANDOM_SECRET_OF_AT_LEAST_24_CHARACTERS",
  "bootstrap_admin_username": "admin",
  "bootstrap_admin_password": "REPLACE_WITH_A_LONG_INITIAL_PASSWORD",
  "static_root": "/absolute/path/to/cpagx-go/webui/out",
  "python_bin": "/absolute/path/to/python",
  "python_path": "/absolute/path/to/cpagx-go/services/analysis/src"
}
```

`go -C internal/jobs/integration run ./cmd/cpagx-v3 --config /absolute/private/cpag/v3.json` starts the service. `CPAG_V3_CONFIG` is an alternative for the config **path only**; application values come from the JSON file. If omitted, public and internal addresses default to `127.0.0.1:8095` and `127.0.0.1:8094`, and `python_bin` defaults to `python3`. `static_root` may be omitted in API-only tests. No LAN mode is supported here; LAN access requires a separately specified and validated TLS deployment. The existing Python Worker points to `http://127.0.0.1:8094` and uses the two internal tokens from a separate mode-0600 worker configuration. The public API never returns them.

The initial administrator is created only if `v3_users` is empty. The service stores a bcrypt password hash in PostgreSQL. Users log in with `POST /api/v3/session`; the browser receives a 12-hour `HttpOnly`, `SameSite=Strict` cookie. Logout revokes the server-side session. Restoring a backup revokes all restored sessions, so users log in again. Only administrators create users or grant dataset access. Analysts may create datasets and operate their own or explicitly granted datasets. Viewers may only read explicitly granted datasets, runs, evidence, and downloads. Every v3 read of a run first resolves the run's dataset binding and checks ACL.

## Current source and execution limits

Upload uses a known `Content-Length`, streamed temporary file, SHA-256 check, and immutable random storage path. The current intake limit is 64 MiB per PCAP/PCAPNG and 8 MiB per process CSV/XLS/XLSX. The **current runnable M4 dual core** is narrower: one PCAP/PCAPNG, one CSV, 16 MiB per input, 2 MiB process CSV, 64 KiB profile, 1000 logical process records, and explicit synthetic profile. Intake acceptance does not imply runnable format support. Duplicate `Idempotency-Key` with identical role, filename, bytes and size returns the original file; a different upload returns 409. An interrupted or mismatched upload leaves no catalog row.

`POST /api/v3/datasets/{id}/configs` creates `intake` or `dual` versions. The original JSON bytes, SHA-256, and canonical fingerprint are retained; updating a configuration creates a new row. The intake version supplies declared authorization/time/mapping fields to the existing `cpag_core.intake` metadata preflight. A dual version can be stored with missing clock basis to document the gap; run submission then returns 422. A runnable synthetic dual profile requires at least one mapping and nonempty network and process clock basis, offset and uncertainty. Real datasets cannot submit dual-source runs in this round. `POST /api/v3/runs` inserts its exact file/config references and the existing `m4_jobs` payload in one PostgreSQL transaction; it does not create another job state machine.

Preflight retains the core report and an immutable snapshot of its exact file IDs, paths, hashes, dataset provenance, intake config and manifest. The SHA-256 in PostgreSQL covers the exact UTF-8 snapshot JSON bytes. Later uploads do not alter an earlier report's input set. If its dataset identity conflicts with the catalog batch, the API returns 409 `batch_conflict` with the report and records that outcome in audit. Missing declared metadata remains a 200 report with explicit gaps, while a missing or modified stored original returns 409 `source_changed`.

New dual runs require `preflight_id` alongside `dataset_id`, dual `config_version_id` and `mode`. The service checks that this is a fresh native, ready dual-source preflight with no errors or material gaps and that its frozen file identities, hashes, dataset provenance and intake config still match the current selected inputs. It reruns the existing intake core against the frozen manifest and compares the retained report, so an edited ready/gaps field cannot authorize a run. A stale selection or altered report returns 409 `preflight_stale`; gaps return 422 `preflight_incomplete`; a batch conflict returns 409 `batch_conflict`. Rejected submissions leave no M4 job or run binding and record a specific gate audit outcome. A dual profile still requires actual nonempty mappings and clock basis/offset/uncertainty. Illegal `source_kind` at dataset creation returns 400 `invalid_source_kind`.

Migration 007 preserves pre-existing reports and runs as `pending_legacy` / `legacy_unbound`. During maintenance stop, run `go -C internal/jobs/integration run ./cmd/cpagx-v3 --config /absolute/private/cpag/v3.json --backfill-legacy` once. This reconstructs old preflight selections using source files whose catalog creation time is no later than each report, reruns the existing intake core, and stores a `reconstructed` snapshot only on an exact report match. A failed reconstruction retains the report with an `unreconstructable` reason and blocks a trusted complete backup. An old run is associated with a reconstructed report only when exactly one earlier ready report matches its two file identities; that association is labeled `reconstructed_match`, not as evidence that the old runtime enforced the new gate. Unbound old runs remain explicit and also block trusted complete backup. Ordinary startup never rewrites these historical rows.

Published result, graph, evidence and artifact routes reuse M4 verification. Downloads use object IDs or the verified manifest inventory, never a caller-supplied filesystem path. The API contract and error envelope are in [v3.yaml](../../api/openapi/v3.yaml). A CLI should call these same routes and observe the same states and errors.

This round does not claim the R17 target capacity, real dual analysis, or a validated LAN/TLS deployment.

Normal Worker/CLI startup and the complete independent acceptance command are documented in [operations](round16-operations-20261027.md).
