# M4 opt-in internal Worker API

No default application route or deployment enables this service. Only this Go service receives PostgreSQL credentials. The Python worker uses authenticated HTTP and a controlled shared filesystem; it never receives database credentials. Use a dedicated service account and private shared root, with inputs writable only by the API operator, and do not expose the HTTP listener publicly.

Apply `internal/jobs/migrations/001_jobs.sql` then `002_worker_api.sql` to a dedicated PostgreSQL database. Launch from `internal/jobs/integration`:

```sh
CPAG_ENABLE_M4=1 M4_DATABASE_URL='postgres://...' \
CPAG_SHARED_ROOT=/absolute/private/shared \
CPAG_WORKER_TOKEN='<random secret at least 24 characters>' \
go run ./cmd/m4-job-api
```

The default listener is `127.0.0.1:8094`. `CPAG_JOB_API_ADDR` explicitly overrides it. All requests require `Authorization: Bearer <CPAG_WORKER_TOKEN>`. Request bodies are limited to 64 KiB and reject unknown fields. Inputs are limited to 16 MiB each, artifacts to 64 MiB each, and manifests to 64 KiB. TLS/private transport is required if deliberately using separate hosts. Only synthetic M1 inputs are supported. No request specifies executable code or shell commands.

Place source files under shared-root `inputs/`. `POST /v1/jobs` accepts `id` (ASCII letters/digits/underscore/hyphen), `max_attempts` (1–100), and `payload`:

```json
{"network":{"path":"inputs/network.jsonl","sha256":"<64 lowercase hex>"},"process":{"path":"inputs/process.csv","sha256":"<64 lowercase hex>"},"profile":{"path":"inputs/profile.json","sha256":"<64 lowercase hex>"},"config_fingerprint":"<SHA256 of canonical profile JSON>"}
```

Profile fingerprint uses sorted keys, compact separators and unescaped Unicode, matching the core. M4 currently rejects decimal/exponent JSON numbers, numeric -0, and Unicode line separators in profiles to avoid cross-language numeric canonicalization ambiguity. Enqueue checks bytes and fingerprint and creates exclusively named, mode-0400 input snapshots; the stored payload refers to these snapshots. Conflicting IDs or snapshot names fail instead of overwriting. Failed enqueue may leave orphan snapshots for operator cleanup.

`POST /v1/claim` accepts `worker` and `lease_seconds` (1–3600). It returns HTTP 204 if empty, otherwise `id`, `attempt`, `worker`, a cryptographically random `token`, `payload`, `lease_seconds`, and `output_dir` (`jobs/<id>/attempt-<n>`). The output directory must not exist: core creates it exclusively. The worker has a separate attempt-scoped control directory. Claiming reclaims expired running attempts, and fails exhausted attempts. Database time governs leases.

`GET /v1/jobs/<id>` returns state, attempt, payload and nullable published artifact metadata. `POST /v1/jobs/<id>/cancel` requests cancellation. Queued jobs become cancelled immediately. Running jobs remain cancelling until the owning worker confirms its subprocess has exited; `ack-cancel` is never an administrative assumption that the process is dead.

The following POST operations include `attempt`, `worker`, and `token`:

- `heartbeat`: additionally `lease_seconds`; HTTP 409 contains current `state` (including `cancelling`) when ownership is lost or stopping is requested.
- `fail`: additionally `message`, `retryable`; retries use bounded exponential backoff, up to the job's attempt limit.
- `ack-cancel`: only after the child process group exits.
- `complete`: additionally `manifest_sha256`.

Completion reads `output_dir/manifest.json`, whose fields are `config_fingerprint`, `inputs` mapping role to SHA256, and `artifacts` entries `{path,sha256,size}`. Paths must be single filenames. The expected core files are dataset.json, events.json, graph.json, quality.json and run_manifest.json. The server checks source snapshots, canonical configuration fingerprint, input fingerprint, core synthetic flag and success status, core artifact hashes/sizes against wrapper entries, and actual bytes/sizes. Symlink paths are rejected. Before filesystem publication it verifies attempt ownership, then publishes an exclusively created content-addressed manifest and uses a fenced SQL update. A retry can verify/reuse that same file; an already successful identical authenticated completion is idempotent. A crash between filesystem and database operations can leave an orphan content-addressed manifest; database metadata alone identifies the published attempt.

The shared root is a trust boundary: mode bits are defense in depth, not protection against another process running as the same filesystem owner. Use isolated service identities/permissions and retention controls for published files. API reads verify bytes at completion; consuming a published artifact must also verify its recorded checksum. Cancellation of an unreachable worker remains cancelling until a worker/operator independently proves the process exited; there is no unsafe automatic cancellation acknowledgement.

The input snapshot and newly published manifest bytes are file-synced before closing. The manifest bytes are hashed again after the final read and before creating its content-addressed copy. This does not make filesystem publication and the PostgreSQL commit one transaction; directory fsync, power-loss behavior and orphan reconciliation still require separate acceptance. The complete endpoint rechecks persisted files on identical successful retries rather than treating task status alone as integrity proof. Cancel returns the actual resulting state, including already terminal jobs.

Independent recovery additionally requires `003_recovery.sql`. Run a separate
`go run ./cmd/m4-recovery` from `internal/jobs/integration` with `CPAG_ENABLE_M4=1`,
`M4_DATABASE_URL` and `CPAG_SHARED_ROOT`. This Go service intentionally has direct
PostgreSQL access and continues when the HTTP API is down; Python workers and core
receive no database credentials. Recovery checks immediately and every second.
Cancellation has a five second recovery deadline; reaching it starts evidence
inspection, not a claim of process exit. Status exposes `recovery_deadline`,
`recovery_checked_at`, and `recovery_reason`. A missing guardian or inaccessible
remote/shared root leaves `cancelling` with a pending reason until evidence exists.

Receipt trust scope: `cancelled` assumes the trusted CPAG core keeps descendants
in the guardian's process group. Escaped `setsid`/`setpgid` descendants and hostile
same-UID core behavior are outside this receipt guarantee. Linux namespace cleanup
is separately tested but its evidence is not yet bound into cancellation receipts.
Only never-claimed queued jobs cancel immediately. A queued job with a prior
attempt requires that attempt's exit proof and stays `cancelling` if unavailable.
The current single-row identity does not attest all older overwritten attempts;
see the historical-attempt limit in `docs/refactor/round4-recovery.md`.
Conservative gate: attempt numbers greater than one cannot automatically become
`cancelled`, even with a valid latest exit receipt. HTTP ACK rejects that proof;
independent recovery retains `cancelling` with an all-attempt-proof pending reason.
All-attempt exit confirmation is not implemented and needs manual investigation.
