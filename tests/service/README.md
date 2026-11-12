# Synthetic service regressions

Run from the repository root after installing the service's FastAPI/Celery/Redis dependencies plus `httpx==0.27.2`:

```sh
.venv/bin/python -m unittest discover -s tests/service -v
```

These tests exercise actual FastAPI routing, multipart validation, filesystem task status, the same standalone M1 core, exported artifacts, and downloads. Broker submission and Redis admission are mocked. They do **not** establish RabbitMQ delivery, worker execution, proxy/browser behavior, or full stack availability; the separate live smoke covers those paths.

Synthetic submission is opt-in per request: `POST /cpag/synthetic`, multipart `network_file` (`.jsonl`), `process_file` (`.csv`), `profile_file` (`.json`), and `synthetic_confirmed=true`. Profile must additionally declare `synthetic=true`. Files are capped at 16 MiB each. The worker accepts only a generated UUID, resolves files under its configured upload directory, and calls `cpag_core.pipeline.run(..., synthetic=True)` without an evaluation or label input.

HTTP and worker must share absolute `OUTPUT_DIR` and `UPLOAD_DIR`, broker and Redis settings, repository core sources, and the `cpag_generation` queue. Files publish only after core checksums verify; status and task listing persist independently of Redis cache expiry. Status `completed` retains `core_status=succeeded_with_warnings` and the original warnings in the task manifest, available through status/artifact endpoints. Core outputs retain synthetic flags and limitations.

Redis slot admission is atomic and fail-closed. Capacity rejection fails the task explicitly; it does not silently bypass capacity or automatically wait/retry. Slot expiry bounds stale capacity after a worker crash, but this remains a shared set TTL rather than the planned durable per-task lease system. Concurrent HTTP tasks have exclusive UUID input and output directories.

Completed synthetic deliveries are idempotent only after the run-manifest digest and every artifact checksum/size verify. A checksum mismatch raises without changing the completed task manifest. Duplicate active deliveries are ignored without changing the original delivery's task status, input files, or capacity slot. Crash recovery while processing remains limited: an abandoned partial core output is not automatically resumed; a new task is needed after failure/stale-slot expiry.

Once worker admission succeeds, original network JSONL, process CSV, and profile are retained exclusively under `<task>/sources/` with read-only file/directory permissions and recorded SHA-256/byte sizes. The core reads those retained files, so dataset fingerprints and event source references remain resolvable after staging cleanup. Sources survive core success and failure, and completed duplicate checks verify their checksums. They are excluded from the public artifact-download allowlist. File-owner/administrator permission changes can still modify local evidence; this is not WORM storage. Admission/queue rejection happens before source retention.
