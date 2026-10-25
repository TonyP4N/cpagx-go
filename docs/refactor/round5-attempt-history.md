# Fifth-round persistent execution history and recovery

This opt-in change adds migration `004_attempt_history.sql`. `m4_job_attempts`
retains every newly claimed job/attempt/worker/token, claim time, execution location,
immutable container ID, exit receipt/time and publication state/path/digest. A
PostgreSQL trigger writes each claim's history in the same transaction as the
job update, including claims through the existing legacy path. Publication records
are likewise updated transactionally; superseded/non-owning attempts are fenced.
The default application entry point remains unchanged.

Migration preserves existing published job output and copies the latest known
published pointer into history without inventing exit evidence. Earlier attempts
that predate the ledger cannot be reconstructed: status reports each missing or
unproven attempt number, and cancellation remains pending until all required
history is present and exited. This is a data limitation, not an automatic success.

A cancellation serializes against claim on the job row. Only an unclaimed queued
job cancels immediately. Any attempted job enters cancelling. Both ACK and the
independent Go recovery daemon require exit evidence for every attempt 1..N;
a newer receipt alone is insufficient. Old attempts may register their own bound
exit after losing the lease, but never acquire publication rights. A newly leased
attempt and an older recovery sweep cannot override each other's identity.

## External coordinator API

Use distinct secrets: `CPAG_WORKER_TOKEN` for enqueue/claim/heartbeat/complete and
`CPAG_COORDINATOR_TOKEN` for host execution evidence. Set `CPAG_CONTROL_ROOT` to a
host-only directory outside computation mounts; API/recovery read receipts there.
The opt-in runners accept these settings. API does not receive a Docker socket.

* `POST /v1/jobs/<id>/execution`: coordinator bearer; body
  `{attempt,worker,token,location,container_id}`. Location is `docker:<daemon-id>`
  and container ID is the full 64-hex immutable ID. Registration requires the
  current live running claim, is idempotent for that exact execution, and precedes
  container start. Host creates and durably records the non-running container
  identity before registration/start.
* `POST /v1/jobs/<id>/exit`: coordinator bearer; same identity plus `scope:
  "container"`, `exited:true`, `removed:true`, `inspected_id`, `running:false`,
  `pid:0`, and exact `labels` values for `cpag.job`, `cpag.attempt`, `cpag.worker`.
  The trusted host coordinator must actually inspect these values, stop/wait and
  remove the immutable container before reporting. Removal prevents a suspended
  original coordinator from starting a previously stopped container after recovery.
  A missing container without a preexisting durable removal receipt is not proof.
  Matching historical exit registration is accepted and exact retries are idempotent.
* `GET /v1/jobs/<id>/attempts`: coordinator bearer; persistent historical execution
  identities including private tokens, usable after coordinator state loss. Public
  job status omits these tokens and redacts them from exit evidence.

An atomic host receipt may be written to
`<control-root>/jobs/<id>/attempt-N.worker/exit.json` with all exit fields plus `id`.
Independent recovery imports bound receipts for all persisted attempts, including
older attempts while a replacement is running. It then evaluates cancellation.
The API can be unavailable; the Go daemon uses PostgreSQL directly. Python
computation/containers receive no API, coordinator or database credentials.

`GET /v1/jobs/<id>` adds `attempt_history`, `missing_exit_attempts` and a read-only
`lease_valid` calculated with database time. Host recovery uses this without
renewing an orphan's lease. History includes location, container ID, claim/exit
times, redacted evidence, publication state and artifact pointer/digest.

Container completion requires a persisted exit/removal receipt even while its
lease is otherwise valid. Go checks immutable attempt artifact hashes/manifest
and only then atomically marks published metadata. An old receipt never permits
stale completion. Host handoff durability and full protocol re-decoding are separate
checks in the opt-in container coordinator, not inferred from HTTP response alone.

## Compatibility and limits

The default trusted-core process-group guardian remains supported for the existing
legacy worker flow. Its receipt does not attest arbitrary `setsid` descendants or
hostile same-UID code. External container receipts use the separately registered
host-only control path; the legacy fallback is never accepted for a registered
container execution. Coordinator and control storage are trusted infrastructure;
Go verifies the submitted inspect identity/labels but does not independently call
Docker. The coordinator must enforce the inspect/remove sequence.

Recovery runs immediately and each second. Each database pass has a ten-second
context, but that does not impose a kernel-level timeout on blocked filesystem
reads. Database outages are logged and retried; no persisted last-check timestamp
can be written while PostgreSQL is inaccessible.

## Validation evidence

`validation-round5/history-postgres.log` records real disposable PostgreSQL tests
with race detection: lost predecessor/new live attempt, old exit registration,
latest-only pending cancellation, all-attempt cancellation after handler/repository
restart, coordinator authorization, restartable stopped-container rejection,
cancel/retry claim race, missing history, publication removal gate and metadata,
and preexisting published-result migration preservation. Handler reconstruction is
not itself an OS process restart; actual API/coordinator process restart is tested
by the container execution harness separately.

`validation-round5/history-worker.log` preserves the existing legacy live HTTP
worker/core, database restart and actual API outage + Worker SIGKILL checks against
new history. These remain synthetic software lifecycle tests, not industrial-data
validation or production acceptance.

## Packet completion gate

`payload.kind="packet"` preserves immutable network PCAP, process compatibility
placeholder and explicit `synthetic-packet-1` profile. The wrapper must contain
exactly dataset/events/graph/quality/run_manifest/packet_observations; the core
manifest must contain the corresponding five payload files. Legacy kind omitted
continues to require the original five wrapper/four core files.

Go verifies capture file digest, classic PCAP/PCAPNG frame indexing, raw timestamp
references, each frame slice's range/hex/digest and agreement with the assembled
PDU, complete PDU and named-field coverage, and event/node/claim reference links.
Identical retransmission slices may overlap if every referenced byte matches.
Range checks use subtraction to reject integer overflow before slicing. Sidecar
and published events/graph must match. Empty named-field slices, MaxInt ranges
and unrelated event frame references are rejected by direct Go tests.

This Go gate verifies byte/reference consistency, not an independent re-decode of
CIP/Modbus semantics. Full original-capture re-decoding is performed by the Python
packet verification in the host handoff and backup audit. A caller using only the
Go completion API obtains the stated byte-consistency check, not a claim that Go
independently rederived every decoded semantic field.

Conservative create/register window: if the host has only created an unstarted
container when cancellation/lease expiry wins before `/execution` registration,
stale registration is rejected. The host can remove that never-started container,
but its unregistered container ID is not accepted retroactively as exit evidence.
The attempt remains pending/manual investigation. This avoids inventing an
execution binding; automated not-started attestation/registration reconciliation
is not implemented in this round. Containers must never start before successful
registration.
