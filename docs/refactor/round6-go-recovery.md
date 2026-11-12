# Round 6 Go recovery stability

Baseline: `2f08784`. Default application routes remain unchanged. Scope is the
opt-in job API/repository, coordinator discovery, and historical receipt recovery.
No protocol, UI or replay feature is added here.

## Reproduced defect and correction

The baseline ACK statement accepted only `state='cancelling'`. After successful
cancellation (or independent recovery completing it), the identical authenticated
ACK affected zero rows and returned `ErrStale`/HTTP409. A lost success response
therefore looked like failure on retry. `TestHistoricalContainerCancellation`
replays this exact baseline SQL against real PostgreSQL through a minimal HTTP
adapter and records HTTP409. This is an exact SQL/HTTP guard reproduction, not a
claim that the entire old application binary was launched.

ACK now accepts an already-cancelled job only with the same current job/attempt/
worker/token and complete historical exit evidence. Identical retries return200;
wrong identity and older attempt identity still return409. The operation does not
allow publication or change a different terminal result.

## Single-machine discovery and registration-window convergence

`GET /v1/executions?location=docker:<daemon-id>` requires the separate coordinator
bearer. It reads persisted history without renewing leases and returns exact
same-daemon registered executions needing exit cleanup, plus current running
unpublished attempts with a prior exit receipt. Each item contains private
identity/token, execution location/container ID, exit time, current job attempt,
state and read-only lease validity. Worker bearer is rejected; other-daemon
records are not returned. Location is opaque after its docker prefix and may
include the host shared/control scope hash; matching is exact. The host coordinator can rebuild its work list after
losing local execution records or being restarted.

`/execution` still requires a fresh running claim. A successful response remains
an authorization prerequisite for start. Recovery cannot turn a stale registration
into such an authorization.

A trusted coordinator may instead submit a complete `/exit` removed-container
receipt for an otherwise empty execution binding in persisted attempt history.
The single conditional database update binds the immutable full ID/location and
marks exit together. This also works after cancellation or lease expiry. The
receipt must carry the matching historical secret identity, inspected ID, exact
labels, explicit `Running=false`, PID0 and `removed=true`; the host must have
actually inspected and removed that immutable container. Missing-container
observation alone is insufficient. An existing binding can never be replaced.
A retired binding cannot later pass registration/start or stale publication.
This closes the create/register window when the host has durable intent/nonce
proof that identifies the created container; host intent reconciliation is tested
by the isolated-executor work, not implemented by Go guessing a Docker identity.

## Lost isolated claims and the start gate

New isolated claims explicitly send `executor:"isolated-v2"` and their scoped
Docker `location`. The claim and history executor/location update commit in one
transaction before the response. Zero affected history rows roll back the entire
claim rather than return an executable identity; a real trigger-suppression test
checks this exceptional path. Thus a lost claim response, or capacity rejection
before any create intent, remains discoverable by the coordinator.

Coordinator-only `POST /v1/jobs/<id>/not-started` accepts
`{attempt,worker,token,location}` only for an isolated-v2 history row with no bound
container. It atomically sets `start_revoked_at`, `exited_at` and a receipt
`{id,attempt,worker,token,location,scope:"not-started",start_revoked:true}`. This is
proof of a closed execution-registration gate, not an inference from absent PIDs
or containers. Legacy claims cannot use it. Registration and revocation serialize
on the job row: registration winning requires real container cleanup evidence;
revocation winning permanently prevents registration, lease renewal and publication.
All exit and final publication paths use the same job-lock ordering to avoid
cross-table cancellation/publication races.

A valid removed-container receipt can later enrich a revoked record with its
actual cleaned-up container identity while preserving the closed gate. An isolated
attempt that has not registered a container cannot publish even before revocation.
Retiring any previously unbound execution through a removed receipt also closes
its start/publication gate; cleanup alone never creates publication authority.
This lets cancellation/retry of newly gated never-started attempts converge safely
without manual exit invention. Old legacy claims lacking this initial mode
attestation retain their conservative missing-evidence behavior.

## Per-attempt invalid evidence versus shared dependency failure

Apply additive `005_exit_diagnostics.sql` after migration004; it includes
executor kind/start revocation as well as exit diagnostics. History now retains
`exit_checked_at` and `exit_error` for missing or semantically invalid receipts;
public status shows these diagnostics without exposing attempt tokens. A valid
recorded receipt clears the error. Pending cancellation lists the missing attempt
numbers and available per-attempt reasons.

Semantic invalidity or a stale receipt remains an isolated pending item. Actual
PostgreSQL write/query failure from `RecordExit` aborts and reports the recovery
pass; it is no longer silently swallowed by a per-item `continue`. The shared
receipt root is probed first when receipts remain outstanding; its unavailability
is a shared dependency failure. Once that root is available, per-attempt path
failures such as EACCES or a self-referential symlink (ELOOP) are diagnosed locally
and do not prevent later valid receipts from importing. Already-proven terminal
ACK retries do not depend on reopening receipt storage.
A PostgreSQL trigger raising a real server-side error during receipt recording
reproduces this distinction; removal of the fixture permits the same valid receipt
to recover. The daemon reports shared outages and retries future passes.

## Actual validation and limits

* `validation-round6/history-postgres.log`: disposable real PostgreSQL and race
  detection; baseline SQL ACK409 reproduction, fixed ACK retries and wrong-token
  rejection, coordinator discovery authorization/location isolation/no lease
  renewal, removed unregistered execution retirement, different-ID rejection,
  historical cancellation/Claim races, publication fencing, migration preservation,
  per-item invalid proof diagnostics, real ELOOP isolation, server-side database-write
  failure, discarded claim responses, register/revoke races and zero-row history
  rollback.
* `validation-round6/database-outage.log`: `scripts/m4/validate-round6-recovery.sh`
  actually stops PostgreSQL, starts the independent Go OS process while no API is
  running, observes connection-refused failure logging, restarts PostgreSQL and
  observes the same process fence the expired attempt. It then stops that Go process, inserts another expired job, and starts a new
  recovery OS process which must actively fence the new job while preserving the
  earlier failed/fenced history. Dedicated
  compose project/port/volume are disposed afterwards. This is real dependency
  outage recovery, not a mocked repository failure.
* `validation-round6/legacy-worker-api-outage.log`: existing real HTTP/Worker/core
  suite including actual API process termination, Worker SIGKILL, independent
  recovery and database restart, rerun with the new schema and ACK behavior.

The coordinator and host-only receipt storage remain trusted. Go validates the
submitted inspect/removal evidence and persisted identity; it does not possess a
Docker socket or independently inspect Docker. Legacy trusted-core process-group
proof retains its existing limited scope. A missing host intent/removal journal
still remains pending rather than inventing exit. Database contexts have a
10-second per-pass deadline; blocked kernel filesystem I/O is not guaranteed to
respect that deadline. All validation is synthetic software behavior, not an
industrial or production acceptance result.
