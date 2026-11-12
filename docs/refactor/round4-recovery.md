# Independent recovery and computation exit evidence

The opt-in `internal/jobs/integration/cmd/m4-recovery` Go process scans PostgreSQL
without HTTP or new claims. It runs immediately and every second, with a 10 second
per-pass database timeout. Existing application defaults are unchanged. Apply all
three numbered jobs migrations before starting either opt-in service. Python
Worker/Core never receive the recovery daemon's database connection string.

An expired running lease is independently changed to queued (attempts remain) or
failed (limit exhausted), records a check timestamp and reason, and clears the
lease. Existing attempt/token/state/lease comparisons fence heartbeat, failure,
completion and publication after recovery. Concurrent daemons use conditional
updates; stale cancellation proof cannot overwrite a newer attempt.

Running cancellation records a database-time recovery deadline five seconds from
request. After the deadline, the independent pass reads the exact attempt's
`jobs/<id>/attempt-<n>.worker/exit.json`. The guardian atomically replaces this file
only after waiting for its direct child, terminating the computation group, and
checking that no computing group member remains. Linux ignores dead zombie
entries; other platforms conservatively require group absence. It includes job,
attempt, worker, secret attempt token, child and guardian identity, and explicit
group exit confirmation. The API also requires this evidence before ACK. Partial,
missing, stale or mismatching proof leaves cancellation pending with a persistent
reason and last-check timestamp. A completely absent guardian never yields an
invented cancellation. The deadline is a time to inspect, not an exit guarantee.

The verifier never sends signals to marker PIDs and does not look up a remote
Worker's PID on the recovery host, avoiding PID reuse and remote-host confusion.
Only the guardian checks its own group immediately before producing evidence.
The shared control directory and guardian are trusted infrastructure: the marker
is an authenticated attempt receipt, not an OS attestation against a malicious
same-UID process. The supported cancellation receipt scope is the trusted CPAG core and descendants
that remain in its process group. `setsid`/`setpgid` descendants can escape this
scope: a group-empty receipt does NOT establish that arbitrary descendants exited.
The Linux namespace watchdog's separate whole-container lifecycle evidence is NOT
currently bound into the database cancellation receipt. Container placement alone
also does not separate a same-UID core from its guardian control directory.
Do not interpret `cancelled` as an OS-attested termination of arbitrary hostile
code; this implementation's cancellation guarantee applies only to the trusted
core process-group model. Root/path access failures preserve
pending state, as does guardian death before proof publication.

Validation: `scripts/m4/validate-postgres.sh` runs real disposable PostgreSQL,
independent ticker recovery without HTTP or further claims, persists pending
missing/wrong-token proof reasons, then runs the actual guardian subprocess with
parent pipe EOF, checks its bound exit proof, and verifies cancellation plus stale
attempt fencing. It also verifies expired final attempts are discovered with no
claim activity. `scripts/m4/validate-worker.sh` covers existing live HTTP worker
faults and the independent daemon/API-outage scenario.

Final 2026-10-25 evidence: `validation-round4/recovery-postgres.log` (race-enabled
PostgreSQL tests, real guardian EOF, explicit stale Complete rejection after
independent recovery) and `validation-round4/recovery-worker.log` (live API/Core
fault suite, database restart, API outage and Worker SIGKILL). Both scripts exited
zero against their dedicated disposable local databases. These are synthetic
lifecycle/recovery checks, not real industrial protocol or production validation.

Recovery self-review: non-positive library ticker intervals report an error and
return rather than panic. The daemon's interval is fixed at one second; database
operations use a ten-second context per pass, not an unconditional wall-clock
SLA for unavailable network filesystem reads or blocked local kernel I/O. During
database outage the daemon logs failures and retries; it cannot persist check
metadata until PostgreSQL is reachable. Claim's legacy expiry path remains for
compatibility; its row locks and recovery's state/lease-conditional UPDATE prevent
an old recovery scan from fencing a newly leased attempt. Legacy Claim expiry
itself does not populate independent-recovery audit fields. No process-exit
assertion is made when requeuing an expired running attempt; only publication is
fenced. Resource containment for any surviving old computation is separate.

Queued cancellation after an attempt: only a never-claimed queued job (`attempt=0`)
can become `cancelled` immediately. A queued retry (`attempt>0`), whether created
by lease recovery or retryable failure, enters `cancelling` with a five second
deadline and requires its retained attempt/worker/token exit receipt. Its temporary
cancellation lease field satisfies the running/cancelling table invariant and does
not restore heartbeat or publication ownership. `Fail` retains the attempt identity
needed for this evidence. PostgreSQL regression tests verify absent proof remains
pending, bound proof permits cancellation, and predecessor completion is stale.

Remaining historical-attempt limit: the current jobs row holds the latest attempt
identity, not an append-only ledger of every earlier lease. Once another Claim
replaces that identity, a receipt for the latest attempt does not establish exit of
all older expired computations. Full all-attempt termination needs an attempt
ledger or a namespace/cgroup receipt covering every predecessor; neither is claimed
by this round's process-group receipt implementation.

Conservative multi-attempt gate (implemented): `VerifyExit` rejects every
`attempt>1` with `all-attempt exit proof not implemented`. Both HTTP ACK and the
independent recovery daemon use this verifier. Even a correctly bound latest
receipt therefore leaves the database in `cancelling`; recovery persists the
pending reason. This prevents a latest receipt from being represented as evidence
that older computations exited. Multi-attempt jobs cannot automatically reach
`cancelled` in this round and require manual investigation; automated all-attempt
exit confirmation remains an explicit incomplete item, not an acceptance claim.
The latest-receipt rejection is covered by unit and real PostgreSQL tests.
