# Round 5 opt-in isolated executor

The default Worker and default deployment remain unchanged. This executor is an explicitly enabled host coordinator with a compute-only Linux Docker container per attempt. All tests use synthetic software inputs.

## Run and dependencies

The integration command from repository root is:

```sh
bash scripts/m4/isolated/validate-isolated.sh
```

Dependencies: Python 3 standard library, Go toolchain/module downloads, Docker Linux daemon and Compose plugin. The Dockerfile fetches `mirror.gcr.io/library/python:3.12-alpine`. No macOS paths are hard-coded; repository and temporary locations are derived at runtime. Ports 55451/18115 and Compose project `cpag-m5-isolated` are disposable test resources. The script retains the printed temporary workspace for inspection; its tokens stay in host environment/control files and are omitted from repository evidence.

For explicit host use, build `deployments/isolated-executor/Dockerfile` as `cpag-isolated:round5`; supply `CPAG_API_URL`, `CPAG_WORKER_TOKEN`, separate `CPAG_COORDINATOR_TOKEN`, `CPAG_SHARED_ROOT`, and `CPAG_CONTROL_ROOT`. Control root must be outside shared root. Launch:

```sh
PYTHONPATH=services/worker:services/analysis/src python3 -m cpag_worker.isolated --enable-isolated-executor
PYTHONPATH=services/worker:services/analysis/src python3 -m cpag_worker.isolated --enable-isolated-executor --recover
```

Recovery scans known host job directories. If an entire local job directory was lost, supply `--recover --recover-job JOB_ID` to retrieve its authoritative attempt history using coordinator authorization and reconstruct execution records. There is deliberately no assumption that absence of a container means it exited safely.

## Authority and execution boundary

The host holds all API credentials, execution registration, handoff and exit receipts. Compute gets exactly a read-only staged input directory at `/inputs`, read-only root filesystem, no network, no control mount or Docker socket, UID 65532, no capabilities/no-new-privileges, 256 MiB memory and swap cap, 0.5 CPU, 64 PIDs, bounded local log rotation, 1 MiB runtime tmpfs, and a 16 MiB aggregate output tmpfs. Input suffixes are preserved. Packet jobs select `cpag_core.packet_job`; legacy jobs select `cpag_core`.

The host creates the container without starting it, atomically fsyncs its immutable full ID/daemon ID/attempt identity locally, registers it in the database, then starts it. Compute PID 1 has an independent wall deadline and holds tmpfs output available after the calculation finishes. A host controller hard-exit cannot remove that wall bound.

Stop proof requires exact Docker ID and job/attempt/worker labels, stop/wait, an actual stopped inspect (`Running=false`, `Pid=0`), and successful Docker removal. Only then does the host atomically persist and submit `removed:true` evidence. Removal prevents a controller paused before `docker start` from subsequently starting the old container. A missing container without a persisted trusted removal proof stays pending. A crash after removal but before durable proof can therefore require manual evidence reconciliation; it never fabricates exit.

## Durable handoff and recovery

Output transfer is a tar stream from bounded tmpfs while the container still exists. The host caps captured archive bytes and transfer time (30 seconds), rejects links, nested paths, duplicates and unexpected files, checks standard contracts, exact artifact membership, manifest SHA-256/size and configuration identity. Packet output is fully re-decoded against the original host-controlled capture with `packet_job.verify_artifacts`; merely rehashing forged decoded fields cannot pass.

A separate heartbeat thread maintains the lease during transfer and fsync. Host staging is a private sibling directory on the destination filesystem. Every file and directory is fsynced. Only after container removal proof is persisted/accepted does an exclusive publication lock reserve the attempt namespace, and a directory rename publishes the complete output atomically. Existing attempt output is never replaced. The API then independently validates the publication and writes its content-addressed manifest before `complete`. Files become read-only; the directory becomes read-only after the API adds its manifest. Partial staging directories never qualify as published output.

A durable `handoff.json` binds output directory to manifest digest. After a crash following rename, recovery validates all handoff hashes plus removed-container proof and packet re-decoding before an idempotent `complete`. Database ownership/lease fencing still applies. Recovery reads `lease_valid` without renewing leases; it skips active computations, stops stale/cancelling executions, reconstructs lost records from authoritative attempt history, and leaves missing evidence pending. The independent Go recovery daemon consumes external receipts and finalizes cancellation only when every historical attempt is proved removed.

## Evidence and limits

`validation-round5/isolated-integration.log` records the actual Docker/PostgreSQL/Go API run. `isolated-exit-evidence.json` contains token-redacted real inspect/removal receipts. The temporary workspace retains detailed stopped Docker inspections, host execution records, partial staging and test publication files.

The integration covers packet publication, forged-and-rehashed packet semantics, legacy publication and repeated completion, actual cancellation, actual compute output tmpfs ENOSPC, simulated host durable-handoff ENOSPC injection with partial staging cleanup, calculation failure, hard host exits before start/during execution/during file transfer/after copy/after publication, the registration/start cancellation race, two historical attempts with an expired dead controller, repeated read-only recovery scans, lost local execution identity reconstruction, API restart, independent Go recovery restart, and old-attempt completion fencing.

These checks do not validate industrial data, real protocol completeness, physical process safety, hostile Docker daemon/root administrator behavior, kernel isolation escapes, host power-loss durability or production deployment. Docker daemon evidence is trusted. Shared host durable storage capacity and retention need operational quotas; the compute tmpfs limit does not impose a host artifact-store quota. Publication files/receipts are host-only authority; a lost proof is conservatively pending. Default execution is not switched to this prototype.

Host durable-store ENOSPC is injected as an explicit OSError at the first copied/fsynced handoff file; this does not fill the user disk and is distinct from the actual compute tmpfs-full case. Both must leave the job non-successful with no published attempt directory. The simulated handoff failure cleans its partial staging directory after stopping/removing the calculation container. It does not establish a host artifact-store capacity quota.
