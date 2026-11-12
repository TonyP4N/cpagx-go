# Round 4: opt-in Linux resource isolation

This validation uses synthetic fault programs, including the actual Python Worker and guardian for lifecycle cases. It is not industrial-data or production validation. Default Compose is unchanged.

## Boundary

Use one Worker `--once` per container, never a shared multi-attempt container. `init.py` is container PID 1 and exits when its Worker exits or the independent wall deadline expires. Linux then terminates every remaining process in the container PID namespace, including a calculation that called `setsid()` and escaped its original process group. Killing both Worker and guardian therefore still ends calculation at container teardown. Process-group cleanup alone does not provide this guarantee.

The container runs as UID/GID 65532, with all capabilities dropped, no privilege escalation, read-only root filesystem, a PID limit, CPU quota, memory plus swap cap, and bounded tmpfs storage. The PID 1 watchdog is separate from Worker/guardian. A stopped container is required before external recovery treats calculation as gone; a missing PID or expired lease is insufficient. Host/daemon failure recovery and durable publication still require the coordinator's evidence protocol.

## Reproduce

From the repository root, with Docker's Linux daemon available:

```sh
python3 scripts/m4/linux-isolation/validate.py
```

The runner builds only the isolated image, starts uniquely named `cpag-r4-*` disposable containers, records full effective Docker limits, final states and fault output in `docs/refactor/validation-round4/linux/results.json`, and removes its own containers. It does not mount host directories or contact an external API. The image uses the public Python Alpine mirror; no privileged container or Docker socket mount is involved.

For a standalone lifecycle demonstration:

```sh
docker compose -p cpag-r4-demo -f deployments/linux-isolation/compose.yml up --build --abort-on-container-exit
docker compose -p cpag-r4-demo -f deployments/linux-isolation/compose.yml down
```

This opt-in Compose runs a synthetic Worker with a short timeout and tmpfs quota. It is an executable isolation recipe, not a production deployment. To adapt it for an API-driven attempt, stage hash-verified inputs into the bounded shared tmpfs before Worker starts, supply the API/token explicitly, replace the probe command with `python -m cpag_worker.worker --enable-m4-worker --once`, and set network access only to the required API. Do not expose the Docker socket or replace tmpfs with an unbounded host mount. Publish validated artifacts to a separately quota-managed durable store before reporting success; tmpfs contents disappear when the container stops. This recipe does not implement that durable artifact transfer.

## Acceptance cases and limits

* Memory probe repeatedly allocates until the 128 MiB cgroup kills it (swap capped at the same value).
* CPU probe spins under a 0.25 CPU quota; the runner measures cgroup CPU usage over a three-second interval and requires between 0.10 and 0.40 cores, allowing startup/scheduling noise.
* Disk probes independently fill 16 MiB runtime and 8 MiB output tmpfs and require ENOSPC. These are aggregate filesystem limits, unlike a per-file rlimit.
* PID probe forks until the cgroup rejects another process with EAGAIN.
* Runtime probe uses the actual Worker timeout and a deliberately detached descendant; container deadline also caps the whole attempt independently.
* Double-kill probe records the calculation, detached descendant, Worker and guardian identities, kills Worker and guardian, and requires container exit 137 with no running container process namespace.

The raw results are the authority for the latest run. These checks cover a single attempt under a functioning Linux Docker daemon. They do not establish industrial protocol correctness, physical process safety, daemon crash durability, host disk quotas, multi-node scheduling or production readiness.

Receipt-integrity limitation: Worker, guardian and calculation currently share a UID. A malicious calculation can read or alter same-UID control files despite mode 0700/0600. Container resource enforcement and namespace teardown do not authenticate such receipts. The results establish cleanup/resource behavior for faulting synthetic calculations, not hostile-core receipt integrity. A production design must separate control ownership/visibility (for example distinct UIDs and inaccessible control storage) and verify container-stop evidence externally.

## Observed run (2026-10-25)

All seven cases passed on Docker Engine 29.1.3 (Linux VM on macOS). Cgroup CPU consumption was 0.24954 cores under the configured 0.25 quota. Memory exited 137; both filesystems returned errno 28; PID exhaustion returned errno 11; CPU wall cutoff exited 124; actual Worker timeout exited 0 after its guardian recorded reason `timeout`; simultaneous Worker/guardian kill exited 137. Every final Docker state had Running=false and Pid=0. This is daemon-observed whole-container stop evidence, not an industrial workload benchmark.
