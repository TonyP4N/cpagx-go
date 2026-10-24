# M4 opt-in HTTP worker validation

The standalone Python standard-library worker lives in `services/worker/cpag_worker`. It calls the Go jobs API using a bearer token; it imports no database client and receives no database credentials. It runs only with an explicit `--enable-m4-worker` flag. Existing analysis routes and deployment defaults do not enable this worker.

Example, using a disposable validation API and shared filesystem:

```sh
export CPAG_API_URL=http://127.0.0.1:8094
export CPAG_SHARED_ROOT=/absolute/disposable/shared-root
export CPAG_WORKER_TOKEN='<same validation secret as API>'
export PYTHONPATH="$PWD/services/worker:$PWD/services/analysis/src"
python3 -m cpag_worker --enable-m4-worker
```

`--once` claims at most one attempt. `CPAG_WORKER_ID` optionally sets identity; the default includes the local PID. The worker has no API-controlled shell/command option. Test-only local constructors can substitute a synthetic fault command.

## Attempt and cancellation behavior

Every claim starts a fresh `python -m cpag_core` process with explicit `--synthetic`. Inputs are checked against the claim's checksums and resolved below the shared root. The core writes artifacts into the attempt-specific path and writes its final manifest after them; this is not a filesystem transaction. A sibling `.worker` directory contains bounded logs, child PID, supervisor configuration (runtime environment only), and observed exit record. Publication builds `manifest.json` from the core's `run_manifest.json`, config fingerprint, input hashes and actual artifact checksums/sizes. The API validates this manifest before accepting completion.

The worker renews its lease while the subprocess runs. Cancellation, stale ownership, API/network failure, or local stop immediately closes the supervisor's parent pipe. An independent supervisor detects EOF, sends TERM and then KILL to the core's entire POSIX process group, waits for the core exit, drains bounded logs, and records the outcome. Only a successful supervisor exit with an exit record permits cancellation acknowledgement. Lost ownership causes no completion/failure/cancellation write. Abnormal supervisor exit or a missing exit record also returns lost ownership with no terminal write because child exit is unconfirmed. Deterministic input/hash/configuration errors, normal nonzero core exit, and HTTP 4xx failures are nonretryable; elapsed timeout, signal termination and HTTP 5xx may retry within the API attempt budget. SIGTERM stops the worker gracefully; SIGKILL also closes the pipe so the supervisor can kill the core independently. Interrupted attempts remain available for API lease expiry/recovery.

Defaults: 120-second elapsed timeout, 60 CPU seconds, 1 GiB address space where effective, 64 MiB per output file, 128 open descriptors, 64 KiB each stdout/stderr. Logs continue draining after the cap, preventing pipe deadlock. Resource limits are applied in the single-threaded child setup before any supervisor threads start. macOS address-space limits are explicitly skipped because they are not supported effectively there. Linux supports `RLIMIT_AS`; these are process limits, not aggregate cgroup/container limits. Run inside a Linux container/cgroup for aggregate memory, CPU, file-count and descendant containment. This prototype requires POSIX signals/process groups and is not supported on Windows.

## Verification

Run the real-process tests:

```sh
PYTHONPATH=services/worker:services/analysis/src python3 -m unittest discover -s tests/worker -v
```

The suite exercises real core output and manifest hashes; real subprocess timeout and bounded log draining; cancelling and stale lease termination; API unavailability termination; graceful worker SIGTERM; worker SIGKILL with independent child cleanup; invalid-input nonretryable classification; and abnormal supervisor exit without a terminal state write. Cancellation ACK is asserted only after the actual child PID disappears. HTTP behavior in the unit suite is a stub; it is not evidence of a database transaction.

With the actual Go API backed by disposable PostgreSQL already running and the three environment variables above set:

```sh
python3 scripts/m4/worker_http_faults.py
```

The live runner uses synthetic checked-in fixtures only and tests actual API/database success with events/graph checksums matching direct core, elapsed timeout, cancellation, SIGKILL and observed child cleanup, real lease expiry followed by attempt-2 recovery, stale completion fencing, and corrupt artifact rejection. Its isolated helper command is created locally by the runner and never accepted through an API request. The queue must be empty at the start; use the disposable validation database. The parent validation report records whether the live runner was actually executed.

## Limits and rollback

A supervisor itself killed alongside the worker cannot perform cleanup; deploy the worker/supervisor under a container or service manager which kills the whole container/cgroup on shutdown. Ordinary worker-only SIGKILL is covered by the independent pipe watchdog. An untrusted core deliberately escaping its process group is outside this synthetic prototype; enforce cgroups before using untrusted plugins. Filesystem quotas and retention are operational requirements: per-file limits and per-stream caps do not bound accumulated attempts. Shared filesystem permissions must restrict input/attempt writes to trusted API/worker principals. No real data is approved by this validation.

Rollback: stop the standalone worker, disable the opt-in API, and leave the existing analysis path active. No production compose switch or database dependency is added to the Python core. Preserve attempt directories for diagnosis before deleting disposable validation storage.

## 本轮实际验收补充（2026-10-24）

`tests/worker` 最终 11 项真实子进程测试通过，新增了 CPU 时间上限、单文件大小上限和控制面凭据不传入计算进程的检查。环境隔离同样应用于独立守护进程。内存总量/cgroup 尚未验证，不能由这些测试替代。

完整复现：`CPAG_PYTHON=python3 scripts/m4/validate-worker.sh`。需要 Docker Compose、Go 和 Python 3.11+；依赖可以预缓存，脚本本身不是离线交付包。脚本使用独立 project `cpag-m4-worker-validation`、本机 PostgreSQL 55440/API 18095，可分别通过 `CPAG_M4_PG_PORT` / `CPAG_M4_API_PORT` 改动。随机内部 token 仅在本次运行环境；数据库凭据只传给 Go API。测试完成后停止 API、删除专用容器/测试卷和临时目录，不停止原业务服务。

实际运行了 Go API + PostgreSQL + Worker：鉴权、错误 attempt token、排队取消、核心结果一致、重复完成幂等、完成后篡改检测、超时、运行中取消、Worker SIGKILL、子进程退出、真实租约到期后 attempt 2 恢复、旧 attempt 拒绝和损坏产物拒绝。PostgreSQL 使用独立可丢弃卷，容器重启后 API 能重连并读取既有终态和已发布 manifest。该测试不是断电、磁盘损坏或备份恢复证明。

首次复现使用旧 tmpfs 容器并尝试重启 PID 1，容器随主进程退出，测试失败。已将恢复测试改为带独立数据卷的容器重启；首次失败和修正后通过日志均保存在 `validation-round3/`。旧 `compose.m4-validation.yml` 仍用于快速一次性数据库测试，新恢复测试使用 `compose.m4-worker-validation.yml`。

停用手动启动的 M4 API/数据库后，原本地默认入口的 HTTP→队列→核心→下载回归也已执行；结果由本轮总验收记录引用。尚未开展生产默认切换，因此此证据仅证明独立功能可以停用且原入口继续工作，不等于生产数据库迁移回滚或灾难恢复已完成。
