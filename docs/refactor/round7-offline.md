# Round 7 engineering offline package

The package version is provisionally `cpag-engineering-synthetic-rc1`. This is a limited engineering candidate for synthetic tasks, not industrial validation or a production deployment. Final freeze requires the clean-source build and the complete disconnected-target/drill acceptance; intermediate builds are not frozen releases.

## Explicit supported target

The target is **containerized Linux/arm64**, running a fresh Docker Engine 29.1.3 inside the pinned Docker-in-Docker image, with brand-new daemon/image-store and state volumes. The observed target reports Alpine Linux 3.23 (containerized), Linux kernel/resource controllers supplied by the outer Docker Linux VM, aarch64 and cgroup v2. Exact `/etc/os-release`, `uname -a`, Docker client/server versions and capabilities are captured in `validation-round7/offline/target-platform.json` and `clean-target.json` when the run reaches those steps. This is not bare-metal or VM operating-system installation acceptance.

Public network isolation is enforced by the **outer** Docker internal network: no default route and unsuccessful public HTTPS access are required both before install and after services start. Inner service containers use a private ordinary bridge so Docker 29 can publish the authenticated API/evidence ports to host loopback. Inner bridge membership is not claimed as the air-gap boundary. Compute containers separately use network none.

## Package and provenance

Final local package destination (outside Git):

`/Users/nbtechx-pyf/Documents/ChatGPT/FYP/releases/cpag-engineering-synthetic-rc1/`

The preparation scripts are `scripts/release/build-offline.py` and `validate-offline.py`; runtime wrappers are in `deployments/engineering`. Artifacts include application/compute/PostgreSQL image tar, a separate lab-engine tar, source/release manifests, fixed dependency lock, non-secret configuration example, Chinese operating instructions, installer/lifecycle CLI, rollback drill and SHA256SUMS covering every packaged file. No large image tar is committed to Git. `/private/tmp` is used only for a same-checksum lab copy to avoid macOS Documents file-sharing prompts.

Pinned runtime/build dependencies are Python 3.12.12-alpine3.22, Go 1.26.5 with CGO disabled and Linux arm64 output, Docker CLI/engine 29.1.3 and PostgreSQL 17.6-alpine. Python uses only the standard library. Target installation uses docker load, never online pull/build/package installation. Docker Engine/sh/sha256sum are target prerequisites; the lab-engine image supplies the explicitly containerized engine environment.

`release.json` records candidate full source commit and source-file hashes. The baseline core/API/worker/schema/migrations come from `git archive 1386a4f`; its full baseline commit is recorded, while the engineering wrappers are separately identified as the new packaging/operations layer. Thus rollback tests old core behavior under the common harness; they do not claim the old commit originally contained the new harness. Saved image config SHA-256 and development daemon OCI index IDs are distinguished because Docker's classic/vfs loader and the preparation daemon can expose different image ID forms for the same saved image.

The final build must use `--require-clean`: all relevant source inputs must match committed HEAD and remain unchanged through export. Documentation/evidence may be committed separately afterward. Package checksums bind the exported artifacts; checksum manifests alone are not a claim that intermediate dirty source builds are frozen.

## Runtime layout and interface

Default data root is `/cpag-root/data`; Docker host paths are mounted at the same absolute paths inside the controller so isolated input bind mounts refer to the correct host filesystem. The host coordinator keeps worker/coordinator API credentials and control receipts; compute gets only read-only inputs and bounded output/runtime tmpfs. API, PostgreSQL, host coordinator, SQL recovery and authenticated evidence/download are separate containers. An independent recovery loop performs Docker cleanup/reconciliation every five seconds; SQL recovery alone is not substituted for it.

`cpag.sh install|start|maintenance|stop|restart|demo|check` is the supported package CLI. Project names prefix service containers and the PG volume. Existing network/volume resources must have the matching ownership label; PG reuse additionally verifies image, DB name, credentials, mount and network. Stop verifies the daemon and service ownership, distinguishes a genuinely absent container from daemon/inspection failures, and retains data volumes/directories. Maintenance leaves PostgreSQL available for backup. Migrations and their content hashes are recorded in the same database transaction and startup is serialized by an operations lock.

The API uses localhost:18115; evidence/download uses localhost:18120 and Bearer authentication. The HTTP evidence/download adapter supports only the two registry-listed demo tasks. It checks API succeeded state and artifact path/hash, original input digests, publication wrapper, the exact downloadable manifest bytes bound to the API publication SHA, core manifest and artifact hashes/sizes before returning data. Packet output is re-decoded from the original capture. The acceptance check downloads and opens both result archives, checks every member against the published wrapper, queries a packet field, and exercises missing/tampered legacy artifacts/originals plus a tampered packet wrapper and a separately tampered downloadable manifest. API input references remain under `inputs/`; installed samples are copied to `shared/inputs` without changing their filenames.

## Reproduction and acceptance records

Online preparation after the final code commit:

```sh
python3 scripts/release/build-offline.py --include-baseline --require-clean \
  --output /Users/nbtechx-pyf/Documents/ChatGPT/FYP/releases/cpag-engineering-synthetic-rc1
```

The clean lab uses an independent privileged Docker-in-Docker container; it does not mount the development daemon socket into the inner target. It requires fresh lab volumes, records zero target images before installation, checks the public-route boundary, loads only package images, installs, submits legacy/packet synthetic tasks via API, verifies real isolated attempt history, queries evidence, validates result downloads, and restarts services with persisted job results. The disposable upgrade drill then executes baseline tasks, upgrades while preserving prior evidence, restores a candidate checkpoint into a new DB/directory, and rolls back an old checkpoint to the old app/compute images and executes fresh old-version tasks. Stopping services by itself does not qualify as rollback.

```sh
python3 scripts/release/validate-offline.py --package /private/tmp/cpag-offline-lab-package \
  --evidence docs/refactor/validation-round7/offline --keep --run-upgrade-drill
```

The preparation output path may be any explicit directory; the final delivery path above is fixed for this run. The lab package copy must retain identical SHA256SUMS/content. Detailed evidence remains under `validation-round7/offline`; final result status and package digests are appended only after actual acceptance completes.

## Final observed acceptance (2026-10-26)

The final candidate was built with `--require-clean` from **49e998545b9b7b47f2b1dc9b19e6d8562f780765**. The external package is 295,307,920 bytes; the SHA-256 of its `SHA256SUMS` is `8671381859425cb1d170c64cf200ca7cc3546e2fbcaf7e6f3a71f256656e1bf9`. The temporary lab copy was checked against every packaged file checksum and is identical. The package contents were left unchanged after this build.

The fresh disconnected target reported Alpine Linux **3.23.2**, aarch64, kernel **6.12.54-linuxkit**, Docker client/server **29.1.3**, cgroup v2, and zero initial images. Both public-route checks passed. Installation/load, independent API/PG/controller/recovery/evidence services, actual isolated legacy and packet task execution, packet field query, both downloaded tar archives (six and seven verified members), persisted results after service restart, and all **five** download negative cases passed. The negative cases cover a separately tampered downloadable manifest, missing legacy artifact, tampered legacy artifact, changed original input, and tampered packet publication wrapper.

The complete upgrade drill passed: old-core execution, upgrade with previous evidence preserved, candidate checkpoint restoration into a separate empty DB/directory, rollback from the old checkpoint to the archived old app/compute images, and fresh old-core tasks after rollback. Six incomplete/tampered snapshot variants were rejected before restore; the original snapshot remained unchanged. Full results are in `validation-round7/offline/upgrade-rollback-result.json` and `acceptance.log`.

Final compute identity (same saved image, two daemon representations):

- Preparation daemon OCI ID: `sha256:99d890615dbf7667af785470e77160b1d2f0ee77d97e6076069d876be0780c53`.
- Portable saved config/target ID: `sha256:bf4c9d0208dff86d6e7868c357a9f114697d544dc517f4a8d71bae7f56b556a9`.

`release.json`, `baseline-release.json`, `dependencies.lock.json`, `SHA256SUMS`, and `package-identity.json` are copied into the evidence directory for compact provenance review. Earlier namespace and downloadable-manifest defect reproductions remain in `pre-fix-input-prefix` and `pre-fix-manifest`; they are not mixed with the final passing result.

After acceptance, the inner daemon reported **zero running containers**. The outer disposable lab engine was then stopped (Docker recorded exit code 137); its test volumes were preserved. `stopped-target.json` records the observed stopped state. No claim of graceful daemon shutdown or bare-metal/VM OS installation is made. The supported data remain synthetic engineering fixtures; real industrial-data validation and production deployment remain outside this acceptance.
