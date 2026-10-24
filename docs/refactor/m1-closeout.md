# M1 evidence closeout — 2026-10-24

Scope remains the synthetic normalized JSONL + explicitly profiled CSV pipeline from ADR 0001 and proposal §4.3/M1. Raw packet adapters remain separate and opt-in; this change does not connect packet decoding to the pipeline or claim M2/M3 completion.

## Changes

- A per-run `EvidenceIndex` snapshots and hashes each input once, indexes complete raw records, and supplies the exact same bytes to its parser. Event lookup is indexed; it does not hash or scan a source per event.
- JSONL logical numbering follows physical JSONL lines, preserving invalid-line positions while allowing later valid evidence to resolve. CSV indexing and parsing both use strict `csv.reader`, include empty logical records in numbering, and preserve multiline fields. Invalid widths do not shift later positions.
- `EvidenceIndex.resolve` exposes the original row including raw strings for evidence inspection. The compatibility `resolve_evidence` API still returns the verified source path. The pipeline checks network and profiled CSV raw times against the snapshot. CSV `EvidenceIndex.resolve` deliberately returns the raw row without assuming a timestamp column: only the profile identifies that column, so the pipeline enforces the CSV raw-time equality. A regression injects an incorrect CSV raw time and verifies failure before any output directory is created. Invalid UTF-8 now fails the pipeline explicitly with `ContractError`; standalone parser APIs continue to return partial quality with no events.
- Either empty required source (including a header-only process CSV) is rejected before creating an output directory. This deliberately tightens the dual-input M1 invocation; it is not a claim that every later analysis mode must reject zero events.
- Source inode/size/mtime/ctime are checked during indexing and lookup. Full content checks run before creating output and immediately before writing the success manifest. A mutation at publication leaves no success manifest; any already written partial artifacts remain an unsuccessful reserved attempt.

## Verification

Using repository `.venv/bin/python`, with `PYTHONPATH=services/analysis/src`:

- `python -m unittest discover -s tests/core -q`: 12 passed.
- `python -m unittest discover -s tests/parsers -q`: 13 passed.
- `python -m unittest discover -s tests/integration -q`: 2 passed.
- `git diff --check`: passed.

Regression coverage checks invalid JSONL preceding a valid record, complete raw row equality, blank CSV records followed by multiline values, raw zero and state strings, empty-source rejection, mutation before/during index creation, after indexing, before publication, and during manifest validation. Existing repeatability, contract and immutable-directory checks remain passing.

## Synthetic scaling measurement

Reproduce: `PYTHONPATH=services/analysis/src .venv/bin/python scripts/benchmarks/m1_evidence.py`.
Raw results: `validation/m1-evidence-scaling.json`. The generator produces equal row counts per source and three events per row pair. Timings include parsing, validation, indexed evidence checks, sorting, canonical serialization and publication. Peak memory is Python allocations measured by `tracemalloc`, not total process RSS. One sample per size is a smoke benchmark, not a statistical performance budget.

| Records per source | Events | Elapsed seconds | Peak Python MiB |
| ---: | ---: | ---: | ---: |
| 100 | 300 | 0.303 | 2.358 |
| 1,000 | 3,000 | 2.878 | 16.106 |
| 5,000 | 15,000 | 14.935 | 70.642 |

Increasing input 50× increased elapsed time about 49× in this local synthetic measurement. The former per-event full-file hashing/rescanning is removed. There is no measured claim about real industrial captures or deployed service throughput.

## Limits

The index, parser events, graph and serialization remain in memory; memory grows with input size. This is not a streaming/out-of-core implementation. The source snapshot is stable, and source changes through the final integrity check are detected, but local filesystem checks cannot lock an adversarial writer out of the tiny interval after the last check. Retaining and publishing immutable copied evidence would require a separate storage/publication design. No legacy service/container deployment behavior was changed or validated in this scoped closeout.

## Matched baseline comparison

Reproduce: `.venv/bin/python scripts/benchmarks/m1_evidence_compare.py`.
The script reads revision `75a9e92` using `git ls-tree`/`git show` into a temporary source tree (including its schemas) and runs each variant and size in a fresh subprocess. It never checks out or changes baseline files in the workspace. Both variants use identical generated records, the same profile and interpreter. Raw results: `validation/m1-evidence-comparison.json`.

| Records/source | Events | Baseline seconds | Indexed seconds | Baseline peak Python MiB | Indexed peak Python MiB |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 300 | 0.425 | 0.422 | 2.190 | 2.382 |
| 500 | 1,500 | 4.034 | 1.474 | 8.899 | 9.835 |
| 1,000 | 3,000 | 13.082 | 2.983 | 14.594 | 16.475 |

At 1,000 rows per source this sample is about 4.4× faster, with about 13% higher peak Python allocations. The index trades memory for lookup speed. These are individual local measurements under `tracemalloc`, with caching and instrumentation effects; peak Python allocation memory is explicitly **not RSS**. No 5,000-row baseline was attempted because the former algorithm rescans sources per event.

## Integrated service verification

The parent integration run also passed all 11 service regressions and the actual
HTTP → Go → FastAPI → RabbitMQ → Worker → download smoke test. Header-only CSV
fails the task without downloadable artifacts; a zero-byte network upload is
rejected by HTTP before queueing. Invalid leading JSONL plus blank/multiline CSV
completes with warnings and preserved evidence positions. Logs are recorded in
`validation-round2/`. Core version is now `0.1.1`; schema remains `1.0.0`.

The code commit for this closeout is recorded in the subsequent round summary,
so this document does not attempt to embed its own commit hash.
