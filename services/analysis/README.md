# M1 standalone analysis core

Run from the repository root with Python 3.10+; the runtime uses only the standard library. No database, web service, broker, external packet parser, or package installation is needed.

```sh
PYTHONPATH=services/analysis/src python3 -m cpag_core \
  --network tests/fixtures/synthetic/network.normalized.jsonl \
  --process tests/fixtures/synthetic/process.csv \
  --profile profiles/synthetic-demo.json \
  --output /tmp/cpag-m1-example \
  --synthetic
```

Choose a new output directory for every attempt. Existing directories are refused, including empty ones. Outputs are `dataset.json`, `events.json`, `graph.json`, `quality.json`, and `run_manifest.json`. The manifest lists artifact SHA-256 and byte sizes, input/configuration fingerprints, tool versions, and stable event/graph result hashes. The manifest does not hash itself. Partial I/O failures may leave an incomplete attempt directory; only a valid manifest denotes a completed core export. Downstream callers must verify every listed checksum before consuming a run. Files remain ordinary local files, so filesystem permissions must enforce retention after publication.

The API is `cpag_core.pipeline.run(network, process, profile, output, synthetic=True)`. A profile can be a JSON path or dictionary. Both Python and Go validate the shared nine `schemas/*.schema.json` contracts. Keep the repository layout intact: the standalone core locates schemas relative to its source file. Core runtime validation implements the checked-in schema subset without `jsonschema`; development `jsonschema` independently checks schema syntax and exported artifacts. Install `services/analysis/requirements-test.txt` before running Python tests.

```sh
PYTHONPATH=services/analysis/src python3 -m unittest discover -s tests/core -v
PYTHONPATH=services/analysis/src python3 -m unittest discover -s tests/contracts -v
PYTHONPATH=services/analysis/src python3 -m unittest discover -s tests/parsers -v
go test ./internal/contracts
```

M1 consumes explicitly synthetic normalized network JSONL and process CSV. This does not implement raw PCAP parsing, real clock/device alignment, derived events, cross-source correlation, causality, replay, or detection evaluation. Graph nodes preserve each observed event and its source reference; edges and claims are empty. Unconnected observations are intentional. Unresolved time and device fields remain null with quality reasons. Runtime IDs and ingestion timestamps are excluded from canonical result hashes. Event ordering and IDs depend on event content and source evidence, not execution time. A source hash and one-based logical record (CSV header excluded) plus column resolve original evidence; multiline CSV fields do not change record numbering.

`EvaluationRecord` defines a future independent-label contract; the core never creates evaluation metrics or labels from predictions. A declared independent-label flag is a contract assertion, not proof that a dataset is independent. Contract validation cannot establish real-world source authenticity or annotation independence.
