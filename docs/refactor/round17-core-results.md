# R17 core implementation and bounded verification

Preregistered expected outcomes: [round17-core-scenarios.md](round17-core-scenarios.md). This record covers generated references and the software real-source branch only. No industrial source bytes or authorization authenticity were independently validated.

## Opt-in and provenance

The original `synthetic: true` profile without `analysis_mode` uses the historical result version and parser semantics. New clock/mapping metadata, custom CSV timestamp/missing definitions, finite rules and real input require `analysis_mode: bounded-real-capable-v1`; unknown fields and unsupported schema versions are rejected. The opted-in result version is `bounded-dual-source-1`, retaining schema version `1.0.0` and explicit additive metadata.

A real-source profile additionally requires nonblank source/release/authorization/timezone/mapping/rules references, a collection interval, clock version/validity/drift/precision evidence, and mapping version/validity/evidence. These references are declarations, not proof of authorization authenticity or field correctness. All events, derived events, claims, graphs and manifests retain `synthetic: false` and `real_source_unvalidated`. Standard dataset metadata comes from the retained declared provenance. Missing alignment facts cannot create cross-source support.

## Time and mapping semantics

Each clock applies `corrected = raw + offset + (raw - drift_anchor) * drift_ppm / 1,000,000`. Uncertainty and declared precision add on each side of the interval. Original network integer ticks, tick rate, hash and local frame number remain attached; original CSV text remains in its source reference. Exact network ticks and process microseconds are converted using rational arithmetic and floating interval endpoints rounded outward. The drift computation also rounds outward. Config dates with more than six fractional second digits fail explicitly; extended CSV timestamps at that unsupported precision remain unknown with original text retained.

Clock validity applies to the raw UTC interval; mapping/rule validity applies to corrected intervals. The entire uncertain interval must fit inside the closed declared validity. Missing drift/precision/version/validity material in an opted-in synthetic run yields unknown clock status; incomplete real material declarations fail profile validation. A request crossing a mapping boundary remains unresolved. All applicable matches are retained; two matches never choose the first. The old profile remains immutable through the retained profile bytes and fingerprint.

## Finite rule semantics

The only kinds are `state_change`, `threshold`, and `process_constraint`. Rules require an ID, version, basis, asset/tag, units and validity. Operators are `gt/ge/lt/le/eq/ne`. Numeric threshold predicates apply to sampled values, with exact inclusive/exclusive boundary semantics and no claim about unsampled values. A state change compares adjacent valid samples within the configured sample gap. A process constraint applies only to two unambiguous observations with exactly equal corrected intervals; allowed arithmetic is sum, difference or ratio. Both operands must have the declared identical units; sum/difference retain that unit and ratio is dimensionless. No conversion or nearest-sample matching is inferred.

An optional `applies_when` uses one exact synchronous tag/unit/value condition. A false or missing condition yields unknown/not applicable rather than evidence for the predicate. Each finding records exact parameters, applicability, support, refutation with original references, missing reasons, and `missing_value_policy: unknown_no_interpolation`. Zero remains distinct from missing. Invalid quality, ambiguous source mappings, division by zero, incompatible units and nonfinite arithmetic cannot support a finding. False predicates emit refutation evidence. The implementation contains no expression/code evaluator.

Findings remain separate from observed sample transitions and hypothetical cross-source claims. Standard export wraps each finding as a `DerivedEvent` (`finite_rule_finding`) and a graph node. Existing `change_id` evidence queries can select `finding_id`; the verified selection is `rule_finding`.

## Inventory, limits and compatibility

One scalar capture retains `sources/network.pcap`. Ordered captures two through four retain `sources/network-001.pcap` through `network-003.pcap`; the dual manifest declares `network_inputs`. Local frame number is always paired with the original file hash. Query/rebuild checks every original source and the complete normalized result. Standard manifests have exact dynamic file inventories and verified graph/event hashes; failed export removes partial outputs.

Actual execution limits remain: four captures, aggregate 16 MiB and 10,000 frames; process 2 MiB, 1,000 logical records, 16 mapped columns; profile 64 KiB; 100 mappings, 100 operations, 100 finite rules, 10,000 candidate associations and 10,000 finite findings. All are reported on opted-in results. The R19 candidate 128 MiB / 10,000 process records and reference-hardware performance targets remain unachieved and are not silently replaced by these development limits.

Generated fixture tests are `tests/dual_source/test_round17_core.py`; reusable profiles are in `scripts/validation/round17_profile.py`. Verification includes direct API/CLI canonical output equality; real-branch provenance and false flags; conservative precision, missing metadata and validity boundaries; mapping ambiguity; threshold boundaries, state evidence, bounded constraints and missing/zero handling; cross-file equal-frame-number evidence; immutable old runs, tampered originals, and failed publication cleanup. Existing dual tests remain included. An independent execution of baseline `68977076ec3869fd3fa1c7e841c918e4b196840f` dual-source code against the same supported parser references produced byte-identical normalized analysis for all 15 prior registered scenarios. Parser-specific legacy edge compatibility is recorded separately.

## Final-review order correction

The preregistered addendum exposed an order gap independently: `precision_seconds: 2`, `max_sample_gap_seconds: 10` retained overlapping process intervals and previously emitted one transition, one unknown candidate and one supported state-change finding without any order warning. The newly added regression failed before the implementation at the expected nonempty `changes` assertion. The ordinary 3-second gap guard had masked this case, so the explicit 10-second fixture isolates order from sampling coverage.

The extended-mode group check now requires strictly separated adjacent process intervals. Overlap or a shared endpoint produces `process_order_uncertain`; original observations remain intact while derived before/after changes and transition candidates are suppressed, and finite findings for that unresolved group remain unknown. The regression covers precision widening, uncertainty widening and touching intervals. Historical mode is unchanged. All 33 dual-source tests pass. Independent comparison with pre-correction commit `4b298e1` confirmed byte-identical canonical results for the 15 legacy scenarios and four non-overlapping R17 synthetic/real and finite-rule variants. This correction adds no real-data validation claim.
