# Round 4 — synthetic packet evidence path (experimental)

Baseline: 06984b8. No M2-complete or real-protocol validation claim.

New opt-in entry point: `cpag_core.packet_pipeline`. The default import pipeline,
API, worker and UI remain unchanged. No schema additions were needed: standard
NetworkEvent's single `source_ref` anchors the event; GraphArtifact node/claim
`evidence_refs` preserve **all** contributing frame refs (including identical
retransmissions). Rich byte ranges and parsed fields live in the adapter result's
observation sidecar. Existing Python/Go contract shape therefore stays identical.

## Supported subset

Existing strict classic PCAP / single-interface PCAPNG envelope, Ethernet/IPv4/TCP,
port 44818, ENIP SendRRData, canonical two-item CPF, CIP Get/Set Attribute Single,
8-bit class/instance/attribute path and associated response status/data bytes.
No clock alignment: event_time and ingest_time remain null; raw capture ticks and
resolution remain available in frame evidence. Protocol response status is not a
physical success assertion. IPv4/TCP checksum residuals and stored bytes are calculated by raw evidence queries;
validity describes captured bytes only, with offload and endpoint acceptance unknown.
Protocol events explicitly retain network_checksums_not_validated quality because
the decode/association path does not gate on these diagnostics. SHA-256 proves
evidence integrity only.

Sparse finite-capture stream collection supports segmentation, multiple PDUs per
stream (coalescing), out-of-order delivery, identical overlapping retransmissions.
Every segment intersecting a PDU is retained. Conflicting overlaps, gaps, truncated
PDUs, unsupported decoding and invalid direction reject the entire directional
stream; its epoch is disabled for request/response pairing. Unknown transport
frames conservatively disable all associations in that capture. No missing bytes
are filled. A rejected stream never contributes a partial decoded PDU prefix.

SYN starts a new observed epoch, FIN/RST closes it; payload on control packets and
payload after close are rejected. Epoch separation is conservative, not a TCP
handshake/state-machine reconstruction. Repeated SYNs create separate epochs.
Captures starting mid-connection remain explicitly epoch-unverified. Wraparound,
IP fragments, VLAN, IPv6, TCP urgent flags/control payloads and protocol alternatives
are not supported (URG is rejected).

Resource limits: capture 16 MiB / 10,000 frames / 262,144 bytes per frame; 128
cached directional epochs, 2,048 segments per stream, 262,144 sequence span per
stream, 2,048 total PDUs, 300 seconds timestamp distance from first directional
frame, and 10 seconds monotonic processing deadline. Limits are configurable via
Python dataclasses. Capture bounds constrain aggregate retained frame bytes;
sequence span constrains sparse allocation. Exceeded capture/cache/deadline limits
fail the call; malformed/span/time streams produce explicit unsupported entries.

Association requires a unique request and response with reversed endpoints,
same observed epoch, session, nonzero sender context and service. The graph claim
is `observed / protocol_request_response_association`, and explicitly excludes
attack, causal, device-identity and physical-effect conclusions. Capture order is
not used as causality. Reused/duplicate contexts remain ambiguous without an edge.

## Read-only evidence query

From repository root:

```sh
PYTHONPATH=services/analysis/src python3 -m cpag_core.packet_pipeline CAPTURE --synthetic
PYTHONPATH=services/analysis/src python3 -m cpag_core.packet_pipeline CAPTURE --synthetic --frame 1
PYTHONPATH=services/analysis/src python3 -m cpag_core.packet_pipeline CAPTURE --synthetic --event-id EVENT_ID --field cip.path
```

Full result supplies event IDs and field names (`encapsulation.command/length/
session/status/context`, `cip.service/path/general_status/data` as applicable).
Event query returns standard event, graph node, decoded observation and every
verified field slice: file hash, frame hash, frame offset, absolute capture offset,
raw frame hex, field hex and SHA-256. PacketEvidence rehashes bounded input on every
query and rejects stale hashes, frame metadata, raw timestamps, invalid ranges or
field hashes. The CLI is the minimal local evidence viewer; no HTTP server or
external publication is required.

## Reproducible checked-in synthetic example and tests

`validation-round4/protocol-synthetic.pcap` is generated from literal synthetic
ENIP request/response vectors, with reordered segments and a retransmission.
`protocol-result.json` contains 2 standard events, 2 graph nodes and 1 association.
The request node keeps refs for frames 1, 2 and 3; response keeps frame 4.
`protocol-field-query.json` is an actual CLI query of the request's `cip.path` and
contains verified raw-frame/field bytes. These are synthetic structural results.

`PYTHONPATH=services/analysis/src python3 -m unittest discover -s tests/packets -v`
passed 29 tests (`protocol-tests.log`), including both capture containers,
segmentation/coalescing/order/retransmit/conflict/gap/close/epoch tests, stream/
segment/span/time/PDU/deadline limits, contract validation, all-ref reconstruction,
captured-byte IPv4/TCP checksum diagnostics,
and same-size file, field hash, frame metadata, raw timestamp and range tampering.
Mature parser reuse decision and primary sources: [ADR 004](adr/004-bounded-packet-stream.md).

Remaining: real authorized captures, mature decoder differential validation,
production TCP state/checksum handling and API/UI integration. This is a bounded
synthetic evidence path, not full TCP or industrial protocol completion.

Association outcome annotations: every decoded observation now carries `association_status` and `association_reason`; its NetworkEvent quality reasons include the same outcome. Unique pairs are `matched/unique_request_response`. An absent counterpart is `missing/request_missing` or `missing/response_missing`. Duplicate requests/responses are `ambiguous`, including duplicate-only groups with no counterpart. Pairing blocked by unknown transport, a rejected stream in the epoch, or a zero sender context is `unsupported` with a distinct reason. Rejected undecodable streams remain in the `unsupported` evidence list. These derived annotations do not change event IDs or raw PDU/frame/file hashes.
