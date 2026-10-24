# M2 synthetic ENIP/CIP protocol increment

Status: engineering validation of a bounded synthetic subset, **not M2 real-data
acceptance**. Default parser, pipeline, graph generation and detector remain unchanged.
No NetworkEvents, attack labels, device identities or physical-process success
claims are emitted. This module returns protocol observations and capture-scoped
matching evidence only. All results retain partial quality.

Opt-in API: `cpag_core.parsers.packet_protocol.inspect_protocol(path,
synthetic=True, limits=Limits(...))`. `--synthetic` attests generated input; it does
not detect synthetic input. Do not use this attestation to admit licensed captures.
The lower-level `decode_payload(bytes)` is a pure structural decoder used by tests;
it performs no file ingestion and has no pipeline integration.

```sh
PYTHONPATH=services/analysis/src python3 -m cpag_core.parsers.packet_protocol sample.pcap --synthetic
python3 -m unittest discover -s tests/packets -v
```

CLI supports `--max-bytes`, `--max-frames`, `--max-frame-bytes`; malformed container,
resource-limit, missing attestation and input-mutation failures exit nonzero.
Per-frame unsupported application formats produce explicit reasons and partial
results. `profiles/packets/synthetic-protocol-v1.json` documents the subset; it is
not a profile loader or production switch.

| Layer | Exact supported subset / boundary |
| --- | --- |
| Container | Existing bounded envelope PCAP/PCAPNG subset, unchanged |
| Transport | Ethernet/IPv4/TCP, port 44818, complete application PDU in exactly one TCP payload |
| ENIP | 24-byte little-endian header; SendRRData 0x006f; nonzero session, zero options/status; length must exhaust payload |
| CPF | Interface zero, exactly two items in order: null address with zero length, unconnected data 0x00b2; item length must exhaust body; timeout retained raw |
| CIP request | GetAttributeSingle 0x0e or SetAttributeSingle 0x10; exactly 3 canonical 8-bit logical segments: 0x20 class, 0x24 instance, 0x30 attribute; Get has no request data; Set data retained opaque hex |
| CIP response | Service response bit; reserved byte zero, general status raw integer, additional-status count in 16-bit words, opaque response data hex; no typed-value or state-change interpretation |
| Unsupported | RegisterSession, SendUnitData, connected/routed messaging, UnconnectedSend wrapper, symbolic/16-bit/32-bit paths, additional CPF items, encapsulation error bodies, UDP/VLAN/IPv6/fragments, TCP reassembly/coalescing/wrap |

TCP payloads are **candidate PDU boundaries**, not proof of stream framing. No
reassembly is attempted. Partial header/body, multiple PDUs in one payload and
length discrepancies are explicit unsupported observations; they disable pairing
for the known bidirectional endpoint flow. Sequence interval overlaps (including
identical retransmissions and conflicting overlaps) disable all pairing for that
flow, preserving each contributing frame separately. Out-of-order complete PDUs
can be decoded without inferring timing or causal order. Any observed SYN/FIN/RST (including zero-payload control frames) disables pairing
for the entire known endpoint flow, conservatively preventing matches across
observed connection boundaries. Other zero-payload frames are ignored. TCP
handshakes, ACK consistency, connection epochs and
checksums are not validated. Unsupported frames without decodable endpoints cannot
be assigned to a flow. These limitations prevent any claim of complete stream
coverage; capture-scoped pairs carry `connection_epoch_unverified` quality.

Pairing requires exactly one observed request and one response with reversed
IPv4/TCP endpoints, same nonzero session, same nonzero eight-byte sender context,
and same base service. Direction must match server port 44818. Repeated contexts,
multiple candidates, mismatched service/session/context and zero context never
produce guessed links. Request-only output says `no_matching_response_observed`,
which does not assert actual timeout, loss or device failure. Responses carry no
inferred path. Pairs reference both request and response source frames; they do
not invent a response path. Returned indices refer to the observation array.

Each source reference includes file SHA-256, frame SHA-256, one-based frame
number, byte offset, captured and original lengths. Full frame records also retain
raw timestamp ticks/resolution. Input is reread boundedly and its digest compared
to the indexed snapshot, so a change between reads fails explicitly. Output is
deterministic for fixed bytes. The existing byte/frame limits bound decoding and
output; interval sorting is O(n log n), no unbounded flow cache or external process
is used. This is not a measured throughput claim.

Validation: 19 packet tests pass (10 existing envelope tests, 9 protocol tests).
Independent handwritten hexadecimal Get request and response validate field
positions without the message fixture builder. Generated PCAP and PCAPNG cases
exercise reordered full messages, writes, numeric error/additional status,
identical duplicates/conflicting overlap, request–SYN/FIN/RST–response boundaries with empty and nonempty control payloads, incomplete and split PDUs, coalescing,
unsupported services/paths, CPF length mismatch, capture truncation, fragment rejection, direction/port mismatch, encapsulation header rejection, missing response, correlation
mismatches, zero context, limits, gate, digest mutation and mutation between reads.
Fixtures use structural zero-checksum headers, not a claim of valid wire traffic.

Primary implementation references checked 2026-10-24 (mutable upstream source;
not ODVA conformance certification):

- [OpENer encapsulation implementation](https://github.com/EIPStackGroup/OpENer/blob/master/source/src/enet_encap/encap.c): 0x006f command, 24-byte header field ordering and echoed sender context.
- [OpENer CPF implementation](https://github.com/EIPStackGroup/OpENer/blob/master/source/src/enet_encap/cpf.c): null-address/unconnected-data dispatch and response general/additional-status encoding.
- [OpENer message router](https://github.com/EIPStackGroup/OpENer/blob/master/source/src/cip/cipmessagerouter.c): request service/path/data structure.

Real-data gaps: authorized normal/attack capture provenance and release metadata;
independent fixed-version dissector/known device field comparison; full protocol
specification review; session/connection lifecycle, sender-context reuse and
retransmission inventory; justified bounded reassembly; actual path/service and
linktype coverage; capture truncation, checksums and packet loss assessment;
clock/alignment evidence, device mapping, real resource benchmarks and independent
attack labels. No real-data parsing accuracy or detection result is claimed.
