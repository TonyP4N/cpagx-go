# M2 preparation: synthetic capture envelope only

Status: partial engineering preparation; M2 real-data exit condition remains unmet.
Default network parser and pipeline are unchanged. No NetworkEvents, request pairs,
CIP operations, device labels, success states or graph relations are produced.

Separate API: `cpag_core.parsers.packet_envelope.inspect_capture(path, synthetic=True,
limits=Limits(...))`. Separate CLI (stdout JSON; nonzero failure):

```sh
PYTHONPATH=services/analysis/src python3 -m cpag_core.parsers.packet_envelope sample.pcap --synthetic
python3 -m unittest discover -s tests/packets -v
```

`--synthetic` is a caller attestation, not a detector of synthetic bytes. Do not use
it for licensed/real captures. Profile `profiles/packets/synthetic-envelope-v1.json`
is an explicit support declaration; not automatically loaded by the API.

| Input / condition | Handling and test coverage |
| --- | --- |
| Classic PCAP 2.4 Ethernet | Little/big endian, micro/nanosecond raw integer timestamps; generated tests |
| PCAPNG 1.0 | One unknown-length section and one Ethernet interface; both endian orders; no-option IDB and EPB; default microsecond ticks only |
| Timestamp options / additional sections or interfaces / unknown blocks | Fail explicitly; custom interface timestamp resolutions are unsupported, not silently ignored |
| Unknown linktype / malformed lengths / incomplete headers | Entire call fails with CaptureError; no partial result returned |
| Capture shorter than original frame | Original/captured lengths retained, capture_truncated quality reason |
| Ethernet / IPv4 / TCP | Fixed envelope fields only: addresses, IP protocol, ports, sequence/ack, flags, payload length; no checksum validation |
| VLAN / non-IPv4 / non-TCP / IP fragments / short headers | Explicit unsupported reason; no application inference |
| Duplicate/retransmit/segmented/out-of-order/unanswered/non-target bytes | Actual generated Ethernet/IPv4/TCP frames retain duplicate sequence/data, reordered segment sequence numbers, same-direction unanswered payload and non-target port in file order. Assertions check header and raw-byte preservation only; no reassembly, pairing or unanswered classification is performed |
| ENIP/CIP | Unsupported, including on port 44818. Port number is not protocol confirmation |
| Resource limits | Byte, frame count and frame-size limits; positive integer configuration; bounded input read |

Every indexed frame contains input SHA-256, one-based frame number, byte offset,
captured/original length, raw timestamp ticks/resolution and frame SHA-256. These
allow verification directly against original bytes; timestamp ticks are not
aligned process time. Duplicate data retains separate frame references. Input
remains immutable; output deterministic. API memory is bounded by max_bytes plus
bounded per-frame results; it is not a streaming performance implementation.

Fixtures are generated in `tests/packets/test_packet_envelope.py`; they contain no
licensed data or attack labels. Passing tests demonstrate envelope behavior only.
Real acceptance still requires authorized normal/attack captures, provenance and
release metadata, independent frame-field reference, actual linktype/timestamp
options inventory, ENIP encapsulation/CIP service/path validation, bounded TCP
reassembly and retransmission ambiguity policy, request/response pairing,
real-data resource benchmarks, clock evidence and device mapping review. No
industrial protocol correctness or detection accuracy is claimed.


Validation strengthening: 10 tests pass, including a hand-written literal hexadecimal
PCAP golden record independent of the fixture builders, raw byte checks for both
containers, actual TCP segment header cases, and explicit rejection of multiple
interfaces and if_tsresol values 6, 9 and binary resolution 0x8a. Checksums are not
validated and generated header cases use zero checksums; these are structural
fixtures, not proof of valid wire traffic. The profile is descriptive only;
configuration is passed through Limits or CLI --max-bytes, --max-frames and
--max-frame-bytes. There is no JSON profile loader.

Format reference (primary, work-in-progress): the PCAPNG authors' IETF
[PCAPNG draft, section 4.2](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html#section-4.2)
specifies default timestamp resolution 10^-6 when if_tsresol is absent. This
implementation admits only option-free interfaces, so that default has a defined
basis; any present timestamp-resolution option is rejected. The document is an
Internet-Draft, not a claim of standards certification. Verified 2026-10-24.
