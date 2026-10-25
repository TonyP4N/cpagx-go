# ADR 004 — experimental bounded synthetic stream adapter

Date: 2026-10-25. Status: experimental, not production protocol support.

Considered mature reuse: Wireshark/TShark provides TCP and application reassembly,
including explicit out-of-order preferences; using it would require pinned binary,
configuration and an adapter preserving every contributing frame and field range.
Scapy TCPSession requires application tcp_reassemble support; its documented
StringBuffer fills missing bytes with zeros. That behavior cannot supply evidence
for absent bytes. Neither tool is rejected for future production integration.

Decision: keep default pipeline unchanged and implement a small opt-in synthetic
subset, using existing envelope and strict ENIP/CIP decoder. Store sparse bytes,
reject conflicting overlaps/gaps, retain identical retransmission references,
parse length-delimited PDUs only after complete bounded collection. No zero fill.
A finite capture starts with an unverified connection epoch; SYN opens a new epoch,
FIN/RST closes it; payload on control packets is rejected. No endpoint identity,
handshake validity, TCP checksum validity, attack or physical effect is inferred.
Limits cover capture, streams, segments, bytes per stream, sequence span, PDU count,
and monotonic processing deadline; epoch duration is bounded in capture ticks.
Sequence wrap, IP fragments, VLAN, IPv6 and noncanonical CPF/CIP are unsupported.
The full-capture limit bounds aggregate cache even when many short epochs occur.

Production direction: compare pinned TShark outputs against real authorized
captures and preserve provenance with a tested adapter before expanding support.

Primary sources inspected 2026-10-25:
- https://www.wireshark.org/docs/wsug_html_chunked/ChAdvReassemblySection.html
- https://scapy.readthedocs.io/en/latest/api/scapy.sessions.html
- https://www.rfc-editor.org/rfc/rfc9293.html (sequence space, SYN/FIN semantics)
