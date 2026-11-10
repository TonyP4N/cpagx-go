package jobapi

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestPacketRangeOverflow(t *testing.T) {
	for _, v := range [][3]int{{math.MaxInt, 1, 10}, {1, math.MaxInt, 10}, {-1, 1, 10}, {1, -1, 10}, {0, 0, 10}} {
		if packetRange(v[0], v[1], v[2]) {
			t.Fatal(v)
		}
	}
	if !packetRange(2, 3, 5) {
		t.Fatal("valid range rejected")
	}
}

func TestPacketOriginalEvidenceNegativeCases(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "inputs"), 0700); err != nil {
		t.Fatal(err)
	}
	base := "jobs/test/attempt-1/"
	if err := os.MkdirAll(filepath.Join(root, base), 0700); err != nil {
		t.Fatal(err)
	}
	raw := make([]byte, 41)
	copy(raw, []byte{0xd4, 0xc3, 0xb2, 0xa1})
	binary.LittleEndian.PutUint16(raw[4:], 2)
	binary.LittleEndian.PutUint16(raw[6:], 4)
	binary.LittleEndian.PutUint32(raw[16:], 65535)
	binary.LittleEndian.PutUint32(raw[20:], 1)
	binary.LittleEndian.PutUint32(raw[32:], 1)
	binary.LittleEndian.PutUint32(raw[36:], 1)
	raw[40] = 'x'
	digest := sha256.Sum256(raw)
	fileSHA := hex.EncodeToString(digest[:])
	valueSHA := sha256.Sum256([]byte("x"))
	fieldSHA := hex.EncodeToString(valueSHA[:])
	if err := os.WriteFile(filepath.Join(root, "inputs/test.pcap"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid-retransmission", "empty-named-slices", "overflow-offset", "wrong-event-frame"} {
		t.Run(scenario, func(t *testing.T) {
			ref := map[string]any{"file_sha256": fileSHA, "frame_number": 1, "raw_time": "0"}
			piece := map[string]any{"source_ref": ref, "frame_byte_offset": 0, "pdu_byte_offset": 0, "length": 1, "hex": "78", "sha256": fieldSHA}
			field := map[string]any{"pdu_byte_offset": 0, "length": 1, "hex": "78", "slices": []any{piece}}
			event := map[string]any{"event_id": "event", "source_ref": ref}
			if scenario == "wrong-event-frame" {
				event["source_ref"] = map[string]any{"file_sha256": fileSHA, "frame_number": 2, "raw_time": "0"}
			}
			if scenario == "empty-named-slices" {
				field["slices"] = []any{}
			}
			if scenario == "overflow-offset" {
				piece["frame_byte_offset"] = math.MaxInt
				piece["length"] = math.MaxInt
			}
			events := []any{event}
			graph := map[string]any{"nodes": []any{map[string]any{"id": "event", "event_id": "event", "evidence_refs": []any{ref}}}, "claims": []any{}, "edges": []any{}}
			side := map[string]any{"synthetic": true, "file_sha256": fileSHA, "events": events, "graph": graph, "observations": []any{map[string]any{"source_refs": []any{ref}, "field_slices": []any{piece, piece}, "pdu_hex": "78", "pdu_sha256": fieldSHA, "fields": map[string]any{"value": field}}}}
			for name, value := range map[string]any{"events.json": events, "graph.json": graph, "packet_observations.json": side} {
				b, _ := json.Marshal(value)
				if err := os.WriteFile(filepath.Join(root, base, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := (&Server{Root: root}).validatePacket(base, Payload{Network: Ref{Path: "inputs/test.pcap", SHA: fileSHA}})
			if scenario == "valid-retransmission" && err != nil {
				t.Fatal(err)
			}
			if scenario != "valid-retransmission" && err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
}
