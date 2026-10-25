package jobapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

type packetRef struct {
	Record  *int    `json:"record_number"`
	Column  *string `json:"column"`
	RawTime string  `json:"raw_time"`
	SHA     string  `json:"file_sha256"`
	Frame   int     `json:"frame_number"`
}
type packetSlice struct {
	Ref         packetRef `json:"source_ref"`
	FrameOffset int       `json:"frame_byte_offset"`
	PDUOffset   int       `json:"pdu_byte_offset"`
	Length      int       `json:"length"`
	Hex         string    `json:"hex"`
	SHA         string    `json:"sha256"`
}

type packetFrame struct {
	Data    []byte
	RawTime string
}

func packetFrames(data []byte) ([]packetFrame, error) {
	bad := func() ([]packetFrame, error) { return nil, fmt.Errorf("invalid packet capture envelope") }
	if len(data) < 24 {
		return bad()
	}
	var order binary.ByteOrder
	frames := []packetFrame{}
	switch string(data[:4]) {
	case "\xd4\xc3\xb2\xa1", "\x4d\x3c\xb2\xa1":
		order = binary.LittleEndian
	case "\xa1\xb2\xc3\xd4", "\xa1\xb2\x3c\x4d":
		order = binary.BigEndian
	}
	if order != nil {
		if order.Uint16(data[4:6]) != 2 || order.Uint16(data[6:8]) != 4 || order.Uint32(data[20:24]) != 1 {
			return bad()
		}
		for pos := 24; pos < len(data); {
			if pos+16 > len(data) {
				return bad()
			}
			n := int(order.Uint32(data[pos+8 : pos+12]))
			if n > 262144 || n < 0 || pos+16+n > len(data) {
				return bad()
			}
			resolution := uint64(1000000)
			if string(data[:4]) == "\x4d\x3c\xb2\xa1" || string(data[:4]) == "\xa1\xb2\x3c\x4d" {
				resolution = 1000000000
			}
			frames = append(frames, packetFrame{data[pos+16 : pos+16+n], fmt.Sprint(uint64(order.Uint32(data[pos:pos+4]))*resolution + uint64(order.Uint32(data[pos+4:pos+8])))})
			pos += 16 + n
			if len(frames) > 10000 {
				return bad()
			}
		}
		return frames, nil
	}
	if string(data[:4]) != "\x0a\x0d\x0d\x0a" {
		return bad()
	}
	for pos := 0; pos < len(data); {
		if pos+12 > len(data) {
			return bad()
		}
		if string(data[pos:pos+4]) == "\x0a\x0d\x0d\x0a" {
			if order != nil {
				return bad()
			}
			switch string(data[pos+8 : pos+12]) {
			case "\x4d\x3c\x2b\x1a":
				order = binary.LittleEndian
			case "\x1a\x2b\x3c\x4d":
				order = binary.BigEndian
			default:
				return bad()
			}
		}
		if order == nil {
			return bad()
		}
		kind := order.Uint32(data[pos : pos+4])
		n := int(order.Uint32(data[pos+4 : pos+8]))
		if n < 12 || n%4 != 0 || pos+n > len(data) || int(order.Uint32(data[pos+n-4:pos+n])) != n {
			return bad()
		}
		if kind == 6 {
			if n < 32 {
				return bad()
			}
			captured := int(order.Uint32(data[pos+20 : pos+24]))
			if captured > 262144 || pos+28+captured > pos+n-4 {
				return bad()
			}
			frames = append(frames, packetFrame{data[pos+28 : pos+28+captured], fmt.Sprint(uint64(order.Uint32(data[pos+12:pos+16]))<<32 | uint64(order.Uint32(data[pos+16:pos+20])))})
			if len(frames) > 10000 {
				return bad()
			}
		} else if kind != 1 && kind != 0x0a0d0d0a {
			return bad()
		}
		pos += n
	}
	return frames, nil
}
func packetRange(offset, length, total int) bool {
	return offset >= 0 && length > 0 && offset <= total && length <= total-offset
}

func (s *Server) validatePacket(base string, p Payload) error {
	capture, err := s.file(p.Network.Path)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(capture)
	if err != nil {
		return err
	}
	frames, err := packetFrames(raw)
	if err != nil {
		return err
	}
	sidePath, err := s.file(base + "packet_observations.json")
	if err != nil {
		return err
	}
	sideBytes, err := os.ReadFile(sidePath)
	if err != nil {
		return err
	}
	var side struct {
		SHA          string          `json:"file_sha256"`
		Synthetic    bool            `json:"synthetic"`
		Events       json.RawMessage `json:"events"`
		Graph        json.RawMessage `json:"graph"`
		Observations []struct {
			Refs   []packetRef   `json:"source_refs"`
			Slices []packetSlice `json:"field_slices"`
			PDUHex string        `json:"pdu_hex"`
			PDUSHA string        `json:"pdu_sha256"`
			Fields map[string]struct {
				Offset int           `json:"pdu_byte_offset"`
				Length int           `json:"length"`
				Hex    string        `json:"hex"`
				Slices []packetSlice `json:"slices"`
			} `json:"fields"`
		} `json:"observations"`
	}
	if err = json.Unmarshal(sideBytes, &side); err != nil {
		return err
	}
	if !side.Synthetic || side.SHA != p.Network.SHA || len(side.Observations) == 0 {
		return fmt.Errorf("invalid packet sidecar identity")
	}
	for name, expected := range map[string]json.RawMessage{"events.json": side.Events, "graph.json": side.Graph} {
		path, e := s.file(base + name)
		if e != nil {
			return e
		}
		b, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		var actualValue, expectedValue any
		if json.Unmarshal(b, &actualValue) != nil || json.Unmarshal(expected, &expectedValue) != nil {
			return fmt.Errorf("invalid packet artifact")
		}
		a, _ := json.Marshal(actualValue)
		b, _ = json.Marshal(expectedValue)
		if !bytes.Equal(a, b) {
			return fmt.Errorf("packet sidecar artifact mismatch")
		}
	}
	validRef := func(r packetRef) bool {
		return r.Record == nil && r.Column == nil && r.SHA == p.Network.SHA && r.Frame > 0 && r.Frame <= len(frames) && r.RawTime == frames[r.Frame-1].RawTime
	}
	var events []struct {
		ID  string    `json:"event_id"`
		Ref packetRef `json:"source_ref"`
	}
	var graph struct {
		Nodes []struct {
			ID    string      `json:"id"`
			Event string      `json:"event_id"`
			Refs  []packetRef `json:"evidence_refs"`
		} `json:"nodes"`
		Claims []struct {
			ID   string      `json:"claim_id"`
			Refs []packetRef `json:"evidence_refs"`
		} `json:"claims"`
		Edges []struct {
			Source string `json:"source"`
			Target string `json:"target"`
			Claim  string `json:"claim_id"`
		} `json:"edges"`
	}
	if json.Unmarshal(side.Events, &events) != nil || json.Unmarshal(side.Graph, &graph) != nil || len(events) != len(side.Observations) || len(graph.Nodes) != len(events) {
		return fmt.Errorf("packet event/observation count mismatch")
	}
	equalRefs := func(a, b []packetRef) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	refsByEvent := map[string][]packetRef{}
	for i, event := range events {
		refs := side.Observations[i].Refs
		if len(refs) == 0 || event.Ref != refs[0] || event.ID == "" || refsByEvent[event.ID] != nil {
			return fmt.Errorf("event source reference mismatch")
		}
		refsByEvent[event.ID] = refs
	}
	nodeSeen := map[string]bool{}
	for _, node := range graph.Nodes {
		refs, ok := refsByEvent[node.Event]
		if !ok || node.ID != node.Event || nodeSeen[node.ID] || !equalRefs(node.Refs, refs) {
			return fmt.Errorf("graph node evidence mismatch")
		}
		nodeSeen[node.ID] = true
	}
	claims := map[string][]packetRef{}
	for _, claim := range graph.Claims {
		if claim.ID == "" || claims[claim.ID] != nil {
			return fmt.Errorf("invalid packet claim identity")
		}
		claims[claim.ID] = claim.Refs
	}
	if len(graph.Edges) != len(graph.Claims) {
		return fmt.Errorf("claim edge count mismatch")
	}
	edgeSeen := map[string]bool{}
	for _, edge := range graph.Edges {
		a, okA := refsByEvent[edge.Source]
		b, okB := refsByEvent[edge.Target]
		combined := append(append([]packetRef{}, a...), b...)
		if !okA || !okB || edgeSeen[edge.Claim] || !equalRefs(claims[edge.Claim], combined) {
			return fmt.Errorf("claim evidence mismatch")
		}
		edgeSeen[edge.Claim] = true
	}
	for _, obs := range side.Observations {
		if len(obs.Fields) == 0 {
			return fmt.Errorf("packet named field evidence required")
		}
		pdu, e := hex.DecodeString(obs.PDUHex)
		if e != nil || len(pdu) == 0 {
			return fmt.Errorf("invalid packet PDU")
		}
		sum := sha256.Sum256(pdu)
		if hex.EncodeToString(sum[:]) != obs.PDUSHA {
			return fmt.Errorf("packet PDU digest mismatch")
		}
		covered := make([]bool, len(pdu))
		check := func(piece packetSlice, mark bool) error {
			belongs := false
			for _, ref := range obs.Refs {
				if piece.Ref == ref {
					belongs = true
				}
			}
			if !belongs {
				return fmt.Errorf("slice source ref absent from observation")
			}
			if !validRef(piece.Ref) || !packetRange(piece.FrameOffset, piece.Length, len(frames[piece.Ref.Frame-1].Data)) || !packetRange(piece.PDUOffset, piece.Length, len(pdu)) {
				return fmt.Errorf("packet evidence range invalid")
			}
			value := frames[piece.Ref.Frame-1].Data[piece.FrameOffset : piece.FrameOffset+piece.Length]
			digest := sha256.Sum256(value)
			if hex.EncodeToString(value) != piece.Hex || hex.EncodeToString(digest[:]) != piece.SHA || !bytes.Equal(value, pdu[piece.PDUOffset:piece.PDUOffset+piece.Length]) {
				return fmt.Errorf("packet evidence original bytes mismatch")
			}
			if mark {
				for n := piece.PDUOffset; n < piece.PDUOffset+piece.Length; n++ {
					covered[n] = true
				}
			}
			return nil
		}
		for _, ref := range obs.Refs {
			if !validRef(ref) {
				return fmt.Errorf("packet source reference mismatch")
			}
		}
		for _, ref := range obs.Refs {
			found := false
			for _, piece := range obs.Slices {
				if piece.Ref == ref {
					found = true
				}
			}
			if !found {
				return fmt.Errorf("source ref has no original PDU evidence")
			}
		}
		for _, piece := range obs.Slices {
			belongs := false
			for _, ref := range obs.Refs {
				if piece.Ref == ref {
					belongs = true
				}
			}
			if !belongs {
				return fmt.Errorf("slice source ref absent from observation")
			}
			if e = check(piece, true); e != nil {
				return e
			}
		}
		for _, yes := range covered {
			if !yes {
				return fmt.Errorf("incomplete packet PDU evidence")
			}
		}
		for _, field := range obs.Fields {
			if !packetRange(field.Offset, field.Length, len(pdu)) || hex.EncodeToString(pdu[field.Offset:field.Offset+field.Length]) != field.Hex {
				return fmt.Errorf("named packet field mismatch")
			}
			fieldCovered := make([]bool, field.Length)
			for _, piece := range field.Slices {
				if e = check(piece, false); e != nil {
					return e
				}
				if piece.PDUOffset < field.Offset || piece.PDUOffset-field.Offset > field.Length || piece.Length > field.Length-(piece.PDUOffset-field.Offset) {
					return fmt.Errorf("named field slice range mismatch")
				}
				for n := piece.PDUOffset - field.Offset; n < piece.PDUOffset-field.Offset+piece.Length; n++ {
					fieldCovered[n] = true
				}
			}
			for _, yes := range fieldCovered {
				if !yes {
					return fmt.Errorf("incomplete named field evidence")
				}
			}
		}
	}
	return nil
}
