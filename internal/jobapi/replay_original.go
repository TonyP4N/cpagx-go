package jobapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type replayOriginal struct {
	Slot          string
	Number        int
	Record, Frame []byte
	RawTime       string
	HeaderSHA     string
	Values        []string
	Offset        int
}
type replayOriginals struct {
	Records    map[string]replayOriginal
	Header     []string
	TimeColumn int
}

func replayRecordKey(slot string, n int) string { return fmt.Sprintf("%s:%d", slot, n) }
func bytesSHA(data []byte) string               { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Final verification may read the complete retained original. Prefix execution
// never calls this verifier; snapshot references remain arrived-record hashes.
func (s *Server) replayOriginals(base string, p Payload, profile map[string]any) (replayOriginals, error) {
	out := replayOriginals{Records: map[string]replayOriginal{}, TimeColumn: -1}
	refs, e := p.networkRefs()
	if e != nil {
		return out, e
	}
	for i, ref := range refs {
		rel := base + networkSourceName(i)
		if _, e = s.check(Ref{rel, ref.SHA}); e != nil {
			return out, e
		}
		path, e := s.file(rel)
		if e != nil {
			return out, e
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return out, e
		}
		frames, e := packetFrames(raw)
		if e != nil {
			return out, e
		}
		slot := fmt.Sprintf("network-%d", i)
		var order binary.ByteOrder
		switch string(raw[:4]) {
		case "\xd4\xc3\xb2\xa1", "\x4d\x3c\xb2\xa1":
			order = binary.LittleEndian
		case "\xa1\xb2\xc3\xd4", "\xa1\xb2\x3c\x4d":
			order = binary.BigEndian
		}
		if order != nil {
			number := 0
			for pos := 24; pos < len(raw); {
				number++
				if pos+16 > len(raw) {
					return out, errors.New("truncated replay packet record")
				}
				size := int(order.Uint32(raw[pos+8 : pos+12]))
				end := pos + 16 + size
				if size < 0 || end > len(raw) || number > len(frames) {
					return out, errors.New("invalid replay packet record")
				}
				r := replayOriginal{Slot: slot, Number: number, Record: raw[pos:end], Frame: raw[pos+16 : end], RawTime: frames[number-1].RawTime, HeaderSHA: bytesSHA(raw[:24]), Offset: pos + 16}
				out.Records[replayRecordKey(slot, number)] = r
				pos = end
			}
			continue
		}
		number := 0
		headers := []byte{}
		for pos := 0; pos < len(raw); {
			if pos+12 > len(raw) {
				return out, errors.New("truncated replay packet block")
			}
			if string(raw[pos:pos+4]) == "\x0a\x0d\x0d\x0a" {
				switch string(raw[pos+8 : pos+12]) {
				case "\x4d\x3c\x2b\x1a":
					order = binary.LittleEndian
				case "\x1a\x2b\x3c\x4d":
					order = binary.BigEndian
				default:
					return out, errors.New("invalid replay byte order")
				}
			}
			if order == nil {
				return out, errors.New("missing replay section")
			}
			kind := order.Uint32(raw[pos : pos+4])
			length := int(order.Uint32(raw[pos+4 : pos+8]))
			end := pos + length
			if length < 12 || end > len(raw) {
				return out, errors.New("invalid replay block length")
			}
			if kind == 0x0a0d0d0a || kind == 1 {
				headers = append(headers, raw[pos:end]...)
			} else if kind == 6 {
				number++
				if length < 32 || number > len(frames) {
					return out, errors.New("invalid replay packet block")
				}
				size := int(order.Uint32(raw[pos+20 : pos+24]))
				if size < 0 || pos+28+size > end-4 {
					return out, errors.New("invalid replay packet bytes")
				}
				r := replayOriginal{Slot: slot, Number: number, Record: raw[pos:end], Frame: raw[pos+28 : pos+28+size], RawTime: frames[number-1].RawTime, HeaderSHA: bytesSHA(headers), Offset: pos + 28}
				out.Records[replayRecordKey(slot, number)] = r
			} else {
				return out, errors.New("unsupported replay packet block")
			}
			pos = end
		}
	}
	rel := base + "sources/process.csv"
	if _, e = s.check(Ref{rel, p.Process.SHA}); e != nil {
		return out, e
	}
	path, e := s.file(rel)
	if e != nil {
		return out, e
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return out, e
	}
	prefix := 0
	trimmed := raw
	if bytes.HasPrefix(raw, []byte{0xef, 0xbb, 0xbf}) {
		prefix = 3
		trimmed = raw[3:]
	}
	reader := csv.NewReader(bytes.NewReader(trimmed))
	reader.FieldsPerRecord = -1
	start := 0
	number := 0
	process, _ := obj(profile["process"])
	timeColumn := str(process["timestamp_column"])
	for {
		values, e := reader.Read()
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, e
		}
		number++
		end := int(reader.InputOffset()) + prefix
		if end < start || end > len(raw) {
			return out, errors.New("invalid replay CSV record position")
		}
		values, e = replayCSVValues(raw[start:end], number == 1)
		if e != nil {
			return out, e
		}
		r := replayOriginal{Slot: "process", Number: number, Record: raw[start:end], Values: append([]string(nil), values...), Offset: start}
		if number == 1 {
			out.Header = append([]string(nil), values...)
			for i, name := range values {
				if name == timeColumn {
					out.TimeColumn = i
				}
			}
		} else if out.TimeColumn >= 0 && out.TimeColumn < len(values) {
			r.RawTime = values[out.TimeColumn]
		}
		out.Records[replayRecordKey("process", number)] = r
		start = end
	}
	if out.TimeColumn < 0 {
		return out, errors.New("missing replay CSV timestamp column")
	}
	return out, nil
}
func (o replayOriginals) resolve(ref map[string]any) (replayOriginal, error) {
	slot := str(ref["source_slot"])
	number, ok := intValue(ref["frame_number"])
	network := ref["frame_number"] != nil
	if !network {
		number, ok = intValue(ref["record_number"])
	}
	r, found := o.Records[replayRecordKey(slot, number)]
	if !ok || !found || bytesSHA(r.Record) != ref["record_sha256"] {
		return r, errors.New("replay source record identity mismatch")
	}
	if network {
		if !strings.HasPrefix(slot, "network-") || ref["record_number"] != nil || ref["column"] != nil || ref["raw_time"] != r.RawTime {
			return r, errors.New("replay frame reference mismatch")
		}
	} else {
		if slot != "process" || ref["frame_number"] != nil {
			return r, errors.New("replay CSV reference mismatch")
		}
		if ref["raw_time"] != nil && ref["raw_time"] != r.RawTime {
			return r, errors.New("replay CSV raw time mismatch")
		}
		if ref["column"] != nil {
			found := false
			for _, column := range o.Header {
				found = found || column == ref["column"]
			}
			if !found {
				return r, errors.New("replay CSV column missing")
			}
		}
	}
	return r, nil
}
func (o replayOriginals) originalValue(ref map[string]any) (any, error) {
	r, e := o.resolve(ref)
	if e != nil {
		return nil, e
	}
	if r.Frame != nil {
		return map[string]any{"frame_number": r.Number, "raw_timestamp": r.RawTime, "captured_length": len(r.Frame), "frame_sha256": bytesSHA(r.Frame), "raw_hex": hex.EncodeToString(r.Frame), "integrity": "arrived_record_sha256_verified"}, nil
	}
	values := map[string]string{}
	for i, name := range o.Header {
		if i < len(r.Values) {
			values[name] = r.Values[i]
		}
	}
	return values, nil
}
func replaySourcePath(root, base, name string) string {
	return filepath.Join(root, base, "sources", name)
}

// encoding/csv normalizes CRLF even inside quoted fields. Record boundaries are
// checked with that reader, then original field bytes are decoded without that
// normalization so API evidence matches the declared raw logical record.
func replayCSVValues(raw []byte, first bool) ([]string, error) {
	if first {
		raw = bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})
	}
	if bytes.HasSuffix(raw, []byte{'\r', '\n'}) {
		raw = raw[:len(raw)-2]
	} else if bytes.HasSuffix(raw, []byte{'\n'}) {
		raw = raw[:len(raw)-1]
	}
	values := []string{}
	pos := 0
	for {
		field := []byte{}
		if pos < len(raw) && raw[pos] == '"' {
			pos++
			closed := false
			for pos < len(raw) {
				if raw[pos] == '"' {
					if pos+1 < len(raw) && raw[pos+1] == '"' {
						field = append(field, '"')
						pos += 2
						continue
					}
					pos++
					closed = true
					break
				}
				field = append(field, raw[pos])
				pos++
			}
			if !closed {
				return nil, errors.New("unterminated replay CSV field")
			}
			if pos < len(raw) && raw[pos] != ',' {
				return nil, errors.New("invalid bytes after replay CSV quote")
			}
		} else {
			for pos < len(raw) && raw[pos] != ',' {
				if raw[pos] == '"' || raw[pos] == '\r' || raw[pos] == '\n' {
					return nil, errors.New("invalid replay CSV unquoted field")
				}
				field = append(field, raw[pos])
				pos++
			}
		}
		if !utf8.Valid(field) {
			return nil, errors.New("replay CSV requires UTF-8")
		}
		values = append(values, string(field))
		if pos == len(raw) {
			break
		}
		pos++
		if pos == len(raw) {
			values = append(values, "")
			break
		}
	}
	return values, nil
}
