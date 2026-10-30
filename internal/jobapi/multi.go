package jobapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"time"
)

func (p Payload) networkRefs() ([]Ref, error) {
	if len(p.Networks) == 0 {
		return []Ref{p.Network}, nil
	}
	if !dualFamily(p.Kind) || len(p.Networks) < 2 || len(p.Networks) > 4 || p.Networks[0] != p.Network {
		return nil, errors.New("invalid ordered network refs")
	}
	seen := map[string]bool{}
	for _, r := range p.Networks {
		if seen[r.Path] || seen[r.SHA] {
			return nil, errors.New("duplicate network reference")
		}
		seen[r.Path] = true
		seen[r.SHA] = true
	}
	return p.Networks, nil
}
func networkSourceName(i int) string {
	if i == 0 {
		return "sources/network.pcap"
	}
	return fmt.Sprintf("sources/network-%03d.pcap", i)
}
func dualArtifactNamesFor(p Payload) []string {
	if IsCompactPayload(p) {
		return compactArtifactNames(p)
	}
	out := dualArtifactNames()
	refs, _ := p.networkRefs()
	for i := 1; i < len(refs); i++ {
		out = append(out, "dual/"+networkSourceName(i))
	}
	return out
}
func networkHashes(p Payload) []string {
	if len(p.Networks) == 0 {
		return nil
	}
	out := []string{}
	for _, r := range p.Networks {
		out = append(out, r.SHA)
	}
	return out
}
func publicationInputsMatch(p Payload, inputs map[string]string, networks []string) bool {
	return len(inputs) == 3 && inputs["network"] == p.Network.SHA && inputs["process"] == p.Process.SHA && inputs["profile"] == p.Profile.SHA && reflect.DeepEqual(networks, networkHashes(p))
}

func (s *Server) dualCaptureFrames(base string, p Payload) (map[string][]packetFrame, error) {
	budget, err := payloadLimits(p)
	if err != nil {
		return nil, err
	}
	refs, e := p.networkRefs()
	if e != nil {
		return nil, e
	}
	out := map[string][]packetFrame{}
	totalFrames := 0
	for i, r := range refs {
		path, e := s.file(base + "dual/" + networkSourceName(i))
		if e != nil {
			return nil, e
		}
		if _, e = s.check(Ref{base + "dual/" + networkSourceName(i), r.SHA}); e != nil {
			return nil, e
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			return nil, e
		}
		frames, e := packetFrames(raw, budget.Frames)
		if e != nil {
			return nil, e
		}
		totalFrames += len(frames)
		if totalFrames > budget.Frames {
			return nil, fmt.Errorf("aggregate frame budget exceeded")
		}
		out[r.SHA] = frames
	}
	return out, nil
}

// ReadyRealDualBasis checks evidence declarations, never their field authenticity.
func ReadyRealDualBasis(doc map[string]any) bool {
	if doc["analysis_mode"] != "bounded-real-capable-v1" {
		return false
	}
	source, ok := doc["source_provenance"].(map[string]any)
	if doc["synthetic"] == false || source != nil {
		if !ok {
			return false
		}
		for _, key := range []string{"source", "release", "authorization_ref", "timezone_basis", "mapping_evidence_ref", "rules_evidence_ref"} {
			if !nonblank(source[key]) {
				return false
			}
		}
		interval, ok := source["collection_range"].(map[string]any)
		if !ok || !validInterval(interval["start"], interval["end"]) {
			return false
		}
	}
	clocks, ok := doc["clocks"].(map[string]any)
	if !ok {
		return false
	}
	for _, name := range []string{"network", "process"} {
		clock, ok := clocks[name].(map[string]any)
		if !ok {
			return false
		}
		for _, key := range []string{"version", "basis", "precision_basis", "drift_basis"} {
			if !nonblank(clock[key]) {
				return false
			}
		}
		if !validInterval(clock["valid_from"], clock["valid_to"]) || !validTimestamp(clock["drift_anchor"]) {
			return false
		}
		for _, key := range []string{"offset_seconds", "uncertainty_seconds", "precision_seconds", "drift_ppm"} {
			if _, ok := number(clock[key]); !ok {
				return false
			}
		}
	}
	mappings, ok := doc["mappings"].([]any)
	if !ok || len(mappings) == 0 {
		return false
	}
	for _, m := range mappings {
		mapping, ok := m.(map[string]any)
		if !ok || !nonblank(mapping["version"]) || !nonblank(mapping["basis"]) || !validInterval(mapping["valid_from"], mapping["valid_to"]) {
			return false
		}
	}
	return true
}
func nonblank(v any) bool { s, ok := v.(string); return ok && strings.TrimSpace(s) != "" }
func validTimestamp(v any) bool {
	s, ok := v.(string)
	if !ok || regexp.MustCompile(`\.\d{7}`).MatchString(s) {
		return false
	}
	_, e := time.Parse(time.RFC3339Nano, s)
	return e == nil
}
func validInterval(a, b any) bool {
	if !validTimestamp(a) || !validTimestamp(b) {
		return false
	}
	x, _ := time.Parse(time.RFC3339Nano, a.(string))
	y, _ := time.Parse(time.RFC3339Nano, b.(string))
	return !y.Before(x)
}
func number(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case json.Number:
		f, e := n.Float64()
		return f, e == nil
	case int:
		return float64(n), true
	}
	return 0, false
}

func packetTick(x map[string]any) bool {
	return len(x) == 4 && x["frame_number"] != nil && x["raw_timestamp"] != nil && x["ticks_per_second"] != nil && x["file_sha256"] != nil
}
func verifyPacketTick(x map[string]any, captures map[string][]packetFrame) error {
	n, ok := intValue(x["frame_number"])
	frames := captures[str(x["file_sha256"])]
	resolution, valid := number(x["ticks_per_second"])
	if !ok || n < 1 || n > len(frames) || !valid || resolution <= 0 || fmt.Sprint(x["raw_timestamp"]) != frames[n-1].RawTime {
		return errors.New("capture clock reference mismatch")
	}
	return nil
}
