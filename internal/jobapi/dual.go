package jobapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"github.com/TonyP4N/cpagx-go/internal/contracts"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

// The bounded dual export is an opt-in projection of the existing analysis core.
// These are its complete file and directory inventories; no unlisted output is publishable.
var dualFiles = []string{"dataset.json", "events.json", "graph.json", "quality.json", "analysis.json", "run_manifest.json", "dual/manifest.json", "dual/analysis.json", "dual/sources/network.pcap", "dual/sources/process.csv", "dual/sources/profile.json"}
var dualDirs = map[string]bool{"dual": true, "dual/sources": true}
var dualAnchor = regexp.MustCompile(`^[a-f0-9]{64}\.json$`)

// DualProfileFingerprint is the canonical JSON fingerprint consumed by the
// existing Python dual core. Keep this single implementation for Go clients.
func DualProfileFingerprint(raw []byte) (string, error) {
	var value any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&value); err != nil {
		return "", err
	}
	if d.Decode(new(any)) != io.EOF {
		return "", errors.New("one profile object required")
	}
	canonical, err := pythonCanonical(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// VerifiedDualArtifacts returns only artifacts from the currently published
// attempt after publishedDual has rechecked every source and artifact byte.
func (s *Server) VerifiedDualArtifacts(r *http.Request, id string) ([]struct {
	Path string `json:"path"`
	SHA  string `json:"sha256"`
	Size int64  `json:"size_bytes"`
}, string, error) {
	base, p, _, err := s.publishedDual(r, id)
	if err != nil {
		return nil, "", err
	}
	value, err := s.readDualJSON(base, "manifest.json", p)
	if err != nil {
		return nil, "", err
	}
	m, ok := obj(value)
	if !ok {
		return nil, "", errors.New("invalid publication manifest")
	}
	rows, ok := arr(m["artifacts"])
	if !ok {
		return nil, "", errors.New("invalid publication artifacts")
	}
	result := []struct {
		Path string `json:"path"`
		SHA  string `json:"sha256"`
		Size int64  `json:"size_bytes"`
	}{}
	for _, v := range rows {
		row, ok := obj(v)
		if !ok {
			return nil, "", errors.New("invalid artifact entry")
		}
		n, ok := intValue(row["size"])
		if !ok {
			return nil, "", errors.New("invalid artifact size")
		}
		result = append(result, struct {
			Path string `json:"path"`
			SHA  string `json:"sha256"`
			Size int64  `json:"size_bytes"`
		}{str(row["path"]), str(row["sha256"]), int64(n)})
	}
	return result, base, nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func dualSchemaDir() string {
	locations := []string{os.Getenv("CPAG_SCHEMAS_DIR")}
	if _, source, _, ok := runtime.Caller(0); ok {
		locations = append(locations, filepath.Join(filepath.Dir(source), "../../schemas"))
	}
	locations = append(locations, "/app/schemas", "schemas", "../../schemas")
	for _, dir := range locations {
		if dir == "" {
			continue
		}
		if info, err := os.Stat(filepath.Join(dir, "DualSourceProfile.schema.json")); err == nil && info.Mode().IsRegular() {
			return dir
		}
	}
	return "schemas"
}

func dualArtifactNames() []string { return append([]string(nil), dualFiles...) }
func dualArtifactSet() map[string]bool {
	set := map[string]bool{}
	for _, name := range dualFiles {
		if name != "run_manifest.json" {
			set[name] = true
		}
	}
	return set
}
func validArtifactPath(path, kind string) bool {
	if kind == "dual-source-replay" {
		return validReplayArtifactPath(path)
	}
	if kind == "dual-source" {
		return dualArtifactSet()[path] || path == "run_manifest.json" || regexp.MustCompile(`^dual/sources/network-00[1-3]\.pcap$`).MatchString(path)
	}
	return filepath.Base(path) == path
}

// Python's json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False)
// defines the checked-in core's fingerprint contract. Float values must be
// rendered after JSON parsing, not hashed from arbitrary lexical spellings.
func pythonCanonical(value any) ([]byte, error) {
	var b bytes.Buffer
	var write func(any) error
	write = func(value any) error {
		switch x := value.(type) {
		case nil:
			b.WriteString("null")
		case bool:
			if x {
				b.WriteString("true")
			} else {
				b.WriteString("false")
			}
		case string:
			b.WriteByte('"')
			for _, r := range x {
				switch r {
				case '\\':
					b.WriteString(`\\`)
				case '"':
					b.WriteString(`\"`)
				case '\b':
					b.WriteString(`\b`)
				case '\f':
					b.WriteString(`\f`)
				case '\n':
					b.WriteString(`\n`)
				case '\r':
					b.WriteString(`\r`)
				case '\t':
					b.WriteString(`\t`)
				default:
					if r < 0x20 {
						fmt.Fprintf(&b, `\u%04x`, r)
					} else {
						b.WriteRune(r)
					}
				}
			}
			b.WriteByte('"')
		case json.Number:
			lex := string(x)
			if strings.ContainsAny(lex, ".eE") {
				f, err := strconv.ParseFloat(lex, 64)
				if err != nil || math.IsInf(f, 0) || math.IsNaN(f) {
					return errors.New("invalid floating point profile number")
				}
				if f == 0 && math.Signbit(f) {
					b.WriteString("-0.0")
					break
				}
				text := strconv.FormatFloat(f, 'g', -1, 64)
				absolute := math.Abs(f)
				// Python uses fixed notation for [1e-4, 1e16), Go for [1e-6, 1e21).
				if absolute >= 1e-4 && absolute < 1e16 {
					text = strconv.FormatFloat(f, 'f', -1, 64)
				}
				if absolute > 0 && (absolute < 1e-4 || absolute >= 1e16) {
					text = strconv.FormatFloat(f, 'e', -1, 64)
				}
				if !strings.ContainsAny(text, ".e") {
					text += ".0"
				}
				if at := strings.IndexByte(text, 'e'); at >= 0 {
					exponent, err := strconv.Atoi(text[at+1:])
					if err != nil {
						return err
					}
					text = text[:at] + fmt.Sprintf("e%+03d", exponent)
				}
				b.WriteString(text)
			} else {
				if _, err := x.Int64(); err != nil {
					return err
				}
				if lex == "-0" {
					b.WriteString("0")
				} else {
					b.WriteString(lex)
				}
			}
		case float64:
			// Used only for Go-originated schema constants in tests.
			return write(json.Number(strconv.FormatFloat(x, 'f', -1, 64)))
		case []any:
			b.WriteByte('[')
			for i, v := range x {
				if i != 0 {
					b.WriteByte(',')
				}
				if err := write(v); err != nil {
					return err
				}
			}
			b.WriteByte(']')
		case map[string]any:
			b.WriteByte('{')
			keys := make([]string, 0, len(x))
			for key := range x {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for i, key := range keys {
				if i != 0 {
					b.WriteByte(',')
				}
				if err := write(key); err != nil {
					return err
				}
				b.WriteByte(':')
				if err := write(x[key]); err != nil {
					return err
				}
			}
			b.WriteByte('}')
		default:
			return fmt.Errorf("unsupported canonical value %T", value)
		}
		return nil
	}
	if err := write(value); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
func digestValue(value any) (string, error) {
	var stable func(any) any
	stable = func(v any) any {
		switch x := v.(type) {
		case map[string]any:
			out := make(map[string]any, len(x))
			for key, item := range x {
				if key != "run_id" && key != "ingest_time" {
					out[key] = stable(item)
				}
			}
			return out
		case []any:
			out := make([]any, len(x))
			for i, item := range x {
				out[i] = stable(item)
			}
			return out
		}
		return v
	}
	b, err := pythonCanonical(stable(value))
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
func parseValue(data []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("multiple JSON values")
	}
	return value, nil
}
func validateDualProfile(value any) error {
	profile, ok := value.(map[string]any)
	if !ok {
		return errors.New("dual profile object required")
	}
	process, ok := profile["process"].(map[string]any)
	if !ok {
		return errors.New("dual process mapping required")
	}
	columns, ok := process["columns"].(map[string]any)
	if !ok || len(columns) < 1 || len(columns) > 16 {
		return errors.New("dual column count outside service bounds")
	}
	mappings, ok := profile["mappings"].([]any)
	if !ok || len(mappings) > 100 {
		return errors.New("dual mapping count outside service bounds")
	}
	seen := map[string]bool{}
	for _, v := range mappings {
		row, ok := v.(map[string]any)
		if !ok {
			return errors.New("invalid dual mapping")
		}
		id, ok := row["rule_id"].(string)
		if !ok || seen[id] {
			return errors.New("duplicate or invalid dual rule id")
		}
		seen[id] = true
	}
	return nil
}
func sameJSON(a, b any) bool           { return reflect.DeepEqual(a, b) }
func obj(v any) (map[string]any, bool) { m, ok := v.(map[string]any); return m, ok }
func arr(v any) ([]any, bool)          { a, ok := v.([]any); return a, ok }
func str(v any) string                 { s, _ := v.(string); return s }
func intValue(v any) (int, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	i, e := n.Int64()
	return int(i), e == nil && int64(int(i)) == i
}
func (s *Server) readDualJSON(base, name string, selected ...Payload) (any, error) {
	path, err := s.file(base + name)
	if err != nil {
		return nil, err
	}
	resourceProfile := s.ResourceProfile
	if len(selected) > 0 {
		resourceProfile = selected[0].ResourceProfile
	}
	limit, err := capacity.ArtifactBytes(resourceProfile)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > limit {
		return nil, errors.New("dual JSON exceeds operator resource byte budget")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseValue(raw)
}
func (s *Server) dualInventory(base string, payload ...Payload) error {
	names := dualFiles
	if len(payload) > 0 {
		names = dualArtifactNamesFor(payload[0])
	}
	root, err := s.file(strings.TrimSuffix(base, "/"))
	if err != nil {
		return err
	}
	found := map[string]bool{}
	dirs := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("dual artifact symlink forbidden")
		}
		if entry.IsDir() {
			if !dualDirs[rel] {
				return errors.New("unknown dual directory")
			}
			dirs[rel] = true
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("nonregular dual artifact")
		}
		if rel != "manifest.json" && !dualAnchor.MatchString(rel) && !validArtifactPath(rel, "dual-source") {
			return errors.New("unknown dual artifact")
		}
		found[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	anchors := 0
	for name := range found {
		if dualAnchor.MatchString(name) {
			anchors++
		}
	}
	if anchors > 1 || (anchors == 1 && !found["manifest.json"]) || len(found) != len(names)+anchors+boolInt(found["manifest.json"]) || len(dirs) != len(dualDirs) {
		return errors.New("dual artifact inventory mismatch")
	}
	for _, name := range names {
		if !found[name] {
			return errors.New("missing dual artifact: " + name)
		}
	}
	return nil
}

func (s *Server) validateDual(base string, p Payload, wrapper Manifest, coreRaw []byte) error {
	if err := s.dualInventory(base, p); err != nil {
		return err
	}
	if err := contracts.Validate(dualSchemaDir(), "RunManifest", coreRaw); err != nil {
		return err
	}
	coreValue, err := parseValue(coreRaw)
	if err != nil {
		return err
	}
	core, ok := obj(coreValue)
	if !ok {
		return errors.New("invalid dual core manifest")
	}
	parts := strings.Split(strings.Trim(base, "/"), "/")
	attempt, _ := intValue(core["attempt_id"])
	if len(parts) != 3 || parts[0] != "jobs" || core["run_id"] != parts[1] || parts[2] != fmt.Sprintf("attempt-%d", attempt) || attempt < 1 {
		return errors.New("dual core attempt identity mismatch")
	}
	dualValue, err := s.readDualJSON(base, "dual/manifest.json", p)
	if err != nil {
		return err
	}
	refs, _ := p.networkRefs()
	profile, err := s.readDualJSON(base, "dual/sources/profile.json", p)
	if err != nil {
		return err
	}
	profileDoc, _ := obj(profile)
	synthetic, validSynthetic := profileDoc["synthetic"].(bool)
	if !validSynthetic {
		return errors.New("missing source category")
	}
	if core["synthetic"] != synthetic {
		return errors.New("core source category mismatch")
	}
	dual, ok := obj(dualValue)
	if !ok {
		return errors.New("invalid dual source manifest")
	}
	version, err := dualAnalysisVersion(profileDoc, dual["analysis_version"])
	if err != nil {
		return err
	}
	if declared, exists := core["analysis_version"]; exists && declared != version {
		return errors.New("core analysis version mismatch")
	}
	if !ok || (len(dual) != 5 && len(dual) != 6) || dual["schema_version"] != "1.0.0" || dual["synthetic"] != synthetic || dual["analysis_version"] != version || dual["config_fingerprint"] != p.Fingerprint {
		return errors.New("invalid dual source manifest")
	}
	files, ok := obj(dual["files"])
	if !ok || len(files) != 3+len(refs) {
		return errors.New("invalid dual source file set")
	}
	expectedFiles := map[string]string{"sources/process.csv": p.Process.SHA, "sources/profile.json": p.Profile.SHA, "analysis.json": ""}
	networkNames := []any{}
	for i, r := range refs {
		expectedFiles[networkSourceName(i)] = r.SHA
		networkNames = append(networkNames, networkSourceName(i))
	}
	if len(refs) > 1 && !sameJSON(dual["network_inputs"], networkNames) {
		return errors.New("ordered network inventory mismatch")
	}
	for name, expected := range expectedFiles {
		digest, ok := files[name].(string)
		if !ok || !shaPattern.MatchString(digest) || (expected != "" && digest != expected) {
			return errors.New("dual source hash mismatch: " + name)
		}
		if _, err := s.checkArtifact(p, Ref{base + "dual/" + name, digest}); err != nil {
			return err
		}
	}
	analysis, err := s.readDualJSON(base, "analysis.json", p)
	if err != nil {
		return err
	}
	retained, err := s.readDualJSON(base, "dual/analysis.json", p)
	if err != nil {
		return err
	}
	if !sameJSON(analysis, retained) {
		return errors.New("dual analysis projection mismatch")
	}
	a, ok := obj(analysis)
	if !ok || a["schema_version"] != "1.0.0" || a["synthetic"] != synthetic || a["analysis_version"] != version || a["config_fingerprint"] != p.Fingerprint || a["input_fingerprint"] != core["input_fingerprint"] {
		return errors.New("invalid dual analysis identity")
	}
	budget, err := readPayloadBudget(p, profileDoc)
	if err != nil {
		return err
	}
	if budget.Version != "" {
		for key, limit := range map[string]int{"operations": budget.Operations, "changes": budget.Changes, "candidates": budget.Candidates} {
			rows, yes := arr(a[key])
			if !yes || len(rows) > limit {
				return fmt.Errorf("analysis %s exceeds capacity budget", key)
			}
		}
	}
	profile, err = s.readDualJSON(base, "dual/sources/profile.json", p)
	if err != nil {
		return err
	}
	fp, err := digestValue(profile)
	if err != nil || fp != p.Fingerprint {
		return errors.New("dual profile fingerprint mismatch")
	}
	events, err := s.readDualJSON(base, "events.json", p)
	if err != nil {
		return err
	}
	graph, err := s.readDualJSON(base, "graph.json", p)
	if err != nil {
		return err
	}
	dataset, err := s.readDualJSON(base, "dataset.json", p)
	if err != nil {
		return err
	}
	quality, err := s.readDualJSON(base, "quality.json", p)
	if err != nil {
		return err
	}
	if !sameJSON(quality, a["quality"]) {
		return errors.New("dual quality projection mismatch")
	}
	for name, value := range map[string]any{"GraphArtifact": graph, "DatasetManifest": dataset} {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		if err = contracts.Validate(dualSchemaDir(), name, encoded); err != nil {
			return err
		}
	}
	eventList, ok := arr(events)
	if !ok {
		return errors.New("invalid dual event list")
	}
	network, nok := arr(a["network"])
	process, pok := arr(a["process"])
	changes, cok := arr(a["changes"])
	operations, ook := arr(a["operations"])
	candidates, aok := arr(a["candidates"])
	findings, _ := arr(a["rule_findings"])
	if !nok || !pok || !cok || !ook || !aok || len(eventList) != len(network)+len(process)+len(changes)+len(findings) {
		return errors.New("dual analysis list mismatch")
	}
	projected := make([]any, 0, len(eventList))
	for _, x := range append(append([]any{}, network...), process...) {
		row, ok := obj(x)
		if !ok {
			return errors.New("invalid dual observation")
		}
		projected = append(projected, row["event"])
	}
	projected = append(projected, changes...)
	for i, f := range findings {
		finding, ok := obj(f)
		event, valid := obj(eventList[len(projected)])
		if !ok || !valid || event["event_id"] != finding["finding_id"] || event["event_type"] != "finite_rule_finding" || !sameJSON(event["result"], finding) || !sameJSON(event["parameters"], finding["parameters"]) || !sameJSON(event["evidence_refs"], finding["evidence_refs"]) || event["rule_version"] != finding["rule_version"] {
			return errors.New("finite finding projection mismatch")
		}
		tr, valid := obj(event["time_range"])
		interval, has := arr(finding["interval"])
		if !valid {
			return errors.New("finite finding time range missing")
		}
		for j, key := range []string{"start", "end"} {
			if has && len(interval) == 2 {
				v, valid := number(interval[j])
				parsed, e := time.Parse(time.RFC3339Nano, str(tr[key]))
				if !valid || e != nil || math.Abs(float64(parsed.UnixMicro())/1e6-v) > 0.000001 {
					return errors.New("finite finding interval mismatch")
				}
			} else if tr[key] != nil {
				return errors.New("unknown finite interval changed")
			}
		}
		_ = i
		projected = append(projected, event)
	}
	if !sameJSON(eventList, projected) {
		return errors.New("dual event projection mismatch")
	}
	g, ok := obj(graph)
	if !ok || g["synthetic"] != synthetic || g["input_fingerprint"] != a["input_fingerprint"] {
		return errors.New("invalid dual graph")
	}
	graphID := map[string]any{}
	for key, value := range g {
		if key != "graph_id" {
			graphID[key] = value
		}
	}
	graphDigest, err := digestValue(graphID)
	if err != nil || g["graph_id"] != "dual-graph-"+graphDigest {
		return errors.New("dual graph identity mismatch")
	}
	nodes, nok := arr(g["nodes"])
	edges, eok := arr(g["edges"])
	claims, cok := arr(g["claims"])
	if !nok || !eok || !cok || len(nodes) != len(eventList) || len(edges) != len(candidates) || len(claims) != len(candidates) {
		return errors.New("dual graph count mismatch")
	}
	for i, event := range eventList {
		e, ok := obj(event)
		if !ok || e["synthetic"] != synthetic || str(e["event_id"]) == "" {
			return errors.New("invalid dual event")
		}
		n, ok := obj(nodes[i])
		if !ok || n["id"] != e["event_id"] || n["event_id"] != e["event_id"] {
			return errors.New("dual graph node mismatch")
		}
		refs := []any{}
		if i < len(network) {
			row, _ := obj(network[i])
			obs, ok := obj(row["observation"])
			if !ok {
				return errors.New("invalid network observation")
			}
			refs, _ = arr(obs["source_refs"])
			if len(refs) == 0 || !sameJSON(e["source_ref"], refs[0]) {
				return errors.New("network source reference mismatch")
			}
		}
		if i >= len(network) && i < len(network)+len(process) {
			refs = []any{e["source_ref"]}
		}
		if i >= len(network)+len(process) {
			if (i < len(network)+len(process)+len(changes) && e["event_type"] != "observed_sample_transition") || (i >= len(network)+len(process)+len(changes) && e["event_type"] != "finite_rule_finding") {
				return errors.New("invalid derived event type")
			}
			refs, _ = arr(e["evidence_refs"])
			if i < len(network)+len(process)+len(changes) && len(refs) != 2 {
				return errors.New("derived event requires two source references")
			}
		}
		if !sameJSON(n["evidence_refs"], refs) {
			return errors.New("dual graph evidence mismatch")
		}
		schema := "NetworkEvent"
		if i >= len(network) {
			schema = "ProcessObservation"
		}
		if i >= len(network)+len(process) {
			schema = "DerivedEvent"
		}
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if err = contracts.Validate(dualSchemaDir(), schema, encoded); err != nil {
			return err
		}
	}
	opIDs, changeIDs := map[string]bool{}, map[string]bool{}
	processByID := map[string]map[string]any{}
	for _, value := range process {
		row, _ := obj(value)
		event, _ := obj(row["event"])
		processByID[str(event["event_id"])] = event
	}
	for _, value := range operations {
		row, ok := obj(value)
		if !ok || str(row["operation_id"]) == "" || opIDs[str(row["operation_id"])] {
			return errors.New("duplicate dual operation")
		}
		opIDs[str(row["operation_id"])] = true
	}
	for _, value := range changes {
		row, _ := obj(value)
		changeIDs[str(row["event_id"])] = true
		identity := map[string]any{}
		for key, item := range row {
			identity[key] = item
		}
		identity["event_id"] = ""
		fingerprint, err := digestValue(identity)
		if err != nil || row["event_id"] != "change-"+fingerprint {
			return errors.New("derived event identity mismatch")
		}
		result, ok := obj(row["result"])
		if !ok {
			return errors.New("derived event result missing")
		}
		before, bok := processByID[str(result["before_event_id"])]
		after, aok := processByID[str(result["after_event_id"])]
		refs, rok := arr(row["evidence_refs"])
		if !bok || !aok || !rok || len(refs) != 2 || !sameJSON(refs[0], before["source_ref"]) || !sameJSON(refs[1], after["source_ref"]) || !sameJSON(result["before"], before["value"]) || !sameJSON(result["after"], after["value"]) || result["asset_id"] != before["asset_id"] || result["asset_id"] != after["asset_id"] || result["tag"] != before["tag"] || result["tag"] != after["tag"] {
			return errors.New("derived event source observation mismatch")
		}
	}
	for i, value := range candidates {
		c, ok := obj(value)
		if !ok || !opIDs[str(c["operation_id"])] || !changeIDs[str(c["change_id"])] || c["state"] == "" {
			return errors.New("dual candidate linkage mismatch")
		}
		candidateDigest, err := digestValue([]any{c["operation_id"], c["change_id"], profile})
		if err != nil || c["candidate_id"] != "candidate-"+candidateDigest {
			return errors.New("dual candidate identity mismatch")
		}
		claim, ok := obj(c["claim"])
		if !ok || claim["claim_id"] != c["candidate_id"] || claim["status"] != "hypothetical" || claim["relation_type"] != "candidate_network_process_association" || claim["synthetic"] != synthetic {
			return errors.New("dual claim mismatch")
		}
		if !sameJSON(claims[i], claim) {
			return errors.New("dual claim projection mismatch")
		}
		encoded, err := json.Marshal(claim)
		if err != nil {
			return err
		}
		if err = contracts.Validate(dualSchemaDir(), "Claim", encoded); err != nil {
			return err
		}
		edge, ok := obj(edges[i])
		if !ok || edge["id"] != c["candidate_id"] || edge["source"] != c["operation_id"] || edge["target"] != c["change_id"] || edge["claim_id"] != claim["claim_id"] || edge["candidate_state"] != c["state"] || edge["config_fingerprint"] != p.Fingerprint {
			return errors.New("dual edge mismatch")
		}
	}
	d, ok := obj(dataset)
	if !synthetic {
		provenance, _ := obj(profileDoc["source_provenance"])
		if !sameJSON(a["source_provenance"], provenance) {
			return errors.New("real source declaration changed")
		}
		for _, key := range []string{"source", "release", "authorization_ref", "collection_range", "timezone_basis"} {
			if !sameJSON(d[key], provenance[key]) {
				return errors.New("real dataset provenance mismatch")
			}
		}
	}
	if !ok || d["synthetic"] != synthetic || d["dataset_id"] != "dual-dataset-"+str(a["input_fingerprint"]) {
		return errors.New("invalid dual dataset")
	}
	sourceList, ok := arr(d["files"])
	if !ok || len(sourceList) != len(refs)+1 {
		return errors.New("invalid dual dataset sources")
	}
	expectedSources := []any{}
	for i, ref := range append(refs, p.Process) {
		kind := "network"
		if i == len(refs) {
			kind = "process"
		}
		file, ok := obj(sourceList[i])
		n, e := s.check(ref)
		size, valid := intValue(file["size_bytes"])
		if !ok || e != nil || !valid || int64(size) != n || file["kind"] != kind || file["sha256"] != ref.SHA {
			return errors.New("dual dataset source mismatch")
		}
		expectedSources = append(expectedSources, map[string]any{"kind": kind, "sha256": ref.SHA, "size_bytes": file["size_bytes"]})
	}
	expectedInput, err := digestValue(expectedSources)
	if err != nil || expectedInput != a["input_fingerprint"] {
		return errors.New("dual input fingerprint mismatch")
	}
	eventHash, err := digestValue(events)
	if err != nil {
		return err
	}
	graphHash, err := digestValue(graph)
	if err != nil {
		return err
	}
	hashes, ok := obj(core["result_hashes"])
	if !ok || len(hashes) != 2 || hashes["events"] != eventHash || hashes["graph"] != graphHash {
		return errors.New("dual result fingerprint mismatch")
	}
	if err := s.validateDualReferences(base, p, a, g); err != nil {
		return err
	}
	_ = wrapper
	return nil
}

// Resolve every source reference against the retained original bytes. This is
// deliberately evidence verification, not an alternate association algorithm.
func (s *Server) validateDualReferences(base string, p Payload, analysis, graph map[string]any) error {
	captures, err := s.dualCaptureFrames(base, p)
	if err != nil {
		return err
	}
	processPath, err := s.file(base + "dual/sources/process.csv")
	if err != nil {
		return err
	}
	processRaw, err := os.ReadFile(processPath)
	if err != nil {
		return err
	}
	processHash := sha256.Sum256(processRaw)
	if hex.EncodeToString(processHash[:]) != p.Process.SHA {
		return errors.New("retained process source changed")
	}
	records := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(processRaw, []byte{0xef, 0xbb, 0xbf})))
	records.FieldsPerRecord = -1
	records.ReuseRecord = false
	table, err := records.ReadAll()
	budget, budgetErr := payloadLimits(p)
	if budgetErr != nil {
		return budgetErr
	}
	maxRows := 1002
	if budget.Version != "" {
		maxRows = budget.ProcessRecords + 1
	}
	if err != nil || len(table) < 2 || len(table) > maxRows || len(table[0]) > budget.ProcessColumns {
		return errors.New("invalid dual process source")
	}
	headers := map[string]int{}
	for i, name := range table[0] {
		if name == "" {
			return errors.New("invalid process header")
		}
		if _, duplicate := headers[name]; duplicate {
			return errors.New("duplicate process header")
		}
		headers[name] = i
	}
	for _, row := range table[1:] {
		if len(row) != len(table[0]) {
			return errors.New("invalid process record width")
		}
	}
	profile, err := s.readDualJSON(base, "dual/sources/profile.json", p)
	if err != nil {
		return err
	}
	config, _ := obj(profile)
	processConfig, _ := obj(config["process"])
	timestampColumn := str(processConfig["timestamp_column"])
	timeIndex, ok := headers[timestampColumn]
	if !ok {
		return errors.New("missing process time column")
	}
	visit := func(value any, callback func(map[string]any) error) error {
		var scan func(any) error
		scan = func(value any) error {
			switch x := value.(type) {
			case map[string]any:
				if _, found := x["file_sha256"]; found {
					if packetTick(x) {
						return verifyPacketTick(x, captures)
					}
					return callback(x)
				}
				for _, v := range x {
					if err := scan(v); err != nil {
						return err
					}
				}
			case []any:
				for _, v := range x {
					if err := scan(v); err != nil {
						return err
					}
				}
			}
			return nil
		}
		return scan(value)
	}
	resolve := func(ref map[string]any) error {
		if len(ref) != 5 || ref["file_sha256"] == nil {
			return errors.New("invalid dual source reference shape")
		}
		if ref["frame_number"] != nil {
			number, ok := intValue(ref["frame_number"])
			frames := captures[str(ref["file_sha256"])]
			if !ok || number < 1 || number > len(frames) || ref["record_number"] != nil || ref["column"] != nil || ref["raw_time"] != frames[number-1].RawTime {
				return errors.New("dual frame reference mismatch")
			}
		} else {
			number, ok := intValue(ref["record_number"])
			if !ok || number < 1 || number >= len(table) || ref["file_sha256"] != p.Process.SHA || ref["raw_time"] != table[number][timeIndex] {
				return errors.New("dual CSV reference mismatch")
			}
			if column := ref["column"]; column != nil {
				if _, ok := headers[str(column)]; !ok {
					return errors.New("dual CSV column missing")
				}
			}
		}
		return nil
	}
	if err := visit(analysis, resolve); err != nil {
		return err
	}
	if err := visit(graph, resolve); err != nil {
		return err
	}
	network, _ := arr(analysis["network"])
	for _, value := range network {
		row, _ := obj(value)
		obs, _ := obj(row["observation"])
		fields, ok := obj(obs["fields"])
		if !ok || len(fields) == 0 {
			return errors.New("dual network fields missing")
		}
		for _, fieldValue := range fields {
			field, ok := obj(fieldValue)
			if !ok {
				return errors.New("invalid dual field")
			}
			slices, ok := arr(field["slices"])
			if !ok || len(slices) == 0 {
				return errors.New("dual field slices missing")
			}
			for _, sliceValue := range slices {
				piece, ok := obj(sliceValue)
				if !ok {
					return errors.New("invalid dual field slice")
				}
				ref, ok := obj(piece["source_ref"])
				if !ok {
					return errors.New("missing dual slice reference")
				}
				frame, ok := intValue(ref["frame_number"])
				frames := captures[str(ref["file_sha256"])]
				if !ok || frame < 1 || frame > len(frames) {
					return errors.New("invalid dual slice frame")
				}
				offset, ok1 := intValue(piece["frame_byte_offset"])
				length, ok2 := intValue(piece["length"])
				if !ok1 || !ok2 || !packetRange(offset, length, len(frames[frame-1].Data)) {
					return errors.New("dual field slice range mismatch")
				}
				original := frames[frame-1].Data[offset : offset+length]
				digest := sha256.Sum256(original)
				if piece["hex"] != hex.EncodeToString(original) || piece["sha256"] != hex.EncodeToString(digest[:]) {
					return errors.New("dual field original bytes mismatch")
				}
			}
		}
	}
	return nil
}

func (s *Server) publishedDual(r *http.Request, id string) (string, Payload, map[string]any, error) {
	st, err := s.Repo.Status(r.Context(), id)
	if err != nil {
		return "", Payload{}, nil, err
	}
	var p Payload
	if err = json.Unmarshal(st.Payload, &p); err != nil {
		return "", p, nil, err
	}
	if st.State != "succeeded" || !dualFamily(p.Kind) || st.ArtifactSHA256 == nil || st.ArtifactPath == nil {
		return "", p, nil, errors.New("dual-source result unavailable")
	}
	if err := s.validHistoricalPayload(p); err != nil {
		return "", p, nil, err
	}
	key, err := jobs.ArtifactKey(jobs.Claim{ID: id, Attempt: st.Attempt}, *st.ArtifactSHA256)
	if err != nil || key != *st.ArtifactPath {
		return "", p, nil, errors.New("published dual attempt identity mismatch")
	}
	base := fmt.Sprintf("jobs/%s/attempt-%d/", id, st.Attempt)
	if _, err = s.check(Ref{Path: key, SHA: *st.ArtifactSHA256}); err != nil {
		return "", p, nil, err
	}
	if _, err = s.check(Ref{Path: base + "manifest.json", SHA: *st.ArtifactSHA256}); err != nil {
		return "", p, nil, err
	}
	publication, err := s.readDualJSON(base, "manifest.json", p)
	if err != nil {
		return "", p, nil, err
	}
	pub, ok := obj(publication)
	if !ok || pub["config_fingerprint"] != p.Fingerprint {
		return "", p, nil, errors.New("published dual configuration mismatch")
	}
	inputs, ok := obj(pub["inputs"])
	inputMap := map[string]string{}
	for k, v := range inputs {
		inputMap[k] = str(v)
	}
	var networks []string
	if v, exists := pub["networks"]; exists {
		rows, yes := arr(v)
		if !yes {
			return "", Payload{}, nil, errors.New("invalid ordered network hashes")
		}
		for _, r := range rows {
			networks = append(networks, str(r))
		}
	}
	if !ok || !publicationInputsMatch(p, inputMap, networks) || ((p.Kind == "dual-source-replay") && pub["replay_version"] != p.ReplayVersion) {
		return "", p, nil, errors.New("published dual input mismatch")
	}
	names := dualArtifactNamesFor(p)
	if p.Kind == "dual-source-replay" {
		names = replayArtifactNamesFor(p)
	}
	entries, ok := arr(pub["artifacts"])
	if !ok || len(entries) != len(names) {
		return "", p, nil, errors.New("published dual artifact count mismatch")
	}
	wrapper := Manifest{Fingerprint: p.Fingerprint, Inputs: map[string]string{"network": p.Network.SHA, "process": p.Process.SHA, "profile": p.Profile.SHA}}
	for _, value := range entries {
		e, ok := obj(value)
		if !ok {
			return "", p, nil, errors.New("invalid dual publication entry")
		}
		name := str(e["path"])
		size, ok := intValue(e["size"])
		if !ok || size < 0 || !validArtifactPath(name, p.Kind) {
			return "", p, nil, errors.New("invalid dual publication path")
		}
		wrapper.Artifacts = append(wrapper.Artifacts, struct {
			Path string `json:"path"`
			SHA  string `json:"sha256"`
			Size int64  `json:"size"`
		}{name, str(e["sha256"]), int64(size)})
	}
	seen := map[string]bool{}
	for _, entry := range wrapper.Artifacts {
		if seen[entry.Path] {
			return "", p, nil, errors.New("duplicate dual artifact")
		}
		seen[entry.Path] = true
		n, err := s.checkArtifact(p, Ref{Path: base + entry.Path, SHA: entry.SHA})
		if err != nil || n != entry.Size {
			return "", p, nil, errors.New("published dual artifact changed: " + entry.Path)
		}
	}
	for _, name := range names {
		if !seen[name] {
			return "", p, nil, errors.New("missing dual published artifact")
		}
	}
	// Only immutable, fully verified publications enter the single-entry cache.
	// Database identity, every input/artifact hash and inventory are still checked
	// on every call above/below; no file stat or cache hit substitutes for bytes.
	cacheKey := base + *st.ArtifactSHA256 + p.ResourceProfile
	cacheEnabled := p.Kind == "dual-source" && p.ResourceProfile != ""
	if cacheEnabled {
		if err := s.dualInventory(base, p); err != nil {
			return "", p, nil, err
		}
		s.dualCacheMu.Lock()
		if s.dualCacheKey == cacheKey && s.dualCacheAnalysis != nil {
			analysis := s.dualCacheAnalysis
			s.dualCacheMu.Unlock()
			return base, p, analysis, nil
		}
		s.dualCacheMu.Unlock()
	}
	corePath, err := s.file(base + "run_manifest.json")
	if err != nil {
		return "", p, nil, err
	}
	coreRaw, err := os.ReadFile(corePath)
	if err != nil {
		return "", p, nil, err
	}
	if p.Kind == "dual-source-replay" {
		_, err = s.validateReplay(base, p, wrapper, coreRaw)
	} else {
		err = s.validateDual(base, p, wrapper, coreRaw)
	}
	if err != nil {
		return "", p, nil, err
	}
	a, err := s.readDualJSON(base, "analysis.json", p)
	if err != nil {
		return "", p, nil, err
	}
	analysis, _ := obj(a)
	if cacheEnabled {
		s.dualCacheMu.Lock()
		s.dualCacheKey, s.dualCacheAnalysis = cacheKey, analysis
		s.dualCacheMu.Unlock()
	}
	return base, p, analysis, nil
}

func (s *Server) serveDual(w http.ResponseWriter, r *http.Request, id, kind string) error {
	base, p, analysis, err := s.publishedDual(r, id)
	if err != nil {
		return err
	}
	if p.Kind != "dual-source" {
		return errors.New("offline result route cannot read replay task")
	}
	if kind == "dual-result" {
		graph, err := s.readDualJSON(base, "graph.json", p)
		if err != nil {
			return err
		}
		events, err := s.readDualJSON(base, "events.json", p)
		if err != nil {
			return err
		}
		quality, err := s.readDualJSON(base, "quality.json", p)
		if err != nil {
			return err
		}
		dataset, err := s.readDualJSON(base, "dataset.json", p)
		if err != nil {
			return err
		}
		response := map[string]any{"synthetic": analysis["synthetic"], "data": map[string]any{"analysis": analysis, "graph": graph, "events": events, "quality": quality, "dataset": dataset}}
		addDualCompatibility(response, analysis)
		reply(w, 200, response)
		return nil
	}
	return s.serveDualEvidence(w, r, base, p, analysis)
}

func (s *Server) serveDualEvidence(w http.ResponseWriter, r *http.Request, base string, p Payload, analysis map[string]any) error {
	var err error
	operation, change := r.URL.Query().Get("operation"), r.URL.Query().Get("change")
	if (operation == "") == (change == "") {
		return errors.New("select exactly one operation or change")
	}
	selected := map[string]any{}
	if operation != "" {
		list, _ := arr(analysis["operations"])
		if operation == "first" && len(list) > 0 {
			first, _ := obj(list[0])
			operation = str(first["operation_id"])
		}
		for _, value := range list {
			row, _ := obj(value)
			if row["operation_id"] == operation {
				selected["operation"] = row
				break
			}
		}
		if selected["operation"] == nil {
			return errors.New("unknown operation")
		}
		candidates, _ := arr(analysis["candidates"])
		changes, _ := arr(analysis["changes"])
		chosen := []any{}
		matched := map[string]bool{}
		for _, value := range candidates {
			row, _ := obj(value)
			if row["operation_id"] == operation {
				chosen = append(chosen, row)
				matched[str(row["change_id"])] = true
			}
		}
		linked := []any{}
		for _, value := range changes {
			row, _ := obj(value)
			if matched[str(row["event_id"])] {
				linked = append(linked, row)
			}
		}
		selected["candidates"] = chosen
		selected["changes"] = linked
	} else {
		list, _ := arr(analysis["changes"])
		if change == "first" && len(list) > 0 {
			first, _ := obj(list[0])
			change = str(first["event_id"])
		}
		for _, value := range list {
			row, _ := obj(value)
			if row["event_id"] == change {
				selected["change"] = row
				break
			}
		}
		findings, _ := arr(analysis["rule_findings"])
		for _, value := range findings {
			row, _ := obj(value)
			if row["finding_id"] == change {
				if selected["change"] != nil || selected["rule_finding"] != nil {
					return errors.New("ambiguous change")
				}
				selected["rule_finding"] = row
			}
		}
		if selected["change"] == nil && selected["rule_finding"] == nil {
			return errors.New("unknown change")
		}
	}
	profile, err := s.readDualJSON(base, "dual/sources/profile.json", p)
	if err != nil {
		return err
	}
	config, _ := obj(profile)
	quality, _ := obj(analysis["quality"])
	// All references were checked against the originals by publishedDual. Return
	// the bounded original frame/CSV rows selected by the user.
	var pages []map[string]int
	if p.ResourceProfile != "" || r.URL.Query().Has("ref_offset") || r.URL.Query().Has("ref_limit") {
		offset, limit := 0, 100
		if r.URL.Query().Has("ref_offset") {
			offset, err = strconv.Atoi(r.URL.Query().Get("ref_offset"))
			if err != nil {
				return errors.New("invalid evidence offset")
			}
		}
		if r.URL.Query().Has("ref_limit") {
			limit, err = strconv.Atoi(r.URL.Query().Get("ref_limit"))
			if err != nil {
				return errors.New("invalid evidence limit")
			}
		}
		if offset < 0 || limit < 1 || limit > 100 {
			return errors.New("evidence page outside budget")
		}
		pages = []map[string]int{{"offset": offset, "limit": limit}}
	}
	originals, fields, err := s.dualEvidence(base, p, analysis, selected, pages...)
	if err != nil {
		return err
	}
	response := map[string]any{"synthetic": analysis["synthetic"], "selection": selected, "time_configuration": config["clocks"], "source_ranges": quality["source_ranges"], "quality": quality, "verified_original_evidence": originals, "verified_network_fields": fields, "config_version": config["config_version"], "config_fingerprint": p.Fingerprint, "limitations": analysis["limitations"]}
	if analysis["analysis_mode"] != nil {
		response["source_provenance"] = analysis["source_provenance"]
	}
	if len(pages) > 0 {
		page := pages[0]
		response["evidence_page"] = map[string]any{"version": "source-reference-page-1", "offset": page["offset"], "limit": page["limit"], "total": page["total"], "returned": len(originals), "has_more": page["offset"]+len(originals) < page["total"], "order": "canonical_source_reference"}
		raw, e := json.Marshal(response)
		if e != nil {
			return e
		}
		if len(raw) > 8<<20 {
			return errors.New("evidence response exceeds 8MiB")
		}
	}
	addDualCompatibility(response, analysis)
	reply(w, 200, response)
	return nil
}

func (s *Server) dualEvidence(base string, p Payload, analysis, selection map[string]any, pages ...map[string]int) ([]any, []any, error) {
	captures, err := s.dualCaptureFrames(base, p)
	if err != nil {
		return nil, nil, err
	}
	processPath, err := s.file(base + "dual/sources/process.csv")
	if err != nil {
		return nil, nil, err
	}
	raw, err := os.ReadFile(processPath)
	if err != nil {
		return nil, nil, err
	}
	processHash := sha256.Sum256(raw)
	if hex.EncodeToString(processHash[:]) != p.Process.SHA {
		return nil, nil, errors.New("retained process source changed")
	}
	records := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(raw, []byte{0xef, 0xbb, 0xbf})))
	records.FieldsPerRecord = -1
	table, err := records.ReadAll()
	if err != nil || len(table) < 2 {
		return nil, nil, errors.New("invalid retained CSV")
	}
	refs := map[string]map[string]any{}
	var visit func(any) error
	visit = func(value any) error {
		switch x := value.(type) {
		case map[string]any:
			if _, ok := x["file_sha256"]; ok {
				if packetTick(x) {
					return verifyPacketTick(x, captures)
				}
				if len(x) != 5 {
					return errors.New("invalid selected reference")
				}
				key, err := pythonCanonical(x)
				if err != nil {
					return err
				}
				refs[string(key)] = x
				return nil
			}
			for _, v := range x {
				if err := visit(v); err != nil {
					return err
				}
			}
		case []any:
			for _, v := range x {
				if err := visit(v); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err = visit(selection); err != nil {
		return nil, nil, err
	}
	keys := make([]string, 0, len(refs))
	for key := range refs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if len(pages) > 0 {
		page := pages[0]
		page["total"] = len(keys)
		offset, limit := page["offset"], page["limit"]
		if offset > len(keys) {
			return nil, nil, errors.New("evidence offset outside selection")
		}
		end := offset + limit
		if end > len(keys) {
			end = len(keys)
		}
		keys = keys[offset:end]
	}
	originals := []any{}
	selectedFrames := map[string]bool{}
	for _, key := range keys {
		ref := refs[key]
		if ref["frame_number"] != nil {
			n, ok := intValue(ref["frame_number"])
			frames := captures[str(ref["file_sha256"])]
			if !ok || n < 1 || n > len(frames) || ref["raw_time"] != frames[n-1].RawTime {
				return nil, nil, errors.New("selected frame reference mismatch")
			}
			selectedFrames[fmt.Sprintf("%s:%d", str(ref["file_sha256"]), n)] = true
			data := frames[n-1].Data
			hash := sha256.Sum256(data)
			originals = append(originals, map[string]any{"source_ref": ref, "original": map[string]any{"frame_number": n, "raw_timestamp": ref["raw_time"], "captured_length": len(data), "frame_sha256": hex.EncodeToString(hash[:]), "raw_hex": hex.EncodeToString(data), "integrity": "file_and_frame_sha256_verified"}})
		} else {
			n, ok := intValue(ref["record_number"])
			if !ok || n < 1 || n >= len(table) || len(table[n]) != len(table[0]) || ref["file_sha256"] != p.Process.SHA {
				return nil, nil, errors.New("selected CSV reference mismatch")
			}
			row := map[string]string{}
			for i, name := range table[0] {
				row[name] = table[n][i]
			}
			originals = append(originals, map[string]any{"source_ref": ref, "original": row})
		}
	}
	fields := []any{}
	network, _ := arr(analysis["network"])
	for _, value := range network {
		item, _ := obj(value)
		event, _ := obj(item["event"])
		obs, _ := obj(item["observation"])
		refs, _ := arr(obs["source_refs"])
		include := false
		for _, value := range refs {
			ref, _ := obj(value)
			n, _ := intValue(ref["frame_number"])
			if selectedFrames[fmt.Sprintf("%s:%d", str(ref["file_sha256"]), n)] {
				include = true
			}
		}
		if !include {
			continue
		}
		named := map[string]any{}
		fieldMap, _ := obj(obs["fields"])
		for name, value := range fieldMap {
			field, _ := obj(value)
			slices, _ := arr(field["slices"])
			resolved := []any{}
			for _, value := range slices {
				piece, _ := obj(value)
				ref, _ := obj(piece["source_ref"])
				n, _ := intValue(ref["frame_number"])
				frames := captures[str(ref["file_sha256"])]
				offset, _ := intValue(piece["frame_byte_offset"])
				length, _ := intValue(piece["length"])
				if n < 1 || n > len(frames) || !packetRange(offset, length, len(frames[n-1].Data)) {
					return nil, nil, errors.New("selected field range mismatch")
				}
				raw := frames[n-1].Data[offset : offset+length]
				hash := sha256.Sum256(raw)
				if piece["hex"] != hex.EncodeToString(raw) || piece["sha256"] != hex.EncodeToString(hash[:]) {
					return nil, nil, errors.New("selected field bytes mismatch")
				}
				resolved = append(resolved, map[string]any{"source_ref": ref, "raw_hex": hex.EncodeToString(frames[n-1].Data), "field": piece, "integrity": "file_and_frame_sha256_verified"})
			}
			named[name] = resolved
		}
		fields = append(fields, map[string]any{"event_id": event["event_id"], "fields": named})
	}
	return originals, fields, nil
}
