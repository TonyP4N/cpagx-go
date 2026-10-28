package jobapi

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDualAnalysisVersionReadAndPublicationPolicy(t *testing.T) {
	bounded := map[string]any{"analysis_mode": "bounded-real-capable-v1"}
	legacy := map[string]any{"synthetic": true}
	for _, version := range []string{historicalBoundedAnalysisVersion, currentBoundedAnalysisVersion} {
		if got, e := dualAnalysisVersion(bounded, version); e != nil || got != version {
			t.Fatalf("retained %s: %s %v", version, got, e)
		}
	}
	if got, e := dualAnalysisVersion(legacy, "synthetic-dual-source-1"); e != nil || got != "synthetic-dual-source-1" {
		t.Fatal(got, e)
	}
	for _, tc := range []struct {
		profile map[string]any
		version any
	}{{bounded, "bounded-dual-source-3"}, {bounded, "synthetic-dual-source-1"}, {legacy, currentBoundedAnalysisVersion}, {bounded, nil}, {bounded, 1}} {
		if _, e := dualAnalysisVersion(tc.profile, tc.version); e == nil {
			t.Fatalf("unsupported version accepted: %#v", tc.version)
		}
	}
	if e := validateDualPublicationVersion(historicalBoundedAnalysisVersion, false); e == nil {
		t.Fatal("new v1 publication accepted")
	}
	for _, tc := range []struct {
		version   string
		completed bool
	}{{historicalBoundedAnalysisVersion, true}, {currentBoundedAnalysisVersion, false}, {"synthetic-dual-source-1", false}} {
		if e := validateDualPublicationVersion(tc.version, tc.completed); e != nil {
			t.Fatal(e)
		}
	}
	if e := validateDualPublicationVersion("unknown", true); e == nil {
		t.Fatal("unknown completed version accepted")
	}
}

func TestHistoricalDualResponseCompatibilityMetadata(t *testing.T) {
	analysis := map[string]any{"analysis_version": historicalBoundedAnalysisVersion, "candidates": []any{"unchanged"}}
	response := map[string]any{"data": analysis}
	addDualCompatibility(response, analysis)
	metadata, ok := response["compatibility"].(map[string]any)
	if !ok || metadata["analysis_version"] != historicalBoundedAnalysisVersion || metadata["status"] != "historical_semantics" || metadata["reanalysis_required"] != true {
		t.Fatal(metadata)
	}
	limitations, ok := metadata["known_limitations"].([]string)
	if !ok || len(limitations) != 1 || limitations[0] != "response_clock_quality_not_enforced" {
		t.Fatal(limitations)
	}
	if _, exists := analysis["compatibility"]; exists {
		t.Fatal("retained analysis was rewritten")
	}
	current := map[string]any{}
	addDualCompatibility(current, map[string]any{"analysis_version": currentBoundedAnalysisVersion})
	if _, exists := current["compatibility"]; exists {
		t.Fatal("current version incorrectly marked historical")
	}
}

// The fixture is the byte-preserved pre-fix result, never regenerated using the
// current algorithm and never relabelled as version 2.
func TestRetainedBoundedV1FixtureReadAndEvidenceCompatibility(t *testing.T) {
	fixture := filepath.Join("..", "..", "tests", "fixtures", "r17-response-clock-v1")
	raw, e := os.ReadFile(filepath.Join(fixture, "run_manifest.json"))
	if e != nil {
		t.Fatal(e)
	}
	value, e := parseValue(raw)
	if e != nil {
		t.Fatal(e)
	}
	core, _ := obj(value)
	id := str(core["run_id"])
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	base := "jobs/" + id + "/attempt-1/"
	e = filepath.WalkDir(fixture, func(path string, entry os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(fixture, path)
		if e != nil {
			return e
		}
		target := filepath.Join(root, base, rel)
		if entry.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		bytes, e := os.ReadFile(path)
		if e != nil {
			return e
		}
		return os.WriteFile(target, bytes, 0600)
	})
	if e != nil {
		t.Fatal(e)
	}
	input := filepath.Join(root, "inputs")
	if e = os.Mkdir(input, 0700); e != nil {
		t.Fatal(e)
	}
	ref := func(name string) Ref {
		bytes, e := os.ReadFile(filepath.Join(fixture, "dual/sources", name))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(input, name), bytes, 0600); e != nil {
			t.Fatal(e)
		}
		return Ref{Path: "inputs/" + name, SHA: shaBytes(bytes)}
	}
	p := Payload{Kind: "dual-source", Network: ref("network.pcap"), Process: ref("process.csv"), Profile: ref("profile.json"), Fingerprint: str(core["config_fingerprint"])}
	p.Networks = []Ref{p.Network, ref("network-001.pcap")}
	s := &Server{Root: root}
	if e = s.validateDual(base, p, Manifest{}, raw); e != nil {
		t.Fatalf("retained v1 fixture rejected: %v", e)
	}
	v, e := s.readDualJSON(base, "analysis.json")
	if e != nil {
		t.Fatal(e)
	}
	analysis, _ := obj(v)
	req := httptest.NewRequest("GET", "/v1/jobs/"+id+"/dual-evidence?operation=first", nil)
	rec := httptest.NewRecorder()
	if e = s.serveDualEvidence(rec, req, base, p, analysis); e != nil {
		t.Fatal(e)
	}
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	var response map[string]any
	if e = json.Unmarshal(rec.Body.Bytes(), &response); e != nil {
		t.Fatal(e)
	}
	compatibility, _ := obj(response["compatibility"])
	if compatibility["reanalysis_required"] != true || compatibility["status"] != "historical_semantics" {
		t.Fatal("historical evidence response missing explicit warning")
	}
	// Explicit pages preserve exactly the original reference order and bytes.
	originals, _ := arr(response["verified_original_evidence"])
	for offset, want := range originals {
		req = httptest.NewRequest("GET", fmt.Sprintf("/evidence?operation=first&ref_offset=%d&ref_limit=1", offset), nil)
		rec = httptest.NewRecorder()
		if e = s.serveDualEvidence(rec, req, base, p, analysis); e != nil {
			t.Fatal(e)
		}
		var page map[string]any
		if e = json.Unmarshal(rec.Body.Bytes(), &page); e != nil {
			t.Fatal(e)
		}
		rows, _ := arr(page["verified_original_evidence"])
		if len(rows) != 1 || !sameJSON(rows[0], want) {
			t.Fatal("page differs from original evidence")
		}
		meta, _ := obj(page["evidence_page"])
		if meta["total"] != float64(len(originals)) || meta["has_more"] != (offset+1 < len(originals)) {
			t.Fatal(meta)
		}
	}
	for _, query := range []string{"ref_limit=101", "ref_limit=0", "ref_offset=-1", "ref_offset=999999"} {
		req = httptest.NewRequest("GET", "/evidence?operation=first&"+query, nil)
		if e = s.serveDualEvidence(httptest.NewRecorder(), req, base, p, analysis); e == nil {
			t.Fatal("invalid page accepted", query)
		}
	}
	// Even a declared version typo is rejected instead of falling back to old or new semantics.
	dm, e := s.readDualJSON(base, "dual/manifest.json")
	if e != nil {
		t.Fatal(e)
	}
	manifest, _ := obj(dm)
	for _, version := range []string{"unknown", currentBoundedAnalysisVersion} {
		manifest["analysis_version"] = version
		changed, _ := json.Marshal(manifest)
		if e = os.WriteFile(filepath.Join(root, base, "dual/manifest.json"), changed, 0600); e != nil {
			t.Fatal(e)
		}
		if e = s.validateDual(base, p, Manifest{}, raw); e == nil {
			t.Fatalf("unknown or mixed manifest version %q accepted", version)
		}
	}
}
