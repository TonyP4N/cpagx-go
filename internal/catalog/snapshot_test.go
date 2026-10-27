package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func TestSnapshotBytesHashAndIdentity(t *testing.T) {
	snap := PreflightSnapshot{SchemaVersion: snapshotVersion, Origin: "native", Dataset: SnapshotDataset{ID: "d", SourceKind: "synthetic", Source: "fixture", Batch: "b", AuthorizationRef: "test"}, Files: []SnapshotFile{{DatasetFileID: "f", SourceFileID: "s", Role: "network", Path: "inputs/catalog/d/f.pcap", SHA256: "a", SizeBytes: 1}}, Config: SnapshotConfig{ID: "c", Kind: "intake", Version: 1, Path: "inputs/catalog/d/profiles/c.json", Document: json.RawMessage(`{"dataset_id":"d"}`)}, Manifest: json.RawMessage(`{"files":[]}`)}
	raw, sha, e := snapshotBytes(snap)
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(raw)
	if sha != hex.EncodeToString(sum[:]) {
		t.Fatal("snapshot hash did not cover exact bytes")
	}
	parsed, e := parseSnapshot(raw, sha, "native")
	if e != nil || !sameSnapshotInputs(snap, parsed) {
		t.Fatalf("round trip failed: %v", e)
	}
	changed := append([]byte(nil), raw...)
	changed[len(changed)-2] ^= 1
	if _, e = parseSnapshot(changed, sha, "native"); e == nil {
		t.Fatal("tampered snapshot accepted")
	}
	parsed.Origin = "reconstructed"
	if !sameSnapshotInputs(snap, parsed) {
		t.Fatal("origin alone changed fixed inputs")
	}
	parsed.Config.Document = json.RawMessage("{ \"dataset_id\" : \"d\" }")
	if !sameSnapshotInputs(snap, parsed) {
		t.Fatal("insignificant JSON spacing changed fixed config")
	}
	parsed.Files[0].DatasetFileID = "different"
	if sameSnapshotInputs(snap, parsed) {
		t.Fatal("file identity change ignored")
	}
}
func TestReadyPreflightRequiresNoGaps(t *testing.T) {
	report := map[string]any{"status": "ready_for_manual_review", "source_scope": "dual_source", "input_fingerprint": "abc", "errors": []any{}, "material_gaps": []any{}}
	if !readyPreflight(report) {
		t.Fatal("ready report rejected")
	}
	report["material_gaps"] = []any{"authorization"}
	if readyPreflight(report) {
		t.Fatal("material gap accepted")
	}
	report["material_gaps"] = []any{}
	report["errors"] = []any{"batch_conflict"}
	if readyPreflight(report) {
		t.Fatal("batch conflict accepted")
	}
}
func TestConfigJSONRejectsDuplicateKeys(t *testing.T) {
	if validateUniqueJSON([]byte(`{"a":{"b":1,"b":2}}`)) == nil {
		t.Fatal("nested duplicate key accepted")
	}
	if validateUniqueJSON([]byte(`{"a":[{"b":1},{"b":2}]}`)) != nil {
		t.Fatal("same key in separate objects rejected")
	}
}
func TestBackfillSummaryReportsUnresolvedHistory(t *testing.T) {
	if (BackfillSummary{ReconstructedPreflights: 2, MatchedLegacyRuns: 1}).HasUnresolved() {
		t.Fatal("verified backfill marked unresolved")
	}
	if !(BackfillSummary{UnreconstructablePreflights: 1}).HasUnresolved() {
		t.Fatal("unreconstructable report silently succeeded")
	}
	if !(BackfillSummary{UnboundLegacyRuns: 1}).HasUnresolved() {
		t.Fatal("unbound legacy run silently succeeded")
	}
}
func TestRetainedReportSemanticComparison(t *testing.T) {
	if !sameReport([]byte(`{"status":"material_gaps","errors":[]}`), []byte(`{"errors":[],"status":"material_gaps"}`)) {
		t.Fatal("equivalent jsonb report treated as altered")
	}
	if sameReport([]byte(`{"status":"material_gaps","material_gaps":["authorization"]}`), []byte(`{"status":"ready_for_manual_review","material_gaps":[]}`)) {
		t.Fatal("forged ready report accepted")
	}
}
