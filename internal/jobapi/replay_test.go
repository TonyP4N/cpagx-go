package jobapi

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Replay fixtures use only the standard Python library. CI must execute them,
// even when a developer's optional .venv does not exist.
func replayPython(t *testing.T, repo string) string {
	t.Helper()
	candidate := os.Getenv("CPAG_TEST_PYTHON")
	if candidate == "" {
		candidate = filepath.Join(repo, ".venv/bin/python")
		if _, err := os.Stat(candidate); err != nil {
			candidate = "python3"
		}
	}
	python, err := exec.LookPath(candidate)
	if err != nil {
		t.Fatalf("Python 3 is required for replay contract fixtures: %v", err)
	}
	return python
}

func TestReplayExportProjectionAndHistoricalEvidence(t *testing.T) {
	repo, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	python := replayPython(t, repo)
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	script := `from pathlib import Path
import json,sys
from round18_profile import fixture
from cpag_core.replay_export import export_task
root=Path(sys.argv[1]);n,p,c,_=fixture(root/'inputs')
export_task(n,p,c,root/'jobs/replay/attempt-1',run_id='replay',attempt_id=1)
(root/'refs.json').write_text(json.dumps({'networks':[str(x.relative_to(root)) for x in n],'process':str(p.relative_to(root)),'profile':str(c.relative_to(root))}))`
	cmd := exec.Command(python, "-c", script, root)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "services/analysis/src")+":"+filepath.Join(repo, "scripts/validation"))
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("replay export: %v: %s", e, out)
	}
	var paths struct {
		Networks []string `json:"networks"`
		Process  string   `json:"process"`
		Profile  string   `json:"profile"`
	}
	raw, _ := os.ReadFile(filepath.Join(root, "refs.json"))
	if e = json.Unmarshal(raw, &paths); e != nil {
		t.Fatal(e)
	}
	ref := func(path string) Ref {
		raw, e := os.ReadFile(filepath.Join(root, path))
		if e != nil {
			t.Fatal(e)
		}
		return Ref{path, bytesSHA(raw)}
	}
	p := Payload{Kind: "dual-source-replay", ReplayVersion: ReplayVersion, Network: ref(paths.Networks[0]), Process: ref(paths.Process), Profile: ref(paths.Profile)}
	for _, path := range paths.Networks {
		p.Networks = append(p.Networks, ref(path))
	}
	raw, _ = os.ReadFile(filepath.Join(root, p.Profile.Path))
	p.Fingerprint, e = DualProfileFingerprint(raw)
	if e != nil {
		t.Fatal(e)
	}
	s := &Server{Root: root}
	if e = s.validPayload(p); e != nil {
		t.Fatal(e)
	}
	base := "jobs/replay/attempt-1/"
	coreRaw, _ := os.ReadFile(filepath.Join(root, base, "run_manifest.json"))
	data, e := s.validateReplay(base, p, Manifest{}, coreRaw)
	if e != nil {
		t.Fatal(e)
	}
	if len(data.Snapshots) < 3 || len(data.Revisions) == 0 {
		t.Fatal("missing immutable replay history")
	}
	pending := -1
	for i, snapshot := range data.Snapshots {
		a, _ := obj(snapshot["analysis"])
		ops, _ := arr(a["operations"])
		if len(ops) > 0 {
			op, _ := obj(ops[0])
			state, _ := obj(op["replay"])
			if state["status"] == "pending_response" {
				pending = i
				break
			}
		}
	}
	if pending < 0 {
		t.Fatal("no retained pending response snapshot")
	}
	snapshot := data.Snapshots[pending]
	analysis, _ := obj(snapshot["analysis"])
	req := httptest.NewRequest("GET", "/v1/jobs/replay/replay-evidence?revision=0&operation=first", nil)
	rec := httptest.NewRecorder()
	if e = s.serveReplayEvidence(rec, req, data, snapshot, analysis, pending); e != nil {
		t.Fatal(e)
	}
	if rec.Code != 200 {
		t.Fatal(rec.Code)
	}
	var response map[string]any
	if e = json.Unmarshal(rec.Body.Bytes(), &response); e != nil {
		t.Fatal(e)
	}
	originals, _ := arr(response["verified_original_evidence"])
	if len(originals) == 0 {
		t.Fatal("pending evidence missing")
	}
	for _, v := range originals {
		row, _ := obj(v)
		r, _ := obj(row["source_ref"])
		if r["file_sha256"] != nil || r["source_slot"] == "network-1" {
			t.Fatal("pending snapshot leaked future response or full file identity")
		}
	}
	// Self-rehashed graph/analysis cannot substitute a claim unsupported by its operation and change originals.
	altered, _ := obj(normalizedJSON(data.Analysis))
	candidates, _ := arr(altered["candidates"])
	if len(candidates) == 0 {
		t.Fatal("normal replay candidate missing")
	}
	candidate, _ := obj(candidates[0])
	claim, _ := obj(candidate["claim"])
	claim["evidence_refs"] = []any{}
	tool, _ := obj(data.Core["tool_versions"])
	if _, _, e = replayProjection(altered, data.Profile, str(tool["core"])); e == nil {
		t.Fatal("self-rehashed unsupported replay claim accepted")
	}
	// Every retained record remains bound to its original logical-record bytes.
	path := filepath.Join(root, base, "sources/network-001.pcap")
	if e = os.WriteFile(path, []byte("changed"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.validateReplay(base, p, Manifest{}, coreRaw); e == nil {
		t.Fatal("changed retained replay original accepted")
	}
}

func TestReplayCSVOriginalPreservesQuotedCRLF(t *testing.T) {
	raw := []byte("\xef\xbb\xbftime,note\r\n")
	header, e := replayCSVValues(raw, true)
	if e != nil || len(header) != 2 || header[0] != "time" {
		t.Fatal(header, e)
	}
	values, e := replayCSVValues([]byte("2026-01-01T00:00:10Z,\"one\r\ntwo\"\r\n"), false)
	if e != nil || values[1] != "one\r\ntwo" {
		t.Fatal("original multiline bytes normalized", values, e)
	}
}

func replayLateFixture(t *testing.T) (string, Payload) {
	t.Helper()
	repo, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	python := replayPython(t, repo)
	root, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	script := `from pathlib import Path
import json,sys
from round18_profile import fixture,at
from cpag_core.replay_export import export_task
root=Path(sys.argv[1]);n,p,c,config=fixture(root/'inputs')
seq=[s for s in config['replay']['sequence'] if s.get('kind') not in ('source_eof','advance')]
keep=[s for s in seq if not(s.get('source_slot')=='process' and s.get('record_number',0)>=4)]
keep += [{'kind':'advance','available_at':at(18)}]
keep += [{'source_slot':'process','record_number':4,'available_at':at(19)},{'source_slot':'process','record_number':5,'available_at':at(20)},{'source_slot':'process','record_number':6,'available_at':at(21)}]
keep += [{'kind':'source_eof','source_slot':slot,'available_at':at(22)} for slot in ('network-0','network-1','process')]
config['replay']['sequence']=keep;config['replay']['finish_at']=at(23);c.write_text(json.dumps(config))
export_task(n,p,c,root/'jobs/replay/attempt-1',run_id='replay',attempt_id=1)
(root/'refs.json').write_text(json.dumps({'networks':[str(x.relative_to(root)) for x in n],'process':str(p.relative_to(root)),'profile':str(c.relative_to(root))}))`
	cmd := exec.Command(python, "-c", script, root)
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "services/analysis/src")+":"+filepath.Join(repo, "scripts/validation"))
	if out, e := cmd.CombinedOutput(); e != nil {
		t.Fatalf("late replay fixture: %v: %s", e, out)
	}
	var paths struct {
		Networks []string `json:"networks"`
		Process  string   `json:"process"`
		Profile  string   `json:"profile"`
	}
	raw, _ := os.ReadFile(filepath.Join(root, "refs.json"))
	if e = json.Unmarshal(raw, &paths); e != nil {
		t.Fatal(e)
	}
	ref := func(path string) Ref {
		raw, e := os.ReadFile(filepath.Join(root, path))
		if e != nil {
			t.Fatal(e)
		}
		return Ref{path, bytesSHA(raw)}
	}
	p := Payload{Kind: "dual-source-replay", ReplayVersion: ReplayVersion, Network: ref(paths.Networks[0]), Process: ref(paths.Process), Profile: ref(paths.Profile)}
	for _, path := range paths.Networks {
		p.Networks = append(p.Networks, ref(path))
	}
	raw, _ = os.ReadFile(filepath.Join(root, p.Profile.Path))
	p.Fingerprint, e = DualProfileFingerprint(raw)
	if e != nil {
		t.Fatal(e)
	}
	return root, p
}

func TestReplayTriggerEvidenceIncludesDiscardedRecordAndRejectsFuture(t *testing.T) {
	root, p := replayLateFixture(t)
	s := &Server{Root: root}
	base := "jobs/replay/attempt-1/"
	raw, _ := os.ReadFile(filepath.Join(root, base, "run_manifest.json"))
	data, e := s.validateReplay(base, p, Manifest{}, raw)
	if e != nil {
		t.Fatal(e)
	}
	var snapshot map[string]any
	for _, row := range data.Snapshots {
		if row["status"] == "too_late" {
			snapshot = row
			break
		}
	}
	if snapshot == nil {
		t.Fatal("independent late fixture did not discard a record")
	}
	analysis, _ := obj(snapshot["analysis"])
	trigger, _ := obj(snapshot["trigger"])
	refs, _ := arr(trigger["evidence_refs"])
	if len(refs) == 0 {
		t.Fatal("discarded record trigger missing")
	}
	ref, _ := obj(refs[0])
	number, _ := intValue(ref["record_number"])
	process, _ := arr(analysis["process"])
	for _, v := range process {
		row, _ := obj(v)
		event, _ := obj(row["event"])
		eventRef, _ := obj(event["source_ref"])
		if eventRef["source_slot"] == ref["source_slot"] && eventRef["record_number"] == ref["record_number"] {
			t.Fatal("discarded record unexpectedly became a process event")
		}
	}
	n, _ := intValue(snapshot["snapshot_number"])
	request := httptest.NewRequest("GET", "/v1/jobs/replay/replay-evidence?revision=0&trigger=true", nil)
	response := httptest.NewRecorder()
	if e = s.serveReplayEvidence(response, request, data, snapshot, analysis, n); e != nil {
		t.Fatal(e)
	}
	var value map[string]any
	if e = json.Unmarshal(response.Body.Bytes(), &value); e != nil {
		t.Fatal(e)
	}
	selection, _ := obj(value["selection"])
	if selection["trigger"] == nil {
		t.Fatal("trigger selection not returned")
	}
	originals, _ := arr(value["verified_original_evidence"])
	if len(originals) == 0 || number != 4 {
		t.Fatal("discarded original was not returned")
	}
	for _, query := range []string{"trigger=false", "trigger=", "trigger=TRUE", "trigger=true&operation=first", "trigger=true&change=first", "trigger=true&trigger=false"} {
		r := httptest.NewRequest("GET", "/v1/jobs/replay/replay-evidence?revision=0&"+query, nil)
		if e = s.serveReplayEvidence(httptest.NewRecorder(), r, data, snapshot, analysis, n); e == nil {
			t.Fatalf("invalid selector accepted: %s", query)
		}
	}
	// The client cannot supply references. Even a corrupted retained trigger must
	// not cause a not-yet-arrived original to be disclosed by this resolver.
	future := data.Originals.Records[replayRecordKey("process", 6)]
	changed, _ := obj(normalizedJSON(snapshot))
	changed["trigger"] = map[string]any{"evidence_refs": []any{normalizedJSON(map[string]any{"source_slot": "process", "record_sha256": bytesSHA(future.Record), "frame_number": nil, "record_number": 6, "column": nil, "raw_time": nil})}}
	if e = s.serveReplayEvidence(httptest.NewRecorder(), request, data, changed, analysis, n); e == nil {
		t.Fatal("trigger disclosed a future raw record")
	}
}
