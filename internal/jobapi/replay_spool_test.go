package jobapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSpoolBridgeOutputIsBoundedWithIOCopy(t *testing.T) {
	out := &boundedCLIOutput{maximum: 32}
	_, err := io.Copy(out, strings.NewReader(strings.Repeat("x", 33)))
	if err == nil || out.Len() > 32 {
		t.Fatalf("io.Copy bypassed bounded writer: %d %v", out.Len(), err)
	}
}

func TestSpoolFormatIsExplicitAndOldInventoryIsUnchanged(t *testing.T) {
	for _, bad := range []any{"", nil, "future-history", true} {
		if _, _, err := replayProfileSchema(map[string]any{"replay": map[string]any{"history_format": bad}}); err == nil {
			t.Fatalf("unsupported format %v accepted", bad)
		}
	}
	old := Payload{Kind: "dual-source-replay"}
	current := old
	current.HistoryFormat = ReplaySpoolFormat
	contains := func(rows []string, value string) bool {
		for _, row := range rows {
			if row == value {
				return true
			}
		}
		return false
	}
	if !contains(replayArtifactNamesFor(old), "snapshots.jsonl") || contains(replayArtifactNamesFor(old), "history/history.sqlite3") {
		t.Fatal("old inventory changed")
	}
	if contains(replayArtifactNamesFor(current), "snapshots.jsonl") || !contains(replayArtifactNamesFor(current), "history/history.sqlite3") {
		t.Fatal("explicit spool inventory not selected")
	}
	if validPayloadArtifactPath(old, "history/history.sqlite3") || validPayloadArtifactPath(current, "snapshots.jsonl") || validPayloadArtifactPath(current, "history/../analysis.json") {
		t.Fatal("mixed history or unsafe path accepted")
	}
}

func TestSpoolInventoryRejectsTargetOutputPlusOneBeforeParsing(t *testing.T) {
	root, _ := filepath.EvalSymlinks(t.TempDir())
	base := "jobs/spool/attempt-1/"
	p := Payload{Kind: "dual-source-replay", ReplayVersion: ReplayVersion, HistoryFormat: ReplaySpoolFormat, CapacityProfile: "engineering-capacity-1", ResourceProfile: "engineering-capacity-1"}
	for _, name := range replayArtifactNamesFor(p) {
		path := filepath.Join(root, base, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, base, "history/history.sqlite3")
	file, err := os.OpenFile(path, os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	s := &Server{Root: root, ResourceProfile: "engineering-capacity-1"}
	// Sparse metadata exercises the real byte guard without allocating GiB RAM
	// or presenting this inventory-only case as a valid analysis publication.
	if err = file.Truncate(1 << 30); err != nil {
		t.Fatal(err)
	}
	if err = s.spoolInventory(base, p); err != nil {
		t.Fatalf("inventory byte-boundary check: %v", err)
	}
	if err = file.Truncate((1 << 30) + 1); err != nil {
		t.Fatal(err)
	}
	if err = s.spoolInventory(base, p); err == nil {
		t.Fatal("target output +1 byte accepted")
	}
}

func TestSpoolBridgeCleansPrivateTemporaryDataAfterDeadline(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := "jobs/spool/attempt-1"
	if err = os.MkdirAll(filepath.Join(root, base), 0700); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(root, "test-module/cpag_core")
	if err = os.MkdirAll(module, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(module, "__init__.py"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "temporary-path.json")
	markerJSON, _ := json.Marshal(marker)
	script := "import json,os,pathlib,time\np=pathlib.Path(os.environ['TMPDIR'])\n(p/'interrupted.sqlite3').write_bytes(b'partial verification')\npathlib.Path(" + string(markerJSON) + ").write_text(json.dumps(str(p)))\ntime.sleep(60)\n"
	if err = os.WriteFile(filepath.Join(module, "replay_spool_cli.py"), []byte(script), 0600); err != nil {
		t.Fatal(err)
	}
	s := &Server{Root: root, ControlRoot: filepath.Join(root, "private-control"), PythonBin: python, PythonPath: filepath.Dir(module)}
	if _, err = s.spoolCLI(context.Background(), base, "verify", time.Second); err == nil || !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("bridge deadline not enforced: %v", err)
	}
	raw, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal("temporary-writing child never started", err)
	}
	var scratch string
	if err = json.Unmarshal(raw, &scratch); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(scratch, filepath.Join(s.ControlRoot, "spool-bridge")) {
		t.Fatal("child temporary path escaped trusted control root")
	}
	if _, err = os.Stat(scratch); !os.IsNotExist(err) {
		t.Fatalf("killed child temporary SQLite retained: %v", err)
	}
}

func TestSpoolCoreBridgeUsesRealExportAndRejectsChangedFiles(t *testing.T) {
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	python := filepath.Join(repo, ".venv/bin/python")
	if _, err = os.Stat(python); err != nil {
		python, err = exec.LookPath("python3")
		if err != nil {
			t.Fatal("Python runtime required for real spool contract verification")
		}
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	script := `from pathlib import Path
import json,sys
from round18_profile import fixture
from cpag_core.replay_export import export_task
root=Path(sys.argv[1]); networks,process,path,profile=fixture(root/'inputs')
profile['replay']['history_format']='replay-history-checkpoint-delta-2'
path.write_text(json.dumps(profile))
export_task(networks,process,path,root/'jobs/spool/attempt-2',run_id='spool',attempt_id=2)
(root/'fixture.json').write_text(json.dumps({'networks':[str(p.relative_to(root)) for p in networks],'process':str(process.relative_to(root)),'profile':str(path.relative_to(root))}))`
	cmd := exec.Command(python, "-c", script, root)
	cmd.Dir = repo
	pythonPath := filepath.Join(repo, "services/analysis/src") + string(os.PathListSeparator) + filepath.Join(repo, "scripts/validation")
	cmd.Env = append(os.Environ(), "PYTHONPATH="+pythonPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("spool fixture export failed: %v %s", err, output)
	}
	metaRaw, err := os.ReadFile(filepath.Join(root, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var meta struct {
		Networks         []string `json:"networks"`
		Process, Profile string
	}
	if err = json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatal(err)
	}
	ref := func(name string) Ref {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		sha := sha256.Sum256(raw)
		return Ref{Path: name, SHA: hex.EncodeToString(sha[:])}
	}
	profileRaw, err := os.ReadFile(filepath.Join(root, meta.Profile))
	if err != nil {
		t.Fatal(err)
	}
	fp, err := DualProfileFingerprint(profileRaw)
	if err != nil {
		t.Fatal(err)
	}
	p := Payload{Kind: "dual-source-replay", ReplayVersion: ReplayVersion, HistoryFormat: ReplaySpoolFormat, Fingerprint: fp, Process: ref(meta.Process), Profile: ref(meta.Profile)}
	for _, name := range meta.Networks {
		p.Networks = append(p.Networks, ref(name))
	}
	p.Network = p.Networks[0]
	s := &Server{Root: root, PythonBin: python, PythonPath: pythonPath}
	if err = s.validPayload(p); err != nil {
		t.Fatalf("explicit spool payload: %v", err)
	}
	profileValue, err := parseValue(profileRaw)
	if err != nil {
		t.Fatal(err)
	}
	profileDoc, _ := obj(profileValue)
	options, _ := obj(profileDoc["replay"])
	options["max_snapshots"] = json.Number("4097")
	if err = validateReplayProfile(profileDoc, ReplayVersion); err == nil {
		t.Fatal("new storage silently raised old capacity budget")
	}
	profileDoc["capacity_profile"] = "engineering-capacity-1"
	if err = validateReplayProfile(profileDoc, ReplayVersion); err != nil {
		t.Fatalf("explicit capacity+storage version not admitted: %v", err)
	}
	delete(profileDoc, "capacity_profile")
	options["max_snapshots"] = json.Number("4096")
	bad := p
	bad.HistoryFormat = ""
	if err = s.validPayload(bad); err == nil {
		t.Fatal("new profile accepted as old history payload")
	}
	base := "jobs/spool/attempt-2/"
	coreRaw, err := os.ReadFile(filepath.Join(root, base, "run_manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	verified, err := s.validateSpoolReplay(context.Background(), base, p, Manifest{}, coreRaw)
	if err != nil {
		t.Fatalf("real spool validation failed: %v", err)
	}
	count, ok := intValue(verified.History["snapshot_count"])
	if !ok || count < 2 {
		t.Fatal("spool history count unavailable")
	}
	for _, test := range []struct{ kind, path string }{
		{"replay-result", "?"}, {"replay-snapshot", "?revision=0"}, {"replay-revisions", "?after=0&limit=2"},
		{"replay-evidence", "?revision=" + itoa(count-1) + "&operation=first"},
	} {
		req := httptest.NewRequest("GET", "http://local/"+test.path, nil)
		rec := httptest.NewRecorder()
		if err = s.serveSpoolReplay(rec, req, base, p, test.kind); err != nil {
			t.Fatalf("%s: %v", test.kind, err)
		}
		if rec.Code != 200 || !json.Valid(rec.Body.Bytes()) {
			t.Fatalf("%s invalid response", test.kind)
		}
	}
	for _, query := range []string{"?revision=0&operation=--help", "?revision=0&operation=first&trigger=true", "?after=0&limit=101"} {
		req := httptest.NewRequest("GET", "http://local/"+query, nil)
		rec := httptest.NewRecorder()
		kind := "replay-evidence"
		if strings.Contains(query, "after=") {
			kind = "replay-revisions"
		}
		if err = s.serveSpoolReplay(rec, req, base, p, kind); err == nil || rec.Body.Len() != 0 {
			t.Fatal("invalid spool selector/page produced a response")
		}
	}
	if _, err = s.spoolCLI(context.Background(), base, "arbitrary-command", time.Second); err == nil {
		t.Fatal("unlisted CLI action accepted")
	}
	path := filepath.Join(root, base, "history/history.sqlite3")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := append([]byte(nil), original...)
	changed[len(changed)-1] ^= 1
	if err = os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = s.validateSpoolReplay(context.Background(), base, p, Manifest{}, coreRaw); err == nil {
		t.Fatal("same-size SQLite tampering accepted")
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.validateSpoolReplay(context.Background(), base, p, Manifest{}, coreRaw); err == nil {
		t.Fatal("missing SQLite accepted")
	}
}

func itoa(n int) string { return fmt.Sprint(n) }
