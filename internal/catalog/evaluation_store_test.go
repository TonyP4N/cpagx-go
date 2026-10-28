package catalog

import (
	"bytes"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

type evaluationSavedRow struct {
	savedEvaluation
	Document string
}
type evaluationTx struct{ c *evaluationConn }

func (t evaluationTx) Commit() error {
	t.c.state.Saved = t.c.pending
	t.c.state.Prepared = t.c.pendingPreparation
	t.c.transaction = false
	return nil
}
func (t evaluationTx) Rollback() error {
	t.c.pending = nil
	t.c.pendingPreparation = nil
	t.c.transaction = false
	return nil
}
func (c *evaluationConn) evaluationQuery(q string, args []driver.NamedValue) (driver.Rows, error) {
	saved := c.state.Saved
	if c.transaction {
		saved = c.pending
	}
	switch {
	case strings.HasPrefix(q, "INSERT INTO v3_evaluations"):
		if !c.transaction {
			return nil, fmt.Errorf("insert outside transaction")
		}
		if saved != nil {
			return &runBindingRows{columns: []string{"id", "created"}}, nil
		}
		row := &evaluationSavedRow{savedEvaluation: savedEvaluation{ID: args[0].Value.(string), JobID: args[1].Value.(string), DatasetID: args[2].Value.(string), SHA: args[4].Value.(string), CreatedBy: args[5].Value.(string), CreatedAt: time.Now()}, Document: args[3].Value.(string)}
		c.pending = row
		return &runBindingRows{[]string{"id", "created"}, [][]driver.Value{{row.ID, row.CreatedAt}}}, nil
	case strings.HasPrefix(q, "SELECT id,created_at,created_by"):
		if saved == nil {
			return &runBindingRows{columns: []string{"id", "created", "user"}}, nil
		}
		return &runBindingRows{[]string{"id", "created", "user"}, [][]driver.Value{{saved.ID, saved.CreatedAt, saved.CreatedBy}}}, nil
	case strings.Contains(q, "document_json FROM v3_evaluations"):
		rows := &runBindingRows{columns: []string{"id", "job", "dataset", "sha", "user", "created", "document"}}
		if saved != nil && args[0].Value == saved.ID && args[1].Value == saved.JobID && args[2].Value == saved.DatasetID {
			rows.values = [][]driver.Value{{saved.ID, saved.JobID, saved.DatasetID, saved.SHA, saved.CreatedBy, saved.CreatedAt, saved.Document}}
		}
		return rows, nil
	case strings.Contains(q, "ORDER BY created_at"):
		rows := &runBindingRows{columns: []string{"id", "job", "dataset", "sha", "user", "created"}}
		if saved != nil {
			rows.values = [][]driver.Value{{saved.ID, saved.JobID, saved.DatasetID, saved.SHA, saved.CreatedBy, saved.CreatedAt}}
		}
		return rows, nil
	default:
		return nil, fmt.Errorf("unexpected saved evaluation query: %s", q)
	}
}
func evaluationStoreRequest(s *Server, method, path string, body []byte, p *principal) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/v3/runs/run/"+path, bytes.NewReader(body))
	w := httptest.NewRecorder()
	parts := strings.Split(strings.Split("runs/run/"+path, "?")[0], "/")
	s.serveRuns(w, r, p, parts)
	return w
}
func evaluationDocumentFixture(t *testing.T, s *Server, root string, withOriginals ...bool) []byte {
	t.Helper()
	script := `from pathlib import Path
from datetime import datetime,timezone,timedelta
import json,sys,time,hashlib
from cpag_core.evaluation import digest
from cpag_core.evaluation_bundle import freeze,evaluate_bundle,V2_VERSION,V3_VERSION
from cpag_core.reference_inventory import build_inventory,LOCATOR_VERSION
from cpag_core.evaluation_details import V2_MATCHING_VERSION
root=Path(sys.argv[1]);artifact=root/'jobs/run/attempt-1';core=json.loads((artifact/'run_manifest.json').read_text());sample=core['input_fingerprint']
originals=sys.argv[2]!='legacy';located=sys.argv[2]=='v3';kwargs={};reference_sha='b'*64
if originals:
 source=root/'controlled-reference-originals';source.mkdir()
 data=b'event_id,time,notes\r\nmanual-operation,10,"first\r\nsecond"\r\nmanual-change,12,last' if located else b'Independent reference notes: request at 10s, transition upper bound at 12s.\n'
 name='review.csv' if located else 'review.txt'
 (source/name).write_bytes(data);reference_sha=hashlib.sha256(data).hexdigest()
 kwargs={'bundle_version':V3_VERSION if located else V2_VERSION,'matching_version':V2_MATCHING_VERSION,'reference_inventory':build_inventory(source,{name:reference_sha})}
split={'schema_version':'1.0.0','synthetic':True,'rule_windows_seconds':{'coupling':60},'isolation_seconds':60,'blocks':[{'partition':'calibration','batch':'dataset-batch','start':'2025-12-31T22:00:00Z','end':'2025-12-31T23:00:00Z','sample_sha256':['a'*64],'normal':False},{'partition':'holdout','batch':'dataset-batch','start':'2026-01-01T00:00:00Z','end':'2026-01-01T00:01:00Z','sample_sha256':[sample],'normal':False}]}
now=datetime.now(timezone.utc);opened=now+timedelta(seconds=3)
reg={'schema_version':'1.0.0','synthetic':True,'registered_at':(now-timedelta(seconds=1)).isoformat(),'holdout_opened_at':opened.isoformat(),'input_fingerprint':sample,'config_fingerprint':core['config_fingerprint'],'split_sha256':digest(split),'tolerance_seconds':2,'thresholds':{}}
freeze(artifact,split,reg,root/'frozen',batch='dataset-batch',sample_sha256=sample,**kwargs)
# Independent oracle is authored here; no predicted event is copied as gold.
labels={'schema_version':'1.0.0','synthetic':True,'origin':'independent','source_ref':'hand-authored-service-oracle','review_ref':'fixture-author','annotation_version':'1','events':[{'id':'manual-operation','batch':'dataset-batch','kind':'network_operation','asset':'["192.0.2.2",44818]','time':'2026-01-01T00:00:10Z','sample_sha256':sample},{'id':'manual-change','batch':'dataset-batch','kind':'process_change','asset':'["synthetic-pump","pump_state"]','time':'2026-01-01T00:00:12Z','sample_sha256':sample}],'disputed_intervals':[]}
references={e['id']:{'source_ref':'handwritten-service-fixture','sha256':reference_sha,**({'locator':{'version':LOCATOR_VERSION,'file_sha256':reference_sha,'record_number':i+1,'columns':['event_id','time']}} if located else {'record':e['id']})} for i,e in enumerate(labels['events'])}
time.sleep(max(0,(opened-datetime.now(timezone.utc)).total_seconds()))
evaluate_bundle(root/'frozen',artifact,labels,references,root/'bundle')
print(json.dumps({p.name:json.loads(p.read_text()) for p in (root/'bundle').iterdir()}))`
	fixtureVersion := "legacy"
	if len(withOriginals) > 0 && withOriginals[0] {
		fixtureVersion = "v2"
	}
	if len(withOriginals) > 1 && withOriginals[1] {
		fixtureVersion = "v3"
	}
	cmd := exec.Command(s.cfg.PythonBin, "-c", script, root, fixtureVersion)
	cmd.Env = append(os.Environ(), "PYTHONPATH="+s.cfg.PythonPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("evaluation document: %v %s", err, out)
	}
	return out
}
func TestEvaluationStorePermissionsQueriesAndLimits(t *testing.T) {
	state := &evaluationDBState{Mode: "dual_source", State: "queued", Payload: json.RawMessage(`{}`), ACL: true}
	db := evaluationDB(t, state)
	s := &Server{DB: db}
	viewer := &principal{ID: "viewer", Role: "viewer"}
	admin := &principal{ID: "admin", Role: "admin"}
	w := evaluationStoreRequest(s, "POST", "evaluations", []byte(`{}`), viewer)
	if w.Code != 403 || state.Saved != nil {
		t.Fatalf("viewer import %d", w.Code)
	}
	state.ACL = false
	w = evaluationStoreRequest(s, "GET", "evaluations/missing", nil, viewer)
	if w.Code != 404 {
		t.Fatalf("denied read %d", w.Code)
	}
	state.ACL = true
	for _, path := range []string{"evaluations/valid/evidence", "evaluations/valid/evidence?event=x&event=y", "evaluations/valid/evidence?event=x&reference=false", "evaluations/valid/evidence?event=x&artifact=/tmp/x", "evaluations/valid?artifact=/tmp/x"} {
		w = evaluationStoreRequest(s, "GET", path, nil, admin)
		if w.Code != 422 {
			t.Fatalf("path %s got %d", path, w.Code)
		}
	}
	w = evaluationStoreRequest(s, "POST", "evaluations", bytes.Repeat([]byte{'x'}, evaluationProjectionLimit+1), admin)
	if w.Code != 422 {
		t.Fatalf("oversized import %d", w.Code)
	}
	w = evaluationStoreRequest(s, "GET", "evaluations/missing", nil, admin)
	if w.Code != 404 {
		t.Fatalf("missing saved evaluation %d", w.Code)
	}
	w = evaluationStoreRequest(s, "GET", "evaluations", nil, viewer)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "saved_metadata_only") {
		t.Fatalf("metadata list: %d %s", w.Code, w.Body.String())
	}
}
func TestEvaluationStoreImportsReverifiesAndQueriesOriginalEvidence(t *testing.T) {
	s, state, root := evaluationFixture(t, false)
	document := evaluationDocumentFixture(t, s, root)
	admin := &principal{ID: "admin", Role: "admin"}
	viewer := &principal{ID: "viewer", Role: "viewer"}
	state.AuditFail = true
	w := evaluationStoreRequest(s, "POST", "evaluations", document, admin)
	if w.Code != 503 || state.Saved != nil {
		t.Fatalf("failed audit persisted import: %d", w.Code)
	}
	state.AuditFail = false
	w = evaluationStoreRequest(s, "POST", "evaluations", document, admin)
	if w.Code != 201 || state.Saved == nil {
		_, diagnostic := s.verifyEvaluationDocument(httptest.NewRequest("GET", "/", nil), "run", "dataset", document, "", false)
		t.Fatalf("import: %d %s (%v)", w.Code, w.Body.String(), diagnostic)
	}
	identity := state.Saved.ID
	sha := state.Saved.SHA
	w = evaluationStoreRequest(s, "POST", "evaluations", document, admin)
	if w.Code != 200 || state.Saved.ID != identity {
		t.Fatalf("duplicate import: %d", w.Code)
	}
	for _, suffix := range []string{"", "/download", "/evidence?event=manual-operation&reference=true"} {
		w = evaluationStoreRequest(s, "GET", "evaluations/"+identity+suffix, nil, viewer)
		if w.Code != 200 {
			t.Fatalf("read %s: %d %s", suffix, w.Code, w.Body.String())
		}
		if suffix == "/download" && !json.Valid(w.Body.Bytes()) {
			t.Fatal("download invalid")
		}
	}
	var doc map[string]any
	if err := json.Unmarshal(document, &doc); err != nil {
		t.Fatal(err)
	}
	adapted := doc["adapted.json"].(map[string]any)
	pred := adapted["predictions"].(map[string]any)
	event := pred["events"].([]any)[0].(map[string]any)["id"].(string)
	w = evaluationStoreRequest(s, "GET", "evaluations/"+identity+"/evidence?event="+event, nil, viewer)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "verified_original") {
		t.Fatalf("original evidence: %d %s", w.Code, w.Body.String())
	}
	w = evaluationStoreRequest(s, "GET", "evaluations/"+identity+"/evidence?event=unknown", nil, viewer)
	if w.Code != 409 {
		t.Fatalf("unknown evidence: %d", w.Code)
	}
	state.Batch = "different-server-batch"
	w = evaluationStoreRequest(s, "GET", "evaluations/"+identity, nil, viewer)
	if w.Code != 409 {
		t.Fatalf("changed trusted dataset context: %d", w.Code)
	}
	state.Batch = ""
	state.StatusReads = 0
	state.RevokePublication = true
	w = evaluationStoreRequest(s, "GET", "evaluations/"+identity, nil, viewer)
	if w.Code != 409 {
		t.Fatalf("expired attempt publication: %d", w.Code)
	}
	state.RevokePublication = false
	state.Saved.SHA = strings.Repeat("0", 64)
	w = evaluationStoreRequest(s, "GET", "evaluations/"+identity, nil, viewer)
	if w.Code != 409 {
		t.Fatalf("changed digest: %d", w.Code)
	}
	state.Saved.SHA = sha
	state.Saved.Document = strings.Replace(state.Saved.Document, "hand-authored-service-oracle", "tampered-source", 1)
	w = evaluationStoreRequest(s, "GET", "evaluations/"+identity, nil, viewer)
	if w.Code != 409 {
		t.Fatalf("changed document: %d", w.Code)
	}
	// Restore the stored serialization, then corrupt retained original evidence.
	state.Saved.Document = string(document)
	if err := os.WriteFile(filepath.Join(root, "jobs/run/attempt-1/dual/sources/process.csv"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	w = evaluationStoreRequest(s, "GET", "evaluations/"+identity+"/download", nil, viewer)
	if w.Code != 409 {
		t.Fatalf("changed originals: %d", w.Code)
	}
}

func TestEvaluationReferenceInventoryAuthorizationIntegrityAndRestoredDirectory(t *testing.T) {
	for _, located := range []bool{false, true} {
		t.Run(fmt.Sprint("located=", located), func(t *testing.T) {
			s, state, root := evaluationFixture(t, false)
			document := evaluationDocumentFixture(t, s, root, true, located)
			expectedStatus := "reference_original_bytes_sha256_verified"
			if located {
				expectedStatus = "reference_original_csv_record_verified"
			}
			if located {
				// Repair envelope hashes; rejection must exercise the locator.
				script := `import json,sys
from cpag_core.evaluation import digest
v=json.load(sys.stdin);v['references.json']['manual-operation']['locator']['record_number']=999999
v['result.json']['bundle_binding']['references_sha256']=digest(v['references.json'])
for name in v['manifest.json']['files']:v['manifest.json']['files'][name]=digest(v[name])
print(json.dumps(v))`
				cmd := exec.Command(s.cfg.PythonBin, "-c", script)
				cmd.Env = append(os.Environ(), "PYTHONPATH="+s.cfg.PythonPath)
				cmd.Stdin = bytes.NewReader(document)
				bad, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("mutate locator: %v %s", err, bad)
				}
				denied := evaluationStoreRequest(s, "POST", "evaluations", bad, &principal{ID: "admin", Role: "admin"})
				if denied.Code != 409 || state.Saved != nil {
					t.Fatalf("out of range original saved: %d %s", denied.Code, denied.Body.String())
				}
			}
			admin, viewer := &principal{ID: "admin", Role: "admin"}, &principal{ID: "viewer", Role: "viewer"}
			w := evaluationStoreRequest(s, "POST", "evaluations", document, admin)
			if w.Code != 201 || state.Saved == nil {
				t.Fatalf("v2 import: %d %s", w.Code, w.Body.String())
			}
			identity := state.Saved.ID
			path := "evaluations/" + identity + "/evidence?event=manual-operation&reference=true"
			state.ACL = false
			state.StatusReads = 0
			w = evaluationStoreRequest(s, "GET", path, nil, viewer)
			if w.Code != 404 || state.StatusReads != 0 {
				t.Fatalf("unauthorized original read %d status reads %d", w.Code, state.StatusReads)
			}
			state.ACL = true
			w = evaluationStoreRequest(s, "GET", path, nil, viewer)
			if w.Code != 200 || !strings.Contains(w.Body.String(), expectedStatus) || !strings.Contains(w.Body.String(), "content_base64") {
				t.Fatalf("original bytes: %d %s", w.Code, w.Body.String())
			}
			// A new catalog connection and directory retain the exact stored JSON. Full
			// PostgreSQL dump/empty-db restore is exercised by the formal harness.
			t.Run("restored", func(t *testing.T) {
				restored, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
					if err != nil {
						return err
					}
					rel, err := filepath.Rel(root, path)
					if err != nil {
						return err
					}
					target := filepath.Join(restored, rel)
					if entry.IsDir() {
						return os.MkdirAll(target, 0700)
					}
					data, err := os.ReadFile(path)
					if err != nil {
						return err
					}
					return os.WriteFile(target, data, 0600)
				}); err != nil {
					t.Fatal(err)
				}
				if err := os.RemoveAll(filepath.Join(restored, "controlled-reference-originals")); err != nil {
					t.Fatal(err)
				}
				copied := *state
				row := *state.Saved
				copied.Saved = &row
				db := evaluationDB(t, &copied)
				restoredServer := &Server{DB: db, Root: restored, cfg: s.cfg, Internal: &jobapi.Server{Root: restored, Repo: jobs.Repository{DB: db}}}
				w := evaluationStoreRequest(restoredServer, "GET", path, nil, viewer)
				if w.Code != 200 || !strings.Contains(w.Body.String(), expectedStatus) {
					t.Fatalf("restored original %d %s", w.Code, w.Body.String())
				}
				copied.Saved.Document = strings.Replace(copied.Saved.Document, "content_base64", "missing_original_content", 1)
				w = evaluationStoreRequest(restoredServer, "GET", path, nil, viewer)
				if w.Code != 409 {
					t.Fatalf("restored missing original %d", w.Code)
				}
			})
			for _, mutation := range []string{"missing", "tampered"} {
				var changed map[string]any
				if err := json.Unmarshal(document, &changed); err != nil {
					t.Fatal(err)
				}
				inventory := changed["reference_inventory.json"].(map[string]any)
				if mutation == "missing" {
					inventory["files"] = map[string]any{}
				} else {
					for _, value := range inventory["files"].(map[string]any) {
						entry := value.(map[string]any)
						encoded := entry["content_base64"].(string)
						entry["content_base64"] = "A" + encoded[1:]
						break
					}
				}
				raw, err := json.Marshal(changed)
				if err != nil {
					t.Fatal(err)
				}
				w = evaluationStoreRequest(s, "POST", "evaluations", raw, admin)
				if w.Code != 409 {
					t.Fatalf("%s original import %d", mutation, w.Code)
				}
			}
		})
	}
}

func TestEvaluationVersionedJSONAndResourceBudgets(t *testing.T) {
	for _, test := range []struct {
		profile, operator string
		want              int
		ok                bool
	}{
		{"", "", evaluationProjectionLimit, true}, {capacity.DevelopmentS100, capacity.DevelopmentS100, evaluationV2DocumentLimit, true},
		{capacity.Engineering, capacity.Engineering, evaluationV2DocumentLimit, true}, {"", capacity.Engineering, evaluationProjectionLimit, true}, {"unknown", "unknown", 0, false},
	} {
		actual, err := evaluationResourceProjectionLimit(test.profile, test.operator)
		if (err == nil) != test.ok || (err == nil && actual != test.want) {
			t.Fatalf("projection policy %q %q got %d %v", test.profile, test.operator, actual, err)
		}
	}
	large := strings.Repeat("x", evaluationProjectionLimit)
	for _, version := range []string{"evaluation-bundle-1", "evaluation-bundle-2", "evaluation-bundle-3"} {
		raw, _ := json.Marshal(map[string]any{"manifest.json": map[string]any{"version": version}, "padding": large})
		limit, err := evaluationDocumentLimit(raw)
		if version == "evaluation-bundle-1" && err == nil {
			t.Fatal("legacy JSON budget expanded")
		}
		if version != "evaluation-bundle-1" && (err != nil || limit != evaluationV2DocumentLimit) {
			t.Fatalf("explicit v2 budget %d %v", limit, err)
		}
	}
}
