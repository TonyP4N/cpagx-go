package catalog

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

type evaluationDBState struct {
	Payload           json.RawMessage `json:"payload"`
	ArtifactPath      string          `json:"artifact_path"`
	ArtifactSHA       string          `json:"artifact_sha"`
	Mode              string          `json:"mode"`
	State             string
	ACL               bool
	AuditFail         bool
	RevokePublication bool
	StatusReads       int
	Saved             *evaluationSavedRow
	Batch             string
}
type evaluationDriver struct{}
type evaluationConn struct {
	state       *evaluationDBState
	pending     *evaluationSavedRow
	transaction bool
}

var evaluationStates sync.Map

func (evaluationDriver) Open(name string) (driver.Conn, error) {
	v, ok := evaluationStates.Load(name)
	if !ok {
		return nil, fmt.Errorf("unknown evaluation fixture")
	}
	return &evaluationConn{state: v.(*evaluationDBState)}, nil
}
func (*evaluationConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("unexpected prepare")
}
func (*evaluationConn) Close() error { return nil }
func (c *evaluationConn) Begin() (driver.Tx, error) {
	c.transaction = true
	c.pending = c.state.Saved
	return evaluationTx{c}, nil
}
func (c *evaluationConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	s := c.state
	if strings.Contains(q, "v3_evaluations") {
		return c.evaluationQuery(q, args)
	}
	switch {
	case strings.Contains(q, "FROM v3_run_bindings WHERE job_id="):
		return &runBindingRows{[]string{"dataset", "config", "mode", "created", "preflight", "origin", "networks", "replay"}, [][]driver.Value{{"dataset", "config", s.Mode, time.Now(), nil, "native_gate", nil, nil}}}, nil
	case strings.Contains(q, "FROM v3_dataset_acl"):
		rows := &runBindingRows{columns: []string{"access"}}
		if s.ACL {
			rows.values = [][]driver.Value{{"viewer"}}
		}
		return rows, nil
	case strings.Contains(q, "SELECT batch FROM v3_datasets"):
		batch := s.Batch
		if batch == "" {
			batch = "dataset-batch"
		}
		return &runBindingRows{[]string{"batch"}, [][]driver.Value{{batch}}}, nil
	case strings.Contains(q, "FROM m4_jobs WHERE id="):
		s.StatusReads++
		state := s.State
		if s.RevokePublication && s.StatusReads > 1 {
			state = "queued"
		}
		var artifact, sha driver.Value
		if s.ArtifactPath != "" {
			artifact = s.ArtifactPath
			sha = s.ArtifactSHA
		}
		return &runBindingRows{[]string{"id", "state", "attempt", "payload", "artifact_path", "artifact_sha", "last_error", "recovery_deadline", "recovery_checked", "recovery_reason", "lease"}, [][]driver.Value{{"run", state, int64(1), []byte(s.Payload), artifact, sha, nil, nil, nil, nil, false}}}, nil
	case strings.Contains(q, "FROM m4_job_attempts WHERE job_id="):
		return &runBindingRows{columns: []string{"attempt", "worker", "location", "container", "exited", "publication", "artifact", "claimed", "sha", "receipt", "checked", "error", "executor", "revoked"}}, nil
	default:
		return nil, fmt.Errorf("unexpected evaluation query: %s", q)
	}
}
func (c *evaluationConn) ExecContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Result, error) {
	if !strings.Contains(q, "INSERT INTO v3_audit_events") {
		return nil, fmt.Errorf("unexpected exec: %s", q)
	}
	if c.state.AuditFail {
		return nil, fmt.Errorf("audit unavailable")
	}
	return driver.RowsAffected(1), nil
}
func init() { sql.Register("catalog-evaluation-fixture", evaluationDriver{}) }
func evaluationDB(t *testing.T, state *evaluationDBState) *sql.DB {
	t.Helper()
	name := t.Name()
	evaluationStates.Store(name, state)
	db, err := sql.Open("catalog-evaluation-fixture", name)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close(); evaluationStates.Delete(name) })
	return db
}
func evaluationRequest(s *Server, query string, p *principal) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", "/api/v3/runs/run/evaluation-input"+query, nil)
	w := httptest.NewRecorder()
	s.serveRuns(w, r, p, []string{"runs", "run", "evaluation-input"})
	return w
}
func TestEvaluationInputRequiresACLAndStrictQuery(t *testing.T) {
	state := &evaluationDBState{Mode: "dual_source", State: "queued", Payload: json.RawMessage(`{}`)}
	db := evaluationDB(t, state)
	s := &Server{DB: db, Internal: &jobapi.Server{Repo: jobs.Repository{DB: db}}}
	denied := evaluationRequest(s, "", &principal{ID: "no-acl", Role: "viewer"})
	if denied.Code != 404 || state.StatusReads != 0 {
		t.Fatalf("unauthorized adapter access: %d %d", denied.Code, state.StatusReads)
	}
	for _, q := range []string{"?projection=attack", "?projection=network&projection=dual", "?artifact=/private/secret", "?projection=", "?projection=%ZZ"} {
		w := evaluationRequest(s, q, &principal{Role: "admin"})
		if w.Code != 422 {
			t.Fatalf("query %q got %d: %s", q, w.Code, w.Body.String())
		}
	}
	if state.StatusReads != 0 {
		t.Fatal("invalid query reached publication")
	}
	w := evaluationRequest(s, "", &principal{Role: "admin"})
	if w.Code != 409 {
		t.Fatalf("queued publication accepted: %d", w.Code)
	}
	auth := httptest.NewRecorder()
	s.ServeHTTP(auth, httptest.NewRequest(http.MethodGet, "/api/v3/runs/run/evaluation-input", nil))
	if auth.Code != 401 {
		t.Fatalf("anonymous got %d", auth.Code)
	}
}
func evaluationFixture(t *testing.T, replay bool) (*Server, *evaluationDBState, string) {
	t.Helper()
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	python := os.Getenv("CPAG_TEST_PYTHON")
	if python == "" {
		python = filepath.Join(repo, ".venv/bin/python")
		if _, err = os.Stat(python); err != nil {
			python = "python3"
		}
	}
	python, err = exec.LookPath(python)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	script := `from pathlib import Path
import json,sys,hashlib
from cpag_core.pipeline import canonical,file_hash,fingerprint
from dual_source_fixtures import make_case
from round18_profile import fixture
root=Path(sys.argv[1]);replay=sys.argv[2]=='true'
if replay:
 from cpag_core.replay_export import export_task
 networks,p,c,_=fixture(root/'inputs')
else:
 from cpag_core.dual_source_export import export_task
 n,p,c=make_case(root/'inputs');networks=[n]
out=root/'jobs/run/attempt-1'
export_task(networks if replay else networks[0],p,c,out,run_id='run',attempt_id=1)
ref=lambda p:{'path':str(p.relative_to(root)),'sha256':file_hash(p)}
payload={'kind':'dual-source-replay' if replay else 'dual-source','network':ref(networks[0]),'process':ref(p),'profile':ref(c),'config_fingerprint':fingerprint(json.loads(c.read_text()))}
manifest={'config_fingerprint':payload['config_fingerprint'],'inputs':{k:payload[k]['sha256'] for k in ('network','process','profile')},'artifacts':[]}
if replay:
 payload['replay_version']='dual-source-replay-1';manifest['replay_version']=payload['replay_version']
if len(networks)>1:
 payload['networks']=[ref(x) for x in networks];manifest['networks']=[file_hash(x) for x in networks]
core=json.loads((out/'run_manifest.json').read_text())
for name in ['run_manifest.json']+[r['path'] for r in core['artifacts']]:
 path=out/name;manifest['artifacts'].append({'path':name,'sha256':file_hash(path),'size':path.stat().st_size})
raw=canonical(manifest)+b'\n';sha=hashlib.sha256(raw).hexdigest()
(out/'manifest.json').write_bytes(raw);(out/(sha+'.json')).write_bytes(raw)
(root/'fixture.json').write_text(json.dumps({'payload':payload,'artifact_path':'jobs/run/attempt-1/'+sha+'.json','artifact_sha':sha,'mode':'dual_source_replay' if replay else 'dual_source'}))`
	cmd := exec.Command(python, "-c", script, root, fmt.Sprint(replay))
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "services/analysis/src")+":"+filepath.Join(repo, "scripts/validation"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fixture: %v %s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(root, "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	state := &evaluationDBState{State: "succeeded", ACL: true}
	if err = json.Unmarshal(raw, state); err != nil {
		t.Fatal(err)
	}
	db := evaluationDB(t, state)
	return &Server{DB: db, Root: root, cfg: Config{PythonBin: python, PythonPath: filepath.Join(repo, "services/analysis/src")}, Internal: &jobapi.Server{Root: root, Repo: jobs.Repository{DB: db}}}, state, root
}
func TestEvaluationInputPublishedOfflineAndReplayViews(t *testing.T) {
	for _, replay := range []bool{false, true} {
		t.Run(fmt.Sprint(replay), func(t *testing.T) {
			s, state, root := evaluationFixture(t, replay)
			for _, projection := range []string{"network", "process", "dual"} {
				w := evaluationRequest(s, "?projection="+projection, &principal{ID: "viewer", Role: "viewer"})
				if w.Code != 200 {
					t.Fatalf("projection %s: %d %s", projection, w.Code, w.Body.String())
				}
				var result map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				binding := result["binding"].(map[string]any)
				pred := result["predictions"].(map[string]any)
				if binding["batch"] != "dataset-batch" || binding["sample_sha256"] != pred["input_fingerprint"] || binding["projection"] != projection {
					t.Fatalf("trusted context lost: %#v", binding)
				}
				kinds := map[string]bool{}
				for _, row := range pred["events"].([]any) {
					kinds[row.(map[string]any)["kind"].(string)] = true
				}
				if projection == "network" && (!kinds["network_operation"] || len(kinds) != 1) || projection == "process" && (!kinds["process_change"] || len(kinds) != 1) || projection == "dual" && len(kinds) != 2 {
					t.Fatalf("wrong projection kinds: %#v", kinds)
				}
				if replay && binding["final_snapshot"] == nil {
					t.Fatal("replay terminal snapshot missing")
				}
			}
			state.AuditFail = true
			w := evaluationRequest(s, "", &principal{Role: "admin"})
			if w.Code != 503 {
				t.Fatalf("audit failure got %d", w.Code)
			}
			state.AuditFail = false
			state.StatusReads = 0
			state.RevokePublication = true
			w = evaluationRequest(s, "", &principal{Role: "admin"})
			if w.Code != 409 {
				t.Fatalf("changed current publication got %d", w.Code)
			}
			state.RevokePublication = false
			retained := "dual/sources/process.csv"
			if replay {
				retained = "sources/process.csv"
			}
			if err := os.WriteFile(filepath.Join(root, "jobs/run/attempt-1", retained), []byte("changed"), 0600); err != nil {
				t.Fatal(err)
			}
			w = evaluationRequest(s, "", &principal{Role: "admin"})
			if w.Code != 409 {
				t.Fatalf("changed retained evidence got %d", w.Code)
			}
		})
	}
}
func TestEvaluationProjectionSubprocessBoundaries(t *testing.T) {
	repo, _ := filepath.Abs("../..")
	python := filepath.Join(repo, ".venv/bin/python")
	if _, err := os.Stat(python); err != nil {
		python = "python3"
	}
	for _, tc := range []struct{ name, code string }{
		{"malformed", "print('not-json')"}, {"multiple", "print('{}');print('{}')"}, {"oversized", "import sys;sys.stdout.write('x'*(8*1024*1024+1))"}, {"stderr", "import sys;sys.stderr.write('x'*9000)"}, {"failed", "raise SystemExit(2)"}, {"timeout", "import time;time.sleep(3)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pkg := filepath.Join(dir, "cpag_core")
			os.Mkdir(pkg, 0700)
			os.WriteFile(filepath.Join(pkg, "__init__.py"), nil, 0600)
			os.WriteFile(filepath.Join(pkg, "evaluation_artifacts.py"), []byte(tc.code), 0600)
			s := &Server{cfg: Config{PythonBin: python, PythonPath: dir}}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			if _, err := s.runEvaluationProjection(ctx, "ignored", "batch", strings.Repeat("a", 64), "dual"); err == nil {
				t.Fatal("invalid adapter output accepted")
			}
		})
	}
}
