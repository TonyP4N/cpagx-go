package catalog

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A database/sql driver preserves the SQL NULL that caused scalar run GETs to
// disappear, while keeping this HTTP regression independent of external state.
type runBindingDriver struct{}
type runBindingConn struct{ multi bool }
type runBindingRows struct {
	columns []string
	values  [][]driver.Value
}

func (runBindingDriver) Open(name string) (driver.Conn, error) {
	return &runBindingConn{multi: name == "multi"}, nil
}
func (*runBindingConn) Prepare(string) (driver.Stmt, error) {
	return nil, fmt.Errorf("unexpected prepare")
}
func (*runBindingConn) Close() error              { return nil }
func (*runBindingConn) Begin() (driver.Tx, error) { return nil, fmt.Errorf("unexpected transaction") }
func (c *runBindingConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(q, "FROM v3_run_bindings WHERE job_id="):
		var captures driver.Value
		if c.multi {
			captures = []byte(`["capture-one","capture-two"]`)
		}
		return &runBindingRows{[]string{"dataset_id", "config_version_id", "mode", "created_at", "preflight_id", "preflight_link_origin", "network_file_ids"}, [][]driver.Value{{"dataset", "config", "dual_source", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), "preflight", "native_gate", captures}}}, nil
	case strings.Contains(q, "FROM m4_jobs WHERE id="):
		return &runBindingRows{[]string{"id", "state", "attempt", "payload", "artifact_path", "artifact_sha256", "last_error", "recovery_deadline", "recovery_checked_at", "recovery_reason", "lease_valid"}, [][]driver.Value{{"run", "queued", int64(0), []byte(`{}`), nil, nil, nil, nil, nil, nil, false}}}, nil
	case strings.Contains(q, "FROM m4_job_attempts WHERE job_id="):
		return &runBindingRows{columns: []string{"attempt", "worker", "location", "container_id", "exited_at", "publication_state", "artifact_path", "claimed_at", "artifact_sha256", "exit_receipt", "exit_checked_at", "exit_error", "executor_kind", "start_revoked_at"}}, nil
	default:
		return nil, fmt.Errorf("unexpected query: %s", q)
	}
}
func (r *runBindingRows) Columns() []string { return r.columns }
func (r *runBindingRows) Close() error      { return nil }
func (r *runBindingRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}

const runBindingTestDriverName = "catalog-run-binding-null-regression"

func init() { sql.Register(runBindingTestDriverName, runBindingDriver{}) }
func TestRunGETPreservesSQLNullLegacyCaptureBinding(t *testing.T) {
	const name = runBindingTestDriverName
	for _, kind := range []string{"scalar", "multi"} {
		t.Run(kind, func(t *testing.T) {
			db, e := sql.Open(name, kind)
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			s := &Server{DB: db, repo: jobs.Repository{DB: db}}
			req := httptest.NewRequest("GET", "/api/v3/runs/run", nil)
			rec := httptest.NewRecorder()
			s.serveRuns(rec, req, &principal{Role: "admin"}, []string{"runs", "run"})
			if rec.Code != 200 {
				t.Fatalf("run GET returned %d: %s", rec.Code, rec.Body.String())
			}
			var result struct {
				Run struct {
					State    string   `json:"state"`
					Captures []string `json:"network_file_ids"`
				} `json:"run"`
			}
			if e = json.Unmarshal(rec.Body.Bytes(), &result); e != nil {
				t.Fatal(e)
			}
			if result.Run.State != "queued" {
				t.Fatal(result.Run.State)
			}
			if kind == "scalar" && result.Run.Captures != nil {
				t.Fatal("legacy scalar binding changed")
			}
			if kind == "multi" && len(result.Run.Captures) != 2 {
				t.Fatal("ordered multi binding lost")
			}
		})
	}
}
