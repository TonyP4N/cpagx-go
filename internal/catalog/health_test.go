package catalog

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type healthTestDriver struct{}
type healthTestConnection struct{}

func (healthTestDriver) Open(name string) (driver.Conn, error) {
	if name == "down" {
		return nil, errors.New("private-dsn-must-not-leak")
	}
	return healthTestConnection{}, nil
}
func (healthTestConnection) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (healthTestConnection) Close() error                        { return nil }
func (healthTestConnection) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (healthTestConnection) Ping(context.Context) error          { return nil }
func init()                                                      { sql.Register("catalog-health-test", healthTestDriver{}) }
func healthFixture(t *testing.T, name string) *Server {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	control, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"inputs/catalog", "jobs"} {
		if err := os.MkdirAll(filepath.Join(root, sub), 0700); err != nil {
			t.Fatal(err)
		}
	}
	db, err := sql.Open("catalog-health-test", name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Server{DB: db, Root: root, cfg: Config{ControlRoot: control}}
}
func TestReadinessChecksDatabaseAndStorageIndependentlyOfLiveness(t *testing.T) {
	for _, database := range []string{"up", "down"} {
		t.Run(database, func(t *testing.T) {
			s := healthFixture(t, database)
			w := httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("GET", "/health/live", nil))
			if w.Code != 200 {
				t.Fatalf("live=%d", w.Code)
			}
			w = httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("GET", "/health/ready", nil))
			expected := 200
			if database == "down" {
				expected = 503
			}
			if w.Code != expected || strings.Contains(w.Body.String(), "private-dsn") || strings.Contains(w.Body.String(), s.Root) {
				t.Fatalf("ready=%d %s", w.Code, w.Body.String())
			}
			if err := os.Rename(filepath.Join(s.Root, "jobs"), filepath.Join(s.Root, "jobs.off")); err != nil {
				t.Fatal(err)
			}
			w = httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("GET", "/health/ready", nil))
			if w.Code != 503 || !strings.Contains(w.Body.String(), `"storage":false`) {
				t.Fatalf("missing storage=%d %s", w.Code, w.Body.String())
			}
			w = httptest.NewRecorder()
			s.ServeHTTP(w, httptest.NewRequest("GET", "/health/live", nil))
			if w.Code != 200 {
				t.Fatal("storage outage changed process liveness")
			}
		})
	}
}
func TestReadinessRejectsSymlinkStorageAndMutation(t *testing.T) {
	s := healthFixture(t, "up")
	original := filepath.Join(s.Root, "jobs")
	os.Remove(original)
	if err := os.Symlink(t.TempDir(), original); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/health/ready", nil))
	if w.Code != 503 {
		t.Fatal("symlink storage declared ready")
	}
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "/health/live", nil))
	if w.Code != 405 {
		t.Fatal("health mutation accepted")
	}
}
func TestOperationsRequireAdminAndBoundQuery(t *testing.T) {
	s := healthFixture(t, "up")
	for _, role := range []string{"viewer", "analyst"} {
		w := httptest.NewRecorder()
		s.serveOperations(w, httptest.NewRequest("GET", "/api/v3/health/operations", nil), &principal{Role: role}, []string{"health", "operations"})
		if w.Code != 403 {
			t.Fatalf("%s=%d", role, w.Code)
		}
	}
	for _, query := range []string{"?limit=101", "?offset=-1", "?worker_stale_seconds=1", "?errors=raw", "?path=/private", "?limit=1&limit=2"} {
		w := httptest.NewRecorder()
		s.serveOperations(w, httptest.NewRequest("GET", "/api/v3/health/operations"+query, nil), &principal{Role: "admin"}, []string{"health", "operations"})
		if w.Code != 422 {
			t.Fatalf("%s=%d", query, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/api/v3/health/operations", nil))
	if w.Code != 401 {
		t.Fatalf("unauthenticated=%d", w.Code)
	}
}
