package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type lostCommitDriver struct{}
type lostCommitConn struct{ runBindingConn }
type lostCommitTx struct{}

func (lostCommitDriver) Open(string) (driver.Conn, error) { return &lostCommitConn{}, nil }
func (*lostCommitConn) Begin() (driver.Tx, error)         { return lostCommitTx{}, nil }
func (lostCommitTx) Rollback() error                      { return nil }
func (lostCommitTx) Commit() error                        { return errors.New("connection lost awaiting COMMIT response") }
func (*lostCommitConn) QueryContext(_ context.Context, q string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(q, "SELECT source_kind") {
		return &runBindingRows{[]string{"source_kind"}, [][]driver.Value{{"synthetic"}}}, nil
	}
	if strings.Contains(q, "idempotency_key=") {
		return &runBindingRows{columns: []string{"id", "role", "filename", "sha256", "size_bytes", "created_at"}}, nil
	}
	if strings.Contains(q, "max(version)") {
		return &runBindingRows{[]string{"version"}, [][]driver.Value{{int64(1)}}}, nil
	}
	if strings.Contains(q, "FOR UPDATE") {
		return &runBindingRows{[]string{"id"}, [][]driver.Value{{"dataset"}}}, nil
	}
	return nil, fmt.Errorf("unexpected SQL: %s", q)
}
func (*lostCommitConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}
func init() { sql.Register("r21-lost-commit", lostCommitDriver{}) }
func TestUploadDoesNotDeleteBytesWhenCommitAcknowledgmentIsLost(t *testing.T) {
	db, e := sql.Open("r21-lost-commit", "")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	s := Server{Root: t.TempDir(), DB: db}
	data := "synthetic,1\n"
	req := httptest.NewRequest("POST", "/api/v3/datasets/dataset/files?role=process&name=synthetic.csv", strings.NewReader(data))
	req.Header.Set("X-Content-SHA256", fmt.Sprintf("%x", sha256.Sum256([]byte(data))))
	req.Header.Set("Idempotency-Key", "stable-synthetic-upload")
	rec := httptest.NewRecorder()
	s.uploadFile(rec, req, &principal{Role: "admin", ID: "operator"}, "dataset")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "commit_unconfirmed") {
		t.Errorf("status=%d, response=%s", rec.Code, rec.Body.String())
	}
	files, e := filepath.Glob(filepath.Join(s.Root, "inputs/catalog/dataset/*.csv"))
	if e != nil || len(files) != 1 {
		t.Fatalf("lost potentially committed source: %v %v", files, e)
	}
	raw, e := os.ReadFile(files[0])
	if e != nil || string(raw) != data {
		t.Fatal("original no longer readable")
	}
}

func TestConfigDoesNotDeleteProfileWhenCommitAcknowledgmentIsLost(t *testing.T) {
	db, e := sql.Open("r21-lost-commit", "")
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	const doc = `{"dataset_id":"dataset"}`
	s := Server{Root: t.TempDir(), DB: db}
	req := httptest.NewRequest("POST", "/api/v3/datasets/dataset/configs", strings.NewReader(`{"kind":"intake","document":`+doc+`}`))
	rec := httptest.NewRecorder()
	s.createConfig(rec, req, &principal{Role: "admin", ID: "operator"}, "dataset")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "commit_unconfirmed") {
		t.Fatalf("status=%d, response=%s", rec.Code, rec.Body.String())
	}
	files, e := filepath.Glob(filepath.Join(s.Root, "inputs/catalog/dataset/profiles/*.json"))
	if e != nil || len(files) != 1 {
		t.Fatalf("lost potentially committed profile: %v %v", files, e)
	}
	raw, e := os.ReadFile(files[0])
	if e != nil || string(raw) != doc {
		t.Fatal("profile no longer readable")
	}
}
