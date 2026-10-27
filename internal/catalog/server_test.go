package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigRequiresPrivateFileAndLoopback(t *testing.T) {
	c := Config{DatabaseURL: "postgres://test", SharedRoot: "/tmp/shared", ControlRoot: "/tmp/control", PublicAddr: "127.0.0.1:8095", InternalAddr: "127.0.0.1:8094", WorkerToken: "worker-secret-with-adequate-length", CoordinatorToken: "coordinator-secret-with-length", BootstrapAdminUsername: "admin", BootstrapAdminPassword: "initial-long-secret"}
	path := filepath.Join(t.TempDir(), "config.json")
	raw, _ := json.Marshal(c)
	if e := os.WriteFile(path, raw, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadConfig(path); e == nil {
		t.Fatal("world-readable secret config accepted")
	}
	if e := os.Chmod(path, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadConfig(path); e != nil {
		t.Fatal(e)
	}
	c.PublicAddr = "0.0.0.0:8095"
	raw, _ = json.Marshal(c)
	if e := os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadConfig(path); e == nil {
		t.Fatal("LAN listener accepted without TLS")
	}
}
func TestDualRunGatePreservesIncompleteConfig(t *testing.T) {
	doc := map[string]any{"synthetic": true, "mappings": []any{map[string]any{"rule_id": "r"}}, "clocks": map[string]any{"network": map[string]any{"basis": "documented", "offset_seconds": 0, "uncertainty_seconds": 0}, "process": map[string]any{"basis": "documented", "offset_seconds": 0, "uncertainty_seconds": 0}}}
	if !readyDual(doc) {
		t.Fatal("complete synthetic basis rejected")
	}
	doc["mappings"] = []any{}
	if readyDual(doc) {
		t.Fatal("empty mapping accepted")
	}
	doc["mappings"] = []any{map[string]any{"rule_id": "r"}}
	doc["clocks"].(map[string]any)["process"].(map[string]any)["basis"] = ""
	if readyDual(doc) {
		t.Fatal("missing process time basis accepted")
	}
	doc["clocks"].(map[string]any)["process"].(map[string]any)["basis"] = "declared"
	doc["synthetic"] = false
	if readyDual(doc) {
		t.Fatal("real source accepted by synthetic core")
	}
}
func TestStorageNamesRejectPathTraversal(t *testing.T) {
	for _, name := range []string{"../x.pcap", "x/y.pcap", "\\secret", ""} {
		if safeName(name) {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
	if !safeName("capture.pcap") {
		t.Fatal("basename rejected")
	}
}

func TestPublicBoundaryDoesNotExposeWorkerRoutes(t *testing.T) {
	s := &Server{cfg: Config{PublicAddr: "127.0.0.1:8095"}}
	for _, path := range []string{"/v1/claim", "/api/v1/jobs", "/api/v3/unknown"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		if path == "/api/v3/unknown" {
			if rec.Code != 401 {
				t.Fatalf("%s: got %d", path, rec.Code)
			}
		} else if rec.Code != 404 {
			t.Fatalf("%s: got %d", path, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v3/session", nil)
	req.Header.Set("Origin", "https://outside.example")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("cross-origin login got %d", rec.Code)
	}
}
func TestExportedDirectoryIndex(t *testing.T) {
	root := t.TempDir()
	if e := os.MkdirAll(filepath.Join(root, "workspace"), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(root, "workspace", "index.html"), []byte("workspace-ready"), 0600); e != nil {
		t.Fatal(e)
	}
	s := &Server{cfg: Config{StaticRoot: root}}
	req := httptest.NewRequest(http.MethodGet, "/workspace/", nil)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != 200 || rec.Body.String() != "workspace-ready" {
		t.Fatalf("exported page unavailable: %d %s", rec.Code, rec.Body.String())
	}
	rootReq := httptest.NewRequest(http.MethodGet, "/", nil)
	rootRec := httptest.NewRecorder()
	s.ServeHTTP(rootRec, rootReq)
	if rootRec.Code != http.StatusFound || rootRec.Header().Get("Location") != "/workspace/" {
		t.Fatalf("root did not enter workspace: %d", rootRec.Code)
	}
}
func TestOriginalIntegrityGate(t *testing.T) {
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	rel := filepath.Join("inputs", "catalog", "dataset1", "source.pcap")
	path := filepath.Join(root, rel)
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	original := []byte("synthetic-source")
	if e := os.WriteFile(path, original, 0600); e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256(original)
	sha := hex.EncodeToString(sum[:])
	s := &Server{Root: root}
	if _, e := s.verifiedFile(rel, sha, int64(len(original))); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte("tampered-source!"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := s.verifiedFile(rel, sha, int64(len(original))); e == nil {
		t.Fatal("changed original accepted")
	}
	if !integrityErrors(map[string]any{"errors": []any{"checksum_mismatch"}}) {
		t.Fatal("preflight corruption not mapped to conflict")
	}
	if integrityErrors(map[string]any{"errors": []any{"batch_conflict"}}) {
		t.Fatal("metadata gap misclassified as corruption")
	}
	if !hasReportCode(map[string]any{"errors": []any{"batch_conflict"}}, "batch_conflict") {
		t.Fatal("batch conflict report code lost")
	}
}
func TestControlRootSeparation(t *testing.T) {
	if !contained("/tmp/cpag/shared", "/tmp/cpag/shared/control") {
		t.Fatal("nested control root undetected")
	}
	if contained("/tmp/cpag/shared", "/tmp/cpag/control") {
		t.Fatal("sibling root rejected")
	}
}
