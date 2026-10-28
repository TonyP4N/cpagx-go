package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/TonyP4N/cpagx-go/internal/jobapi"
)

func TestPreparedPublicationReadRechecksBytesAndIdentity(t *testing.T) {
	s, state, root := evaluationFixture(t, false)
	internal := s.Internal.(*jobapi.Server)
	request := httptest.NewRequest("GET", "/", nil)
	snapshot, err := internal.CapturePublicationSnapshot(request, "run")
	if err != nil {
		t.Fatal(err)
	}
	p := evaluationPreparation{ID: "prepared", Job: "run", Dataset: "dataset", Attempt: snapshot.Attempt, PayloadSHA: snapshot.PayloadSHA256, PublicationSHA: snapshot.PublicationSHA256, ArtifactPath: snapshot.ArtifactPath, Config: snapshot.ConfigFingerprint, Input: sql.NullString{String: snapshot.InputFingerprint, Valid: true}, Batch: "dataset-batch", Projection: "dual", Strategy: preparationVersion, State: "ready", PreparationAttempt: 1, Limit: evaluationProjectionLimit, Cost: json.RawMessage(`{"total_seconds":1}`)}
	p.Inventory, _ = json.Marshal(snapshot)
	p.Document, err = s.runEvaluationProjection(context.WithValue(context.Background(), evaluationPublicationContextKey{}, snapshot.CoreManifestSHA256), filepath.Join(root, filepath.Dir(snapshot.ArtifactPath)), p.Batch, snapshot.InputFingerprint, "dual")
	if err != nil {
		t.Fatal(err)
	}
	seal := func() {
		sum := sha256.Sum256(p.Document)
		p.DocumentSHA = sql.NullString{String: fmt.Sprintf("%x", sum[:]), Valid: true}
		p.DocumentSize = int64(len(p.Document))
		state.Prepared = &p
	}
	seal()
	if w := evaluationRequest(s, "?projection=dual", &principal{Role: "viewer"}); w.Code != 200 {
		t.Fatalf("ready: %d %s", w.Code, w.Body.String())
	}
	file := filepath.Join(root, filepath.Dir(snapshot.ArtifactPath), snapshot.Files[0].Path)
	original, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte{}, original...)
	bad[len(bad)/2] ^= 1
	if err = os.WriteFile(file, bad, 0600); err != nil {
		t.Fatal(err)
	}
	if w := evaluationRequest(s, "?projection=dual", &principal{Role: "viewer"}); w.Code != 409 {
		t.Fatalf("same-size tamper: %d", w.Code)
	}
	os.WriteFile(file, original, 0600)
	os.Rename(file, file+".missing")
	if w := evaluationRequest(s, "?projection=dual", &principal{Role: "viewer"}); w.Code != 409 {
		t.Fatalf("missing artifact: %d", w.Code)
	}
	os.Rename(file+".missing", file)
	if w := evaluationRequest(s, "?projection=dual", &principal{Role: "viewer"}); w.Code != 200 {
		t.Fatalf("restored bytes: %d %s", w.Code, w.Body.String())
	}
	p.Dataset = "another-dataset"
	if w := evaluationRequest(s, "?projection=dual", &principal{Role: "viewer"}); w.Code != 409 {
		t.Fatalf("wrong dataset binding: %d", w.Code)
	}
	p.Dataset = "dataset"
	// Rehashing a body with a different run cannot repair its source binding.
	var doc map[string]any
	json.Unmarshal(p.Document, &doc)
	doc["predictions"].(map[string]any)["run_id"] = "bad"
	p.Document, _ = json.Marshal(doc)
	seal()
	if w := evaluationRequest(s, "?projection=dual", &principal{Role: "viewer"}); w.Code != 409 {
		t.Fatalf("rehashed wrong run: %d", w.Code)
	}
	p.State = "preparing"
	if w := evaluationRequest(s, "?projection=dual", &principal{Role: "viewer"}); w.Code != 409 {
		t.Fatalf("pending must not publish: %d", w.Code)
	}
}

func TestPreparationQueryAndPublicMetadata(t *testing.T) {
	for _, query := range []string{"?projection=dual&projection=network", "?publication_sha256=abc", "?projection=unknown", "?projection=dual&x=1"} {
		if _, err := strictProjectionQuery(httptest.NewRequest("GET", "/"+query, nil)); err == nil {
			t.Fatalf("accepted untrusted query: %q", query)
		}
	}
	p := evaluationPreparation{Owner: "private-owner", Document: []byte("private-doc"), PayloadSHA: "private-payload", Inventory: []byte("private-inventory"), State: "failed", Reason: "preparation_timeout", Cost: json.RawMessage(`{"total_seconds":1800}`)}
	raw, _ := json.Marshal(p.public())
	var out map[string]any
	json.Unmarshal(raw, &out)
	for _, key := range []string{"owner", "document_bytes", "payload_sha256", "inventory_json", "error_detail"} {
		if _, ok := out[key]; ok {
			t.Fatalf("private metadata leaked: %s", key)
		}
	}
	if out["duration_seconds"] != float64(1800) {
		t.Fatal("actual preparation cost missing")
	}
}

func TestPreparationForeignScopeCannotClaimOrSilentlyWait(t *testing.T) {
	state := &evaluationDBState{ForeignPreparation: 1, Prepared: &evaluationPreparation{State: "preparing", Owner: "other-owner", PreparationAttempt: 2}}
	s := &Server{DB: evaluationDB(t, state), cfg: Config{ControlRoot: t.TempDir()}}
	s.preparePending(context.Background())
	if state.Prepared.State != "preparing" || state.Prepared.Owner != "other-owner" || state.Prepared.PreparationAttempt != 2 {
		t.Fatal("foreign active execution was reclaimed")
	}
	if state.Prepared.Reason != "coordination_scope_mismatch" {
		t.Fatal("foreign coordinator exit is unconfirmed but safe reason is missing")
	}
}

func TestPreparationAuditFailureCannotLeaveQueuedWork(t *testing.T) {
	s, state, _ := evaluationFixture(t, false)
	state.AuditFail = true
	w := evaluationStoreRequest(s, "POST", "evaluation-preparation", []byte(`{"projection":"dual"}`), &principal{Role: "admin"})
	if w.Code != 503 {
		t.Fatalf("audit failure: %d %s", w.Code, w.Body.String())
	}
	if state.Prepared != nil {
		t.Fatal("failed authorization audit left queued preparation")
	}
}
func TestPreparationStatusRequiresAudit(t *testing.T) {
	s, state, _ := evaluationFixture(t, false)
	state.AuditFail = true
	state.Prepared = &evaluationPreparation{State: "preparing", Projection: "dual", Cost: json.RawMessage(`{}`)}
	w := evaluationStoreRequest(s, "GET", "evaluation-preparation?projection=dual", nil, &principal{Role: "admin"})
	if w.Code != 503 {
		t.Fatalf("status audit failure exposed state: %d", w.Code)
	}
}

func TestEvaluationEvidenceWholeResponseBudget(t *testing.T) {
	w := httptest.NewRecorder()
	respondEvaluationEvidence(w, map[string]any{"evidence": strings.Repeat("x", evaluationProjectionLimit)})
	if w.Code != 409 || w.Body.Len() > 1024 {
		t.Fatalf("oversized evidence leaked partial response: %d %d", w.Code, w.Body.Len())
	}
	w = httptest.NewRecorder()
	respondEvaluationEvidence(w, map[string]any{"evidence": "verified"})
	if w.Code != 200 || !json.Valid(w.Body.Bytes()) {
		t.Fatal("bounded complete evidence rejected")
	}
}

func TestPreparationDocumentGlobalAndFrozenVersionBudget(t *testing.T) {
	for _, row := range []struct {
		existing, size, limit int64
		want                  bool
	}{
		{preparationBudget - evaluationProjectionLimit, evaluationProjectionLimit, evaluationProjectionLimit, true},
		{preparationBudget - evaluationProjectionLimit + 1, evaluationProjectionLimit, evaluationProjectionLimit, false},
		{0, evaluationProjectionLimit + 1, evaluationProjectionLimit, false},
		{0, evaluationV2DocumentLimit, evaluationV2DocumentLimit, true},
		{0, evaluationV2DocumentLimit + 1, evaluationV2DocumentLimit, false},
		{0, 1, 256 << 20, false}, {preparationBudget + 1, 1, evaluationProjectionLimit, false}, {-1, 1, evaluationProjectionLimit, false},
	} {
		if got := preparationDocumentFits(row.existing, row.size, row.limit); got != row.want {
			t.Fatalf("budget %v: %t", row, got)
		}
	}
}
