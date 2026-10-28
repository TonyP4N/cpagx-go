package catalog

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobapi"
)

type savedEvaluation struct {
	ID        string    `json:"id"`
	JobID     string    `json:"job_id"`
	DatasetID string    `json:"dataset_id"`
	SHA       string    `json:"document_sha256"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
}
type verifiedEvaluationDocument struct {
	Document json.RawMessage `json:"document"`
	SHA      string          `json:"document_sha256"`
	Result   json.RawMessage `json:"result"`
	Evidence json.RawMessage `json:"evidence,omitempty"`
}

const evaluationV2DocumentLimit = 128 << 20
const evaluationEnvelopeLimit = 3*evaluationV2DocumentLimit + 16<<20

func evaluationDocumentLimit(raw []byte) (int, error) {
	if len(raw) == 0 || len(raw) > evaluationV2DocumentLimit || validateUniqueJSON(raw) != nil {
		return 0, errors.New("invalid bounded evaluation JSON")
	}
	var header map[string]json.RawMessage
	var manifest struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(raw, &header) != nil || json.Unmarshal(header["manifest.json"], &manifest) != nil {
		return 0, errors.New("evaluation manifest required")
	}
	limit := evaluationProjectionLimit
	switch manifest.Version {
	case "evaluation-bundle-1":
	case "evaluation-bundle-2", "evaluation-bundle-3":
		limit = evaluationV2DocumentLimit
	default:
		return 0, errors.New("unsupported evaluation version")
	}
	if len(raw) > limit {
		return 0, errors.New("evaluation document outside versioned budget")
	}
	return limit, nil
}

// serveEvaluations is reached only after serveRuns checks dataset read access.
// Imports additionally require dataset write access. All read results bind to
// the current verified publication, including after restoration or a retry.
func (s *Server) serveEvaluations(w http.ResponseWriter, r *http.Request, p *principal, dataset, id string, parts []string) bool {
	if len(parts) < 3 || parts[2] != "evaluations" {
		return false
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if len(parts) == 3 {
		if r.Method == "POST" {
			if !s.can(ctx, p, dataset, true) {
				fail(w, 403, "forbidden", "dataset write access required")
				return true
			}
			s.importEvaluation(w, r, p, dataset, id)
			return true
		}
		if r.Method == "GET" {
			s.listEvaluations(w, r, p, dataset, id)
			return true
		}
		fail(w, 405, "method_not_allowed", "method not allowed")
		return true
	}
	if !safeID.MatchString(parts[3]) {
		fail(w, 404, "not_found", "evaluation not found")
		return true
	}
	if r.Method != "GET" {
		fail(w, 405, "method_not_allowed", "method not allowed")
		return true
	}
	kind := "result"
	if len(parts) == 5 {
		kind = parts[4]
	} else if len(parts) != 4 {
		fail(w, 404, "not_found", "evaluation route not found")
		return true
	}
	if kind != "result" && kind != "download" && kind != "evidence" {
		fail(w, 404, "not_found", "evaluation route not found")
		return true
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		fail(w, 422, "invalid_evaluation_query", "invalid query encoding")
		return true
	}
	event, reference := "", false
	if kind == "evidence" {
		for key, values := range query {
			if len(values) != 1 || (key != "event" && key != "reference") {
				fail(w, 422, "invalid_evaluation_query", "one event and optional reference=true required")
				return true
			}
		}
		event = query.Get("event")
		if strings.TrimSpace(event) == "" || len(event) > 1024 || (query.Has("reference") && query.Get("reference") != "true") {
			fail(w, 422, "invalid_evaluation_query", "one event and optional reference=true required")
			return true
		}
		reference = query.Get("reference") == "true"
	} else if len(query) != 0 {
		fail(w, 422, "invalid_evaluation_query", "query parameters unsupported")
		return true
	}
	var saved savedEvaluation
	var document string
	err = s.DB.QueryRowContext(ctx, "SELECT id,job_id,dataset_id,document_sha256,created_by,created_at,document_json FROM v3_evaluations WHERE id=$1 AND job_id=$2 AND dataset_id=$3", parts[3], id, dataset).Scan(&saved.ID, &saved.JobID, &saved.DatasetID, &saved.SHA, &saved.CreatedBy, &saved.CreatedAt, &document)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			fail(w, 404, "not_found", "evaluation not found")
		} else {
			fail(w, 503, "database_error", "evaluation unavailable")
		}
		return true
	}
	verified, err := s.verifyEvaluationDocument(r, id, dataset, []byte(document), event, reference)
	if err != nil || verified.SHA != saved.SHA {
		fail(w, 409, "evaluation_unavailable", "saved evaluation or original evidence unavailable or changed")
		return true
	}
	if s.audit(ctx, p, dataset, id, "evaluation_"+kind+"_read", "ok") != nil {
		fail(w, 503, "audit_unavailable", "evaluation read audit unavailable")
		return true
	}
	if kind == "download" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=\"evaluation-"+saved.ID+".json\"")
		w.WriteHeader(200)
		_, _ = w.Write(verified.Document)
		return true
	}
	if kind == "evidence" {
		respondEvaluationEvidence(w, map[string]any{"evaluation": saved, "evidence": verified.Evidence})
		return true
	}
	respond(w, 200, map[string]any{"evaluation": saved, "result": verified.Result})
	return true
}

func (s *Server) importEvaluation(w http.ResponseWriter, r *http.Request, p *principal, dataset, id string) {
	if r.URL.RawQuery != "" {
		fail(w, 422, "invalid_evaluation_query", "query parameters unsupported")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, evaluationV2DocumentLimit))
	if err != nil {
		fail(w, 422, "invalid_evaluation_document", "evaluation document exceeds maximum budget")
		return
	}
	if _, err = evaluationDocumentLimit(raw); err != nil {
		fail(w, 422, "invalid_evaluation_document", "evaluation JSON exceeds its registered version budget")
		return
	}
	verified, err := s.verifyEvaluationDocument(r, id, dataset, raw, "", false)
	if err != nil {
		fail(w, 409, "evaluation_rejected", "evaluation bundle or current publication failed verification")
		return
	}
	tx, err := s.DB.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 503, "database_error", "evaluation storage unavailable")
		return
	}
	defer tx.Rollback()
	saved := savedEvaluation{ID: newID(), JobID: id, DatasetID: dataset, SHA: verified.SHA, CreatedBy: p.ID}
	err = tx.QueryRowContext(r.Context(), "INSERT INTO v3_evaluations(id,job_id,dataset_id,document,document_json,document_sha256,created_by) VALUES($1,$2,$3,$4::text::jsonb,$4::text,$5,$6) ON CONFLICT(job_id,document_sha256) DO NOTHING RETURNING id,created_at", saved.ID, id, dataset, string(verified.Document), verified.SHA, p.ID).Scan(&saved.ID, &saved.CreatedAt)
	status := 201
	if errors.Is(err, sql.ErrNoRows) {
		status = 200
		err = tx.QueryRowContext(r.Context(), "SELECT id,created_at,created_by FROM v3_evaluations WHERE job_id=$1 AND document_sha256=$2 AND dataset_id=$3", id, verified.SHA, dataset).Scan(&saved.ID, &saved.CreatedAt, &saved.CreatedBy)
	}
	if err != nil || auditTx(r.Context(), tx, p, dataset, id, "evaluation_import", "ok") != nil || tx.Commit() != nil {
		fail(w, 503, "database_error", "evaluation storage or audit unavailable")
		return
	}
	respond(w, status, map[string]any{"evaluation": saved, "result": verified.Result})
}

func (s *Server) listEvaluations(w http.ResponseWriter, r *http.Request, p *principal, dataset, id string) {
	if r.URL.RawQuery != "" {
		fail(w, 422, "invalid_evaluation_query", "query parameters unsupported")
		return
	}
	rows, err := s.DB.QueryContext(r.Context(), "SELECT id,job_id,dataset_id,document_sha256,created_by,created_at FROM v3_evaluations WHERE job_id=$1 AND dataset_id=$2 ORDER BY created_at DESC,id LIMIT 100", id, dataset)
	if err != nil {
		fail(w, 503, "database_error", "evaluation list unavailable")
		return
	}
	defer rows.Close()
	items := []savedEvaluation{}
	for rows.Next() {
		var item savedEvaluation
		if rows.Scan(&item.ID, &item.JobID, &item.DatasetID, &item.SHA, &item.CreatedBy, &item.CreatedAt) != nil {
			fail(w, 503, "database_error", "evaluation list unavailable")
			return
		}
		items = append(items, item)
	}
	if rows.Err() != nil {
		fail(w, 503, "database_error", "evaluation list unavailable")
		return
	}
	if s.audit(r.Context(), p, dataset, id, "evaluation_list_read", "ok") != nil {
		fail(w, 503, "audit_unavailable", "evaluation read audit unavailable")
		return
	}
	respond(w, 200, map[string]any{"evaluations": items, "limit": 100, "status": "saved_metadata_only; original evidence reverified on detail, download or evidence reads"})
}

func (s *Server) verifyEvaluationDocument(r *http.Request, id, dataset string, document []byte, event string, reference bool) (verifiedEvaluationDocument, error) {
	var output verifiedEvaluationDocument
	limit, budgetErr := evaluationDocumentLimit(document)
	if budgetErr != nil {
		return output, errors.New("evaluation document outside bounds")
	}
	internal, ok := s.Internal.(*jobapi.Server)
	if !ok {
		return output, errors.New("evaluation adapter unavailable")
	}
	var documentHeader map[string]json.RawMessage
	var adaptedHeader struct {
		Binding struct {
			Projection string `json:"projection"`
		} `json:"binding"`
	}
	if json.Unmarshal(document, &documentHeader) != nil || json.Unmarshal(documentHeader["adapted.json"], &adaptedHeader) != nil || !validPreparationProjection(adaptedHeader.Binding.Projection) {
		return output, errors.New("evaluation projection unavailable")
	}
	prepared, snapshot, handled, err := s.trustedPreparedAdapted(r, id, adaptedHeader.Binding.Projection)
	if err != nil {
		return output, err
	}
	var base, publicationSHA string
	var verifyAfter func() error
	if handled {
		base = filepath.Dir(snapshot.ArtifactPath) + "/"
		publicationSHA = snapshot.CoreManifestSHA256
		verifyAfter = func() error { _, _, err := internal.RecheckPublicationSnapshot(r, id, *snapshot); return err }
	} else {
		before, legacyBase, verifyErr := internal.VerifiedDualArtifacts(r, id)
		if verifyErr != nil {
			return output, verifyErr
		}
		base = legacyBase
		for _, item := range before {
			if item.Path == "run_manifest.json" && shaRE.MatchString(item.SHA) {
				publicationSHA = item.SHA
			}
		}
		verifyAfter = func() error {
			after, afterBase, err := internal.VerifiedDualArtifacts(r, id)
			if err != nil || afterBase != base || !reflect.DeepEqual(after, before) {
				return errors.New("publication changed during evaluation verification")
			}
			return nil
		}
	}
	var batch string
	if err = s.DB.QueryRowContext(r.Context(), "SELECT batch FROM v3_datasets WHERE id=$1", dataset).Scan(&batch); err != nil || strings.TrimSpace(batch) == "" {
		return output, errors.New("dataset batch unavailable")
	}
	if publicationSHA == "" {
		return output, errors.New("verified publication manifest absent")
	}
	args := []string{"-m", "cpag_core.evaluation_bundle", "verify-document", "--artifact", filepath.Join(s.Root, base), "--service-publication-sha256", publicationSHA}
	if event != "" {
		args = append(args, "--id="+event)
		if reference {
			args = append(args, "--reference")
		}
	}
	cmd := exec.CommandContext(r.Context(), s.cfg.PythonBin, args...)
	if handled {
		envelope, err := json.Marshal(map[string]any{"version": "evaluation-service-envelope-1", "document": json.RawMessage(document), "prepared_adapted": json.RawMessage(prepared)})
		if err != nil {
			return output, err
		}
		cmd.Args = append(cmd.Args, "--service-envelope")
		cmd.Stdin = bytes.NewReader(envelope)
	} else {
		cmd.Stdin = bytes.NewReader(document)
	}
	cmd.Env = os.Environ()
	if s.cfg.PythonPath != "" {
		cmd.Env = append(cmd.Env, "PYTHONPATH="+s.cfg.PythonPath)
	}
	cmd.WaitDelay = time.Second
	out, diagnostics := &evaluationBuffer{limit: evaluationEnvelopeLimit}, &evaluationBuffer{limit: 8192}
	cmd.Stdout, cmd.Stderr = out, diagnostics
	if err = cmd.Run(); err != nil {
		return output, err
	}
	decoder := json.NewDecoder(bytes.NewReader(out.Bytes()))
	if decoder.Decode(&output) != nil || decoder.Decode(new(any)) != io.EOF || !shaRE.MatchString(output.SHA) || len(output.Document) == 0 || len(output.Document) > limit || len(output.Result) == 0 || (event != "" && len(output.Evidence) == 0) {
		return output, errors.New("invalid verified evaluation envelope")
	}
	if returnedLimit, err := evaluationDocumentLimit(output.Document); err != nil || returnedLimit != limit {
		return output, errors.New("verified evaluation budget changed")
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(output.Document, &doc) != nil {
		return output, errors.New("invalid verified document")
	}
	var adapted struct {
		Binding struct {
			RunID  string `json:"run_id"`
			Batch  string `json:"batch"`
			Sample string `json:"sample_sha256"`
			Input  string `json:"input_fingerprint"`
		} `json:"binding"`
	}
	if json.Unmarshal(doc["adapted.json"], &adapted) != nil || adapted.Binding.RunID != id || adapted.Binding.Batch != batch || adapted.Binding.Sample != adapted.Binding.Input || !shaRE.MatchString(adapted.Binding.Input) {
		return output, errors.New("evaluation service context differs")
	}
	if err = verifyAfter(); err != nil {
		return output, err
	}
	return output, nil
}

// Marshal the complete response before headers so an oversized original is
// explicitly rejected and cannot become a partial successful evidence body.
func respondEvaluationEvidence(w http.ResponseWriter, value any) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > evaluationProjectionLimit {
		fail(w, 409, "evaluation_evidence_limit_exceeded", "complete evaluation evidence exceeds 8 MiB query budget")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	w.Write(append(raw, '\n'))
}
