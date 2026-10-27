package catalog

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) serveRuns(w http.ResponseWriter, r *http.Request, p *principal, parts []string) {
	if len(parts) == 1 {
		if r.Method == "POST" {
			s.createRun(w, r, p)
		} else if r.Method == "GET" {
			s.listRuns(w, r, p)
		} else {
			fail(w, 405, "method_not_allowed", "method not allowed")
		}
		return
	}
	id := parts[1]
	if !safeID.MatchString(id) {
		fail(w, 404, "not_found", "run not found")
		return
	}
	var dataset, config, mode, linkOrigin string
	var preflightID *string
	var at time.Time
	e := s.DB.QueryRowContext(r.Context(), "SELECT dataset_id,config_version_id,mode,created_at,preflight_id,preflight_link_origin FROM v3_run_bindings WHERE job_id=$1", id).Scan(&dataset, &config, &mode, &at, &preflightID, &linkOrigin)
	if e != nil || !s.can(r.Context(), p, dataset, false) {
		fail(w, 404, "not_found", "run not found")
		return
	}
	if len(parts) == 2 && r.Method == "GET" {
		s.getRun(w, r, id, dataset, config, mode, at, preflightID, linkOrigin)
		return
	}
	if len(parts) == 3 && parts[2] == "cancel" && r.Method == "POST" {
		if !s.can(r.Context(), p, dataset, true) {
			fail(w, 403, "forbidden", "write access required")
			return
		}
		if s.audit(r.Context(), p, dataset, id, "run_cancel_request", "accepted") != nil {
			fail(w, 503, "audit_unavailable", "cancel audit unavailable")
			return
		}
		if e = s.repo.Cancel(r.Context(), id); e != nil {
			_ = s.audit(r.Context(), p, dataset, id, "run_cancel", "failed")
			fail(w, 409, "cancel_conflict", "cannot cancel run")
			return
		}
		_ = s.audit(r.Context(), p, dataset, id, "run_cancel", "ok")
		st, _ := s.repo.Status(r.Context(), id)
		respond(w, 200, map[string]any{"run": map[string]any{"id": id, "state": st.State}})
		return
	}
	if len(parts) == 3 && r.Method == "GET" {
		switch parts[2] {
		case "result", "graph", "evidence":
			s.verifiedProjection(w, r, p, dataset, id, parts[2])
			return
		case "artifacts":
			s.listArtifacts(w, r, p, dataset, id)
			return
		}
	}
	if len(parts) >= 5 && parts[2] == "artifacts" && parts[len(parts)-1] == "download" && r.Method == "GET" {
		s.downloadArtifact(w, r, p, dataset, id, strings.Join(parts[3:len(parts)-1], "/"))
		return
	}
	fail(w, 404, "not_found", "route not found")
}
func (s *Server) createRun(w http.ResponseWriter, r *http.Request, p *principal) {
	var q struct {
		DatasetID   string `json:"dataset_id"`
		ConfigID    string `json:"config_version_id"`
		PreflightID string `json:"preflight_id"`
		Mode        string `json:"mode"`
	}
	if body(w, r, &q, 8192) != nil || !safeID.MatchString(q.DatasetID) || !safeID.MatchString(q.ConfigID) || q.Mode != "dual_source" {
		fail(w, 422, "invalid_run", "dataset, version and supported mode required")
		return
	}
	if !safeID.MatchString(q.PreflightID) {
		_ = s.audit(r.Context(), p, "", "", "run_gate_rejected", "preflight_required")
		fail(w, 422, "preflight_required", "select a current intake preflight")
		return
	}
	if !s.can(r.Context(), p, q.DatasetID, true) {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	var kind string
	e := s.DB.QueryRowContext(r.Context(), "SELECT source_kind FROM v3_datasets WHERE id=$1", q.DatasetID).Scan(&kind)
	if e != nil {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	if kind != "synthetic" {
		fail(w, 422, "unsupported_source", "real material is accepted for preflight only until supported analysis is verified")
		return
	}
	if _, rejected := s.gatePreflight(r.Context(), q.DatasetID, q.PreflightID); rejected != nil {
		_ = s.audit(r.Context(), p, q.DatasetID, "", "run_gate_rejected", rejected.code)
		fail(w, rejected.status, rejected.code, rejected.message)
		return
	}
	var cfgKind, cfgPath, cfgSHA, fp string
	var raw []byte
	e = s.DB.QueryRowContext(r.Context(), "SELECT kind,profile_storage_path,profile_sha256,config_fingerprint,profile_json FROM v3_config_versions WHERE dataset_id=$1 AND id=$2", q.DatasetID, q.ConfigID).Scan(&cfgKind, &cfgPath, &cfgSHA, &fp, &raw)
	if e != nil || cfgKind != "dual" {
		fail(w, 422, "invalid_config", "dual config version required")
		return
	}
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil || !readyDual(doc) {
		_ = s.audit(r.Context(), p, q.DatasetID, "", "run_gate_rejected", "insufficient_basis")
		fail(w, 422, "insufficient_basis", "synthetic dual run requires mappings and explicit clock basis, offset and uncertainty")
		return
	}
	network, process, e := s.runFiles(r, q.DatasetID)
	if e != nil {
		fail(w, 422, "source_count", "one network and one process source required for current dual core")
		return
	}
	var nPath, pPath string
	e = s.DB.QueryRowContext(r.Context(), `SELECT x.storage_path FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.id=$1`, network.ID).Scan(&nPath)
	if e != nil {
		fail(w, 503, "database_error", "source unavailable")
		return
	}
	e = s.DB.QueryRowContext(r.Context(), `SELECT x.storage_path FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.id=$1`, process.ID).Scan(&pPath)
	if e != nil {
		fail(w, 503, "database_error", "source unavailable")
		return
	}
	// M4 validates profile and source bytes, paths, bounds and fingerprint.
	payload := jobapi.Payload{Kind: "dual-source", Network: jobapi.Ref{Path: nPath, SHA: network.SHA}, Process: jobapi.Ref{Path: pPath, SHA: process.SHA}, Profile: jobapi.Ref{Path: cfgPath, SHA: cfgSHA}, Fingerprint: fp}
	if e = s.Internal.(*jobapi.Server).ValidatePayload(payload); e != nil {
		fail(w, 422, "invalid_inputs", "input or profile validation failed")
		return
	}
	rawPayload, _ := json.Marshal(payload)
	id := newID()
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_error", "run unavailable")
		return
	}
	defer tx.Rollback()
	// Lock the dataset to serialize catalog changes with snapshot selection.
	var locked string
	if tx.QueryRowContext(r.Context(), "SELECT id FROM v3_datasets WHERE id=$1 FOR UPDATE", q.DatasetID).Scan(&locked) != nil {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	if _, rejected := s.gatePreflight(r.Context(), q.DatasetID, q.PreflightID); rejected != nil {
		_ = tx.Rollback()
		_ = s.audit(r.Context(), p, q.DatasetID, "", "run_gate_rejected", rejected.code)
		fail(w, rejected.status, rejected.code, rejected.message)
		return
	}
	var networkCount, processCount int
	if tx.QueryRowContext(r.Context(), "SELECT count(*) FILTER (WHERE role='network'),count(*) FILTER (WHERE role='process') FROM v3_dataset_files WHERE dataset_id=$1", q.DatasetID).Scan(&networkCount, &processCount) != nil || networkCount != 1 || processCount != 1 {
		fail(w, 409, "catalog_changed", "source set changed during submission")
		return
	}
	if !s.confirmRunRefs(r, tx, q.DatasetID, q.ConfigID, network.ID, process.ID, network.SHA, process.SHA, cfgSHA, fp) {
		fail(w, 409, "catalog_changed", "input or version changed during submission")
		return
	}
	_, e = tx.ExecContext(r.Context(), "INSERT INTO m4_jobs(id,max_attempts,payload) VALUES($1,3,$2)", id, string(rawPayload))
	if e == nil {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_run_bindings(job_id,dataset_id,network_file_id,process_file_id,config_version_id,mode,created_by,preflight_id,preflight_link_origin,preflight_link_reason) VALUES($1,$2,$3,$4,$5,'dual_source',$6,$7,'native_gate',NULL)", id, q.DatasetID, network.ID, process.ID, q.ConfigID, p.ID, q.PreflightID)
	}
	if e == nil {
		e = auditTx(r.Context(), tx, p, q.DatasetID, id, "run_create", "ok")
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "database_error", "run unavailable")
		return
	}
	respond(w, 201, map[string]any{"run": map[string]any{"id": id, "dataset_id": q.DatasetID, "state": "queued", "config_version_id": q.ConfigID, "preflight_id": q.PreflightID, "mode": "dual_source"}})
}
func readyDual(doc map[string]any) bool {
	if doc["synthetic"] != true {
		return false
	}
	m, ok := doc["mappings"].([]any)
	if !ok || len(m) == 0 {
		return false
	}
	clocks, ok := doc["clocks"].(map[string]any)
	if !ok {
		return false
	}
	for _, name := range []string{"network", "process"} {
		c, ok := clocks[name].(map[string]any)
		if !ok {
			return false
		}
		basis, ok := c["basis"].(string)
		if !ok || strings.TrimSpace(basis) == "" || c["offset_seconds"] == nil || c["uncertainty_seconds"] == nil {
			return false
		}
	}
	return true
}
func (s *Server) runFiles(r *http.Request, dataset string) (fileInfo, fileInfo, error) {
	rows, e := s.DB.QueryContext(r.Context(), `SELECT f.id,f.role,f.filename,x.sha256,x.size_bytes,f.created_at FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.dataset_id=$1`, dataset)
	if e != nil {
		return fileInfo{}, fileInfo{}, e
	}
	defer rows.Close()
	var n, p fileInfo
	nc, pc := 0, 0
	for rows.Next() {
		var f fileInfo
		if e = rows.Scan(&f.ID, &f.Role, &f.Filename, &f.SHA, &f.Size, &f.CreatedAt); e != nil {
			return n, p, e
		}
		if f.Role == "network" {
			n = f
			nc++
		} else {
			p = f
			pc++
		}
	}
	if nc != 1 || pc != 1 {
		return n, p, errors.New("source count")
	}
	return n, p, nil
}
func (s *Server) confirmRunRefs(r *http.Request, tx *sql.Tx, dataset, cfg, n, p, nsha, psha, csha, fp string) bool {
	var role, sha string
	for _, x := range []struct{ id, wantRole, wantSHA string }{{n, "network", nsha}, {p, "process", psha}} {
		if tx.QueryRowContext(r.Context(), `SELECT f.role,x.sha256 FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.dataset_id=$1 AND f.id=$2`, dataset, x.id).Scan(&role, &sha) != nil || role != x.wantRole || sha != x.wantSHA {
			return false
		}
	}
	var kind, profileSHA, fingerprint string
	return tx.QueryRowContext(r.Context(), "SELECT kind,profile_sha256,config_fingerprint FROM v3_config_versions WHERE dataset_id=$1 AND id=$2", dataset, cfg).Scan(&kind, &profileSHA, &fingerprint) == nil && kind == "dual" && profileSHA == csha && fingerprint == fp
}
func (s *Server) listRuns(w http.ResponseWriter, r *http.Request, p *principal) {
	dataset := r.URL.Query().Get("dataset_id")
	if dataset == "" || !s.can(r.Context(), p, dataset, false) {
		fail(w, 404, "not_found", "dataset not found")
		return
	}
	rows, e := s.DB.QueryContext(r.Context(), "SELECT b.job_id,j.state,j.attempt,b.config_version_id,b.created_at,b.preflight_id,b.preflight_link_origin FROM v3_run_bindings b JOIN m4_jobs j ON j.id=b.job_id WHERE b.dataset_id=$1 ORDER BY b.created_at DESC LIMIT 200", dataset)
	if e != nil {
		fail(w, 503, "database_error", "runs unavailable")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, state, cfg, linkOrigin string
		var preflightID *string
		var attempt int
		var at time.Time
		if rows.Scan(&id, &state, &attempt, &cfg, &at, &preflightID, &linkOrigin) == nil {
			out = append(out, map[string]any{"id": id, "dataset_id": dataset, "state": state, "attempt": attempt, "config_version_id": cfg, "preflight_id": preflightID, "preflight_link_origin": linkOrigin, "created_at": at})
		}
	}
	respond(w, 200, map[string]any{"runs": out})
}
func (s *Server) getRun(w http.ResponseWriter, r *http.Request, id, dataset, config, mode string, at time.Time, preflightID *string, linkOrigin string) {
	st, e := s.repo.Status(r.Context(), id)
	if e != nil {
		fail(w, 503, "database_error", "run unavailable")
		return
	}
	history := []any{}
	for _, a := range st.AttemptHistory {
		history = append(history, map[string]any{"attempt": a.Attempt, "location": a.Location, "exited_at": a.ExitedAt, "publication_state": a.PublicationState})
	}
	respond(w, 200, map[string]any{"run": map[string]any{"id": id, "dataset_id": dataset, "config_version_id": config, "preflight_id": preflightID, "preflight_link_origin": linkOrigin, "mode": mode, "created_at": at, "state": st.State, "attempt": st.Attempt, "last_error": st.LastError, "attempt_history": history, "lease_valid": st.LeaseValid}})
}
func (s *Server) verifiedProjection(w http.ResponseWriter, r *http.Request, p *principal, dataset, id, kind string) {
	path := "/v1/jobs/" + id + "/dual-result"
	if kind == "evidence" {
		path = "/v1/jobs/" + id + "/dual-evidence?" + r.URL.RawQuery
	}
	req := httptest.NewRequest("GET", path, nil).WithContext(r.Context())
	req.Header.Set("Authorization", "Bearer "+s.cfg.WorkerToken)
	rec := httptest.NewRecorder()
	s.Internal.ServeHTTP(rec, req)
	if rec.Code != 200 {
		fail(w, 409, "result_unavailable", "published result unavailable or changed")
		return
	}
	var value any
	if json.Unmarshal(rec.Body.Bytes(), &value) != nil {
		fail(w, 409, "result_invalid", "verified result invalid")
		return
	}
	if kind == "graph" {
		m, _ := value.(map[string]any)
		d, _ := m["data"].(map[string]any)
		value = map[string]any{"synthetic": true, "graph": d["graph"]}
	}
	if s.audit(r.Context(), p, dataset, id, "result_read", "ok") != nil {
		fail(w, 503, "audit_unavailable", "read audit unavailable")
		return
	}
	respond(w, 200, value)
}
func (s *Server) listArtifacts(w http.ResponseWriter, r *http.Request, p *principal, dataset, id string) {
	items, _, e := s.Internal.(*jobapi.Server).VerifiedDualArtifacts(r, id)
	if e != nil {
		fail(w, 409, "result_unavailable", "published artifacts unavailable or changed")
		return
	}
	if s.audit(r.Context(), p, dataset, id, "artifact_list", "ok") != nil {
		fail(w, 503, "audit_unavailable", "read audit unavailable")
		return
	}
	respond(w, 200, map[string]any{"artifacts": items})
}
func (s *Server) downloadArtifact(w http.ResponseWriter, r *http.Request, p *principal, dataset, id, name string) {
	items, base, e := s.Internal.(*jobapi.Server).VerifiedDualArtifacts(r, id)
	if e != nil {
		fail(w, 409, "result_unavailable", "published artifacts unavailable or changed")
		return
	}
	for _, x := range items {
		if x.Path == name {
			path := filepath.Join(s.Root, base, name)
			if s.audit(r.Context(), p, dataset, id, "artifact_download", "ok") != nil {
				fail(w, 503, "audit_unavailable", "download audit unavailable")
				return
			}
			w.Header().Set("Content-Disposition", "attachment; filename=\""+filepath.Base(name)+"\"")
			http.ServeFile(w, r, path)
			return
		}
	}
	fail(w, 404, "not_found", "artifact not found")
}
