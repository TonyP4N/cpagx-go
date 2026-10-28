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
	var replayVersion *string
	// Scan SQL NULL through the standard byte slice destination. A named
	// json.RawMessage slice cannot receive nil through database/sql.
	var captureIDs []byte
	var at time.Time
	e := s.DB.QueryRowContext(r.Context(), "SELECT dataset_id,config_version_id,mode,created_at,preflight_id,preflight_link_origin,network_file_ids,replay_version FROM v3_run_bindings WHERE job_id=$1", id).Scan(&dataset, &config, &mode, &at, &preflightID, &linkOrigin, &captureIDs, &replayVersion)
	if e != nil || !s.can(r.Context(), p, dataset, false) {
		fail(w, 404, "not_found", "run not found")
		return
	}
	if s.serveEvaluations(w, r, p, dataset, id, parts) {
		return
	}
	if len(parts) == 2 && r.Method == "GET" {
		s.getRun(w, r, id, dataset, config, mode, at, preflightID, linkOrigin, json.RawMessage(captureIDs), replayVersion)
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
		case "evaluation-input":
			s.evaluationInput(w, r, p, dataset, id, mode)
			return
		case "result", "graph", "evidence":
			if mode == "dual_source_replay" {
				s.replayProjection(w, r, p, dataset, id, parts[2])
				return
			}
			s.verifiedProjection(w, r, p, dataset, id, parts[2])
			return
		case "revisions", "snapshots":
			if mode != "dual_source_replay" {
				fail(w, 404, "not_found", "replay history not found")
				return
			}
			s.replayProjection(w, r, p, dataset, id, parts[2])
			return
		case "artifacts":
			s.listArtifacts(w, r, p, dataset, id)
			return
		}
	}
	if len(parts) == 4 && parts[2] == "snapshots" && r.Method == "GET" {
		if mode != "dual_source_replay" {
			fail(w, 404, "not_found", "replay snapshot not found")
			return
		}
		query := r.URL.Query()
		query.Set("revision", parts[3])
		r.URL.RawQuery = query.Encode()
		s.replayProjection(w, r, p, dataset, id, "snapshots")
		return
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
	if body(w, r, &q, 8192) != nil || !safeID.MatchString(q.DatasetID) || !safeID.MatchString(q.ConfigID) || (q.Mode != "dual_source" && q.Mode != "dual_source_replay") {
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
	var kind, source, batch, authorization string
	e := s.DB.QueryRowContext(r.Context(), "SELECT source_kind,source,batch,authorization_ref FROM v3_datasets WHERE id=$1", q.DatasetID).Scan(&kind, &source, &batch, &authorization)
	if e != nil {
		fail(w, 404, "not_found", "dataset not found")
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
	if json.Unmarshal(raw, &doc) != nil || !readyDual(doc) || doc["synthetic"] != (kind == "synthetic") {
		_ = s.audit(r.Context(), p, q.DatasetID, "", "run_gate_rejected", "insufficient_basis")
		fail(w, 422, "insufficient_basis", "dual run requires source category, mappings and documented time/provenance basis")
		return
	}
	if kind == "real" {
		provenance, _ := doc["source_provenance"].(map[string]any)
		if provenance["source"] != source || provenance["release"] != batch || provenance["authorization_ref"] != authorization {
			_ = s.audit(r.Context(), p, q.DatasetID, "", "run_gate_rejected", "source_provenance_mismatch")
			fail(w, 422, "source_provenance_mismatch", "dual profile provenance must match dataset source, batch and authorization declarations")
			return
		}
	}
	networks, process, e := s.runFiles(r, q.DatasetID)
	if e != nil {
		_ = s.audit(r.Context(), p, q.DatasetID, "", "run_gate_rejected", "source_count")
		fail(w, 422, "source_count", "one to four network sources and one CSV required")
		return
	}
	if strings.ToLower(filepath.Ext(process.Filename)) != ".csv" {
		_ = s.audit(r.Context(), p, q.DatasetID, "", "run_gate_rejected", "unsupported_format")
		fail(w, 422, "unsupported_format", "process Excel input is accepted for intake and requires traceable CSV conversion before analysis")
		return
	}
	payload := jobapi.Payload{Kind: "dual-source", Profile: jobapi.Ref{Path: cfgPath, SHA: cfgSHA}, Fingerprint: fp}
	payload.ResourceProfile = s.cfg.ResourceProfile
	if value, exists := doc["capacity_profile"]; exists {
		version, ok := value.(string)
		if !ok || version == "" {
			fail(w, 422, "invalid_config", "invalid capacity profile")
			return
		}
		payload.CapacityProfile = version
	}
	if q.Mode == "dual_source_replay" {
		payload.Kind = "dual-source-replay"
		replay, _ := doc["replay"].(map[string]any)
		version, _ := replay["version"].(string)
		payload.ReplayVersion = version
	}
	for i, n := range networks {
		var path string
		if s.DB.QueryRowContext(r.Context(), `SELECT x.storage_path FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.id=$1`, n.ID).Scan(&path) != nil {
			fail(w, 503, "database_error", "source unavailable")
			return
		}
		ref := jobapi.Ref{Path: path, SHA: n.SHA}
		if i == 0 {
			payload.Network = ref
		}
		if len(networks) > 1 {
			payload.Networks = append(payload.Networks, ref)
		}
	}
	var pPath string
	if s.DB.QueryRowContext(r.Context(), `SELECT x.storage_path FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.id=$1`, process.ID).Scan(&pPath) != nil {
		fail(w, 503, "database_error", "source unavailable")
		return
	}
	payload.Process = jobapi.Ref{Path: pPath, SHA: process.SHA}
	if len(networks) > 1 && doc["analysis_mode"] != "bounded-real-capable-v1" {
		fail(w, 422, "invalid_inputs", "multiple captures require bounded analysis mode")
		return
	}
	if e = s.Internal.(*jobapi.Server).ValidatePayload(payload); e != nil {
		_ = s.audit(r.Context(), p, q.DatasetID, "", "run_gate_rejected", "invalid_inputs")
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
	if tx.QueryRowContext(r.Context(), "SELECT count(*) FILTER (WHERE role='network'),count(*) FILTER (WHERE role='process') FROM v3_dataset_files WHERE dataset_id=$1", q.DatasetID).Scan(&networkCount, &processCount) != nil || networkCount != len(networks) || processCount != 1 {
		fail(w, 409, "catalog_changed", "source set changed during submission")
		return
	}
	refsOK := true
	for _, network := range networks {
		if !s.confirmRunRefs(r, tx, q.DatasetID, q.ConfigID, network.ID, process.ID, network.SHA, process.SHA, cfgSHA, fp) {
			refsOK = false
		}
	}
	if !refsOK {
		fail(w, 409, "catalog_changed", "input or version changed during submission")
		return
	}
	_, e = tx.ExecContext(r.Context(), "INSERT INTO m4_jobs(id,max_attempts,payload) VALUES($1,3,$2)", id, string(rawPayload))
	if e == nil {
		_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_run_bindings(job_id,dataset_id,network_file_id,process_file_id,config_version_id,mode,created_by,preflight_id,preflight_link_origin,preflight_link_reason,network_file_ids,replay_version) VALUES($1,$2,$3,$4,$5,$9,$6,$7,'native_gate',NULL,$8,$10)", id, q.DatasetID, networks[0].ID, process.ID, q.ConfigID, p.ID, q.PreflightID, networkIDsJSON(networks), q.Mode, optionalString(payload.ReplayVersion))
	}
	if e == nil {
		e = auditTx(r.Context(), tx, p, q.DatasetID, id, "run_create", "ok")
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "database_error", "run unavailable")
		return
	}
	respond(w, 201, map[string]any{"run": map[string]any{"id": id, "dataset_id": q.DatasetID, "state": "queued", "config_version_id": q.ConfigID, "preflight_id": q.PreflightID, "mode": q.Mode, "replay_version": optionalString(payload.ReplayVersion)}})
}
func readyDual(doc map[string]any) bool {
	if _, ok := doc["synthetic"].(bool); !ok || ((doc["synthetic"] == false || doc["analysis_mode"] == "bounded-real-capable-v1") && !readyRealBasis(doc)) {
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
func (s *Server) runFiles(r *http.Request, dataset string) ([]fileInfo, fileInfo, error) {
	rows, e := s.DB.QueryContext(r.Context(), `SELECT f.id,f.role,f.filename,x.sha256,x.size_bytes,f.created_at FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.dataset_id=$1 ORDER BY f.created_at,f.id`, dataset)
	if e != nil {
		return nil, fileInfo{}, e
	}
	defer rows.Close()
	var n []fileInfo
	var p fileInfo
	nc, pc := 0, 0
	for rows.Next() {
		var f fileInfo
		if e = rows.Scan(&f.ID, &f.Role, &f.Filename, &f.SHA, &f.Size, &f.CreatedAt); e != nil {
			return n, p, e
		}
		if f.Role == "network" {
			n = append(n, f)
			nc++
		} else {
			p = f
			pc++
		}
	}
	if nc < 1 || nc > 4 || pc != 1 {
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
	rows, e := s.DB.QueryContext(r.Context(), "SELECT b.job_id,j.state,j.attempt,b.config_version_id,b.created_at,b.preflight_id,b.preflight_link_origin,b.mode,b.replay_version FROM v3_run_bindings b JOIN m4_jobs j ON j.id=b.job_id WHERE b.dataset_id=$1 ORDER BY b.created_at DESC LIMIT 200", dataset)
	if e != nil {
		fail(w, 503, "database_error", "runs unavailable")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, state, cfg, linkOrigin, mode string
		var replayVersion *string
		var preflightID *string
		var attempt int
		var at time.Time
		if rows.Scan(&id, &state, &attempt, &cfg, &at, &preflightID, &linkOrigin, &mode, &replayVersion) == nil {
			out = append(out, map[string]any{"id": id, "dataset_id": dataset, "state": state, "mode": mode, "replay_version": replayVersion, "attempt": attempt, "config_version_id": cfg, "preflight_id": preflightID, "preflight_link_origin": linkOrigin, "created_at": at})
		}
	}
	respond(w, 200, map[string]any{"runs": out})
}
func (s *Server) getRun(w http.ResponseWriter, r *http.Request, id, dataset, config, mode string, at time.Time, preflightID *string, linkOrigin string, captureIDs json.RawMessage, replayVersion *string) {
	st, e := s.repo.Status(r.Context(), id)
	if e != nil {
		fail(w, 503, "database_error", "run unavailable")
		return
	}
	history := []any{}
	for _, a := range st.AttemptHistory {
		history = append(history, map[string]any{"attempt": a.Attempt, "location": a.Location, "exited_at": a.ExitedAt, "publication_state": a.PublicationState})
	}
	respond(w, 200, map[string]any{"run": map[string]any{"id": id, "dataset_id": dataset, "config_version_id": config, "preflight_id": preflightID, "preflight_link_origin": linkOrigin, "mode": mode, "replay_version": replayVersion, "created_at": at, "state": st.State, "attempt": st.Attempt, "last_error": st.LastError, "network_file_ids": captureIDs, "attempt_history": history, "lease_valid": st.LeaseValid}})
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
		graphResponse := map[string]any{"synthetic": m["synthetic"], "graph": d["graph"]}
		if compatibility, exists := m["compatibility"]; exists {
			graphResponse["compatibility"] = compatibility
		}
		value = graphResponse
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

func networkIDsJSON(files []fileInfo) any {
	if len(files) < 2 {
		return nil
	}
	ids := []string{}
	for _, f := range files {
		ids = append(ids, f.ID)
	}
	raw, _ := json.Marshal(ids)
	return string(raw)
}
func readyRealBasis(doc map[string]any) bool { return jobapi.ReadyRealDualBasis(doc) }

func optionalString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
