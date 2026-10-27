package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func (s *Server) preflight(w http.ResponseWriter, r *http.Request, p *principal, dataset string) {
	if !s.can(r.Context(), p, dataset, true) {
		fail(w, 403, "forbidden", "write access required")
		return
	}
	var q struct {
		ConfigID string `json:"config_version_id"`
	}
	if body(w, r, &q, 4096) != nil || !safeID.MatchString(q.ConfigID) {
		fail(w, 422, "invalid_preflight", "intake config version required")
		return
	}
	var kind, source, batch, auth, sourceKind, configPath, configSHA string
	e := s.DB.QueryRowContext(r.Context(), `SELECT c.kind,d.source,d.batch,d.authorization_ref,d.source_kind,c.profile_storage_path,c.profile_sha256 FROM v3_config_versions c JOIN v3_datasets d ON d.id=c.dataset_id WHERE c.dataset_id=$1 AND c.id=$2`, dataset, q.ConfigID).Scan(&kind, &source, &batch, &auth, &sourceKind, &configPath, &configSHA)
	if e != nil || kind != "intake" {
		fail(w, 422, "invalid_preflight", "intake config version required")
		return
	}
	// The immutable file is checked again by the intake CLI. Do not trust JSONB
	// alone: backup and audit require exact retained bytes.
	if _, e = s.verifiedFileHash(configPath, configSHA); e != nil {
		fail(w, 409, "config_changed", "intake config changed")
		return
	}
	entries := []map[string]any{}
	rows, e := s.DB.QueryContext(r.Context(), `SELECT f.role,x.storage_path,x.sha256,x.size_bytes FROM v3_dataset_files f JOIN v3_source_files x ON x.id=f.source_file_id WHERE f.dataset_id=$1 ORDER BY f.id`, dataset)
	if e != nil {
		fail(w, 503, "database_error", "sources unavailable")
		return
	}
	defer rows.Close()
	for rows.Next() {
		var role, path, sha string
		var size int64
		if rows.Scan(&role, &path, &sha, &size) != nil {
			fail(w, 503, "database_error", "sources unavailable")
			return
		}
		if !strings.HasPrefix(path, filepath.Join("inputs", "catalog", dataset)+string(filepath.Separator)) {
			fail(w, 409, "source_conflict", "source path does not belong to dataset")
			return
		}
		if _, e = s.verifiedFile(path, sha, size); e != nil {
			_ = s.audit(r.Context(), p, dataset, "", "preflight", "integrity_rejected")
			fail(w, 409, "source_changed", "stored original source changed")
			return
		}
		entries = append(entries, map[string]any{"name": path, "sha256": sha, "size_bytes": size, "kind": role})
	}
	if len(entries) == 0 {
		fail(w, 422, "missing_source", "upload at least one source file")
		return
	}
	manifest := map[string]any{"schema_version": "1.0.0", "synthetic": sourceKind == "synthetic", "dataset_id": dataset, "source": source, "release": batch, "files": entries, "collection_range": map[string]any{"start": nil, "end": nil}, "timezone_basis": nil, "authorization_ref": auth}
	raw, _ := json.Marshal(manifest)
	tmp, e := os.MkdirTemp("", "cpag-intake-")
	if e != nil {
		fail(w, 503, "storage_error", "preflight unavailable")
		return
	}
	defer os.RemoveAll(tmp)
	mf := filepath.Join(tmp, "manifest.json")
	if e = os.WriteFile(mf, raw, 0600); e != nil {
		fail(w, 503, "storage_error", "preflight unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.PythonBin, "-m", "cpag_core.intake", "--raw-root", s.Root, "--manifest", mf, "--config", filepath.Join(s.Root, configPath), "--output", filepath.Join(tmp, "report"), "--json")
	env := os.Environ()
	if s.cfg.PythonPath != "" {
		env = append(env, "PYTHONPATH="+s.cfg.PythonPath)
	}
	cmd.Env = env
	output, e := cmd.CombinedOutput()
	if ctx.Err() != nil {
		fail(w, 503, "preflight_timeout", "preflight timed out")
		return
	}
	reportRaw, readErr := os.ReadFile(filepath.Join(tmp, "report", "report.json"))
	if readErr != nil || len(reportRaw) > 65536 {
		_ = output
		_ = e
		fail(w, 503, "preflight_error", "metadata preflight unavailable")
		return
	}
	var report map[string]any
	if json.Unmarshal(reportRaw, &report) != nil {
		fail(w, 503, "preflight_error", "invalid preflight report")
		return
	}
	if integrityErrors(report) {
		_ = s.audit(r.Context(), p, dataset, "", "preflight", "integrity_rejected")
		fail(w, 409, "source_changed", "stored original source changed during preflight")
		return
	}
	preID := newID()
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_error", "preflight unavailable")
		return
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(r.Context(), "INSERT INTO v3_preflights(id,dataset_id,config_version_id,report,created_by) VALUES($1,$2,$3,$4,$5)", preID, dataset, q.ConfigID, string(reportRaw), p.ID)
	if e == nil {
		outcome := "ok"
		if hasReportCode(report, "batch_conflict") {
			outcome = "batch_conflict"
		}
		e = auditTx(r.Context(), tx, p, dataset, "", "preflight", outcome)
	}
	if e != nil || tx.Commit() != nil {
		fail(w, 503, "database_error", "preflight unavailable")
		return
	}
	if hasReportCode(report, "batch_conflict") {
		respond(w, 409, map[string]any{"error": apiError{"batch_conflict", "dataset and intake configuration batch identity disagree"}, "preflight_id": preID, "report": report})
		return
	}
	respond(w, 200, map[string]any{"preflight_id": preID, "report": report})
}
func hasReportCode(report map[string]any, code string) bool {
	codes, ok := report["errors"].([]any)
	if !ok {
		return false
	}
	for _, v := range codes {
		if v == code {
			return true
		}
	}
	return false
}
func integrityErrors(report map[string]any) bool {
	codes, ok := report["errors"].([]any)
	if !ok {
		return false
	}
	for _, v := range codes {
		switch v {
		case "checksum_mismatch", "file_changed", "missing_file", "unsafe_path":
			return true
		}
	}
	return false
}
func (s *Server) verifiedFileHash(rel, sha string) (string, error) {
	if filepath.IsAbs(rel) || filepath.Clean(rel) != rel || !strings.HasPrefix(rel, "inputs/catalog/") || strings.Contains(rel, "..") || !shaRE.MatchString(sha) {
		return "", errors.New("unsafe config reference")
	}
	p := filepath.Join(s.Root, rel)
	real, e := filepath.EvalSymlinks(p)
	if e != nil || real != p {
		return "", errors.New("missing config")
	}
	st, e := os.Stat(p)
	if e != nil || !st.Mode().IsRegular() || st.Size() > 65536 {
		return "", errors.New("config size changed")
	}
	raw, e := os.ReadFile(p)
	if e != nil {
		return "", e
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != sha {
		return "", errors.New("config hash changed")
	}
	return p, nil
}
