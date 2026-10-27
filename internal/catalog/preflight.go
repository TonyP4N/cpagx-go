package catalog

import (
	"context"
	"crypto/sha256"
	"database/sql"
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
	snap, e := s.buildSnapshot(r.Context(), dataset, q.ConfigID, "native", nil)
	if e != nil {
		if errors.Is(e, errNoSourceFiles) {
			fail(w, 422, "missing_source", "upload at least one source file")
			return
		}
		if errors.Is(e, sql.ErrNoRows) {
			fail(w, 422, "invalid_preflight", "intake config version required")
			return
		}
		fail(w, 409, "source_changed", "catalog sources or intake config unavailable or changed")
		return
	}
	reportRaw, report, e := s.runIntake(r.Context(), snap)
	if e != nil {
		fail(w, 503, "preflight_error", "metadata preflight unavailable")
		return
	}
	if integrityErrors(report) {
		_ = s.audit(r.Context(), p, dataset, "", "preflight", "integrity_rejected")
		fail(w, 409, "source_changed", "stored original source changed during preflight")
		return
	}
	snapshotRaw, snapshotSHA, e := snapshotBytes(snap)
	if e != nil {
		fail(w, 503, "preflight_error", "snapshot unavailable")
		return
	}
	preID := newID()
	tx, e := s.DB.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503, "database_error", "preflight unavailable")
		return
	}
	defer tx.Rollback()
	_, e = tx.ExecContext(r.Context(), `INSERT INTO v3_preflights(id,dataset_id,config_version_id,report,created_by,snapshot_json,snapshot_sha256,snapshot_status) VALUES($1,$2,$3,$4,$5,$6,$7,'native')`, preID, dataset, q.ConfigID, string(reportRaw), p.ID, string(snapshotRaw), snapshotSHA)
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

func (s *Server) runIntake(parent context.Context, snap PreflightSnapshot) ([]byte, map[string]any, error) {
	tmp, e := os.MkdirTemp("", "cpag-intake-")
	if e != nil {
		return nil, nil, e
	}
	defer os.RemoveAll(tmp)
	mf := filepath.Join(tmp, "manifest.json")
	if e = os.WriteFile(mf, snap.Manifest, 0600); e != nil {
		return nil, nil, e
	}
	ctx, cancel := context.WithTimeout(parent, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.cfg.PythonBin, "-m", "cpag_core.intake", "--raw-root", s.Root, "--manifest", mf, "--config", filepath.Join(s.Root, snap.Config.Path), "--output", filepath.Join(tmp, "report"), "--json")
	env := os.Environ()
	if s.cfg.PythonPath != "" {
		env = append(env, "PYTHONPATH="+s.cfg.PythonPath)
	}
	cmd.Env = env
	_, _ = cmd.CombinedOutput()
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	raw, e := os.ReadFile(filepath.Join(tmp, "report", "report.json"))
	if e != nil || len(raw) > 65536 {
		return nil, nil, errors.New("intake report unavailable or oversized")
	}
	var report map[string]any
	if json.Unmarshal(raw, &report) != nil {
		return nil, nil, errors.New("invalid intake report")
	}
	return raw, report, nil
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
	for _, code := range []string{"checksum_mismatch", "file_changed", "missing_file", "unsafe_path"} {
		if hasReportCode(report, code) {
			return true
		}
	}
	return false
}
func readyPreflight(report map[string]any) bool {
	if report["status"] != "ready_for_manual_review" || report["source_scope"] != "dual_source" || report["input_fingerprint"] == nil {
		return false
	}
	errors, ok1 := report["errors"].([]any)
	gaps, ok2 := report["material_gaps"].([]any)
	return ok1 && ok2 && len(errors) == 0 && len(gaps) == 0
}
func (s *Server) listPreflights(w http.ResponseWriter, r *http.Request, dataset string) {
	rows, e := s.DB.QueryContext(r.Context(), `SELECT id,config_version_id,report,snapshot_status,snapshot_sha256,snapshot_reason,created_at FROM v3_preflights WHERE dataset_id=$1 ORDER BY created_at DESC LIMIT 200`, dataset)
	if e != nil {
		fail(w, 503, "database_error", "preflight history unavailable")
		return
	}
	defer rows.Close()
	out := []any{}
	for rows.Next() {
		var id, cfg, status string
		var report json.RawMessage
		var sha, reason *string
		var at time.Time
		if rows.Scan(&id, &cfg, &report, &status, &sha, &reason, &at) != nil {
			fail(w, 503, "database_error", "preflight history unavailable")
			return
		}
		out = append(out, map[string]any{"id": id, "config_version_id": cfg, "report": report, "snapshot_status": status, "snapshot_sha256": sha, "snapshot_reason": reason, "created_at": at})
	}
	respond(w, 200, map[string]any{"preflights": out})
}
func (s *Server) getPreflight(w http.ResponseWriter, r *http.Request, dataset, id string) {
	if !safeID.MatchString(id) {
		fail(w, 404, "not_found", "preflight not found")
		return
	}
	var cfg, status string
	var report json.RawMessage
	var raw, sha, reason *string
	var at time.Time
	e := s.DB.QueryRowContext(r.Context(), `SELECT config_version_id,report,snapshot_status,snapshot_json,snapshot_sha256,snapshot_reason,created_at FROM v3_preflights WHERE dataset_id=$1 AND id=$2`, dataset, id).Scan(&cfg, &report, &status, &raw, &sha, &reason, &at)
	if e != nil {
		fail(w, 404, "not_found", "preflight not found")
		return
	}
	var snap any
	if raw != nil && sha != nil {
		parsed, e := parseSnapshot([]byte(*raw), *sha, status)
		if e != nil {
			fail(w, 409, "snapshot_changed", "retained preflight snapshot invalid")
			return
		}
		snap = parsed
	}
	respond(w, 200, map[string]any{"preflight": map[string]any{"id": id, "config_version_id": cfg, "report": report, "snapshot_status": status, "snapshot_sha256": sha, "snapshot_reason": reason, "created_at": at, "snapshot": snap}})
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
