package catalog

import (
	"context"
	"encoding/json"
	"strings"
)

type gateFailure struct {
	status        int
	code, message string
}

func (e *gateFailure) Error() string                     { return e.code }
func gate(status int, code, message string) *gateFailure { return &gateFailure{status, code, message} }

// gatePreflight is called before payload assembly and again after the dataset
// row is locked in the enqueue transaction. It never treats a reconstructed
// historical report as proof that a new run passed the current gate.
func (s *Server) gatePreflight(ctx context.Context, dataset, id string) (PreflightSnapshot, *gateFailure) {
	var zero PreflightSnapshot
	if !safeID.MatchString(id) {
		return zero, gate(422, "preflight_required", "select a current intake preflight")
	}
	var cfg, status, raw, sha string
	var reportRaw []byte
	e := s.DB.QueryRowContext(ctx, `SELECT config_version_id,report,snapshot_status,snapshot_json,snapshot_sha256 FROM v3_preflights WHERE dataset_id=$1 AND id=$2`, dataset, id).Scan(&cfg, &reportRaw, &status, &raw, &sha)
	if e != nil {
		return zero, gate(422, "preflight_required", "select a current intake preflight")
	}
	var report map[string]any
	if json.Unmarshal(reportRaw, &report) != nil {
		return zero, gate(409, "preflight_stale", "retained preflight report invalid")
	}
	if status != "native" {
		return zero, gate(422, "preflight_required", "run requires a fresh native preflight")
	}
	saved, e := parseSnapshot([]byte(raw), sha, status)
	if e != nil {
		return zero, gate(409, "preflight_stale", "retained preflight snapshot changed")
	}
	if saved.Dataset.ID != dataset || saved.Config.ID != cfg {
		return zero, gate(409, "preflight_stale", "preflight snapshot identity changed")
	}
	current, e := s.buildSnapshot(ctx, dataset, cfg, "native", nil)
	if e != nil {
		return zero, gate(409, "preflight_stale", "preflight inputs or configuration changed")
	}
	if !sameSnapshotInputs(saved, current) {
		return zero, gate(409, "preflight_stale", "catalog input set or metadata changed since preflight")
	}
	// The report is a separate jsonb column. Recompute it from the frozen
	// manifest and retained config so an edited ready/gaps result cannot pass.
	recomputed, _, e := s.runIntake(ctx, saved)
	if e != nil {
		return zero, gate(503, "preflight_unavailable", "preflight verification unavailable")
	}
	if !sameReport(reportRaw, recomputed) {
		return zero, gate(409, "preflight_stale", "retained preflight report differs from fixed inputs")
	}
	if hasReportCode(report, "batch_conflict") {
		return zero, gate(409, "batch_conflict", "intake configuration and dataset batch conflict")
	}
	if !readyPreflight(report) || strings.TrimSpace(saved.Dataset.Source) == "" || strings.TrimSpace(saved.Dataset.Batch) == "" || strings.TrimSpace(saved.Dataset.AuthorizationRef) == "" {
		return zero, gate(422, "preflight_incomplete", "source, authorization, time or mapping material is incomplete")
	}
	return saved, nil
}
