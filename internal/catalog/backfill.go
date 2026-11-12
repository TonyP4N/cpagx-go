package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type BackfillSummary struct {
	ReconstructedPreflights     int `json:"reconstructed_preflights"`
	UnreconstructablePreflights int `json:"unreconstructable_preflights"`
	MatchedLegacyRuns           int `json:"matched_legacy_runs"`
	UnboundLegacyRuns           int `json:"unbound_legacy_runs"`
}

func (s BackfillSummary) HasUnresolved() bool {
	return s.UnreconstructablePreflights > 0 || s.UnboundLegacyRuns > 0
}

// BackfillLegacy is an explicit maintenance command, never part of normal
// startup. It preserves every old report and gives failures a recorded reason.
func (s *Server) BackfillLegacy(ctx context.Context) (BackfillSummary, error) {
	var result BackfillSummary
	rows, e := s.DB.QueryContext(ctx, `SELECT id,dataset_id,config_version_id,report,created_at FROM v3_preflights WHERE snapshot_status='pending_legacy' ORDER BY created_at,id`)
	if e != nil {
		return result, e
	}
	type oldPreflight struct {
		id, dataset, config string
		report              []byte
		at                  time.Time
	}
	pending := []oldPreflight{}
	for rows.Next() {
		var p oldPreflight
		if e = rows.Scan(&p.id, &p.dataset, &p.config, &p.report, &p.at); e != nil {
			rows.Close()
			return result, e
		}
		pending = append(pending, p)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, e
	}
	for _, p := range pending {
		status, reason := "unreconstructable", "historical_input_unavailable_or_ambiguous"
		var raw []byte
		var sha string
		snap, err := s.buildSnapshot(ctx, p.dataset, p.config, "reconstructed", &p.at)
		if err == nil {
			var recalculated []byte
			recalculated, _, err = s.runIntake(ctx, snap)
			if err == nil && sameReport(p.report, recalculated) {
				raw, sha, err = snapshotBytes(snap)
				if err == nil {
					status, reason = "reconstructed", ""
				}
			} else if err == nil {
				reason = "historical_report_mismatch"
			}
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return result, err
		}
		if status == "reconstructed" {
			_, err = tx.ExecContext(ctx, `UPDATE v3_preflights SET snapshot_json=$2,snapshot_sha256=$3,snapshot_status='reconstructed',snapshot_reason=NULL WHERE id=$1 AND snapshot_status='pending_legacy'`, p.id, string(raw), sha)
		} else {
			_, err = tx.ExecContext(ctx, `UPDATE v3_preflights SET snapshot_status='unreconstructable',snapshot_reason=$2 WHERE id=$1 AND snapshot_status='pending_legacy'`, p.id, reason)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO v3_audit_events(dataset_id,action,outcome) VALUES($1,'preflight_backfill',$2)`, p.dataset, status)
		}
		if err != nil {
			tx.Rollback()
			return result, err
		}
		if err = tx.Commit(); err != nil {
			return result, err
		}
		if status == "reconstructed" {
			result.ReconstructedPreflights++
		} else {
			result.UnreconstructablePreflights++
		}
	}
	runRows, e := s.DB.QueryContext(ctx, `SELECT job_id,dataset_id,network_file_id,process_file_id,created_at FROM v3_run_bindings WHERE preflight_link_origin='legacy_unbound' ORDER BY created_at,job_id`)
	if e != nil {
		return result, e
	}
	type oldRun struct {
		id, dataset, network, process string
		at                            time.Time
	}
	oldRuns := []oldRun{}
	for runRows.Next() {
		var r oldRun
		if e = runRows.Scan(&r.id, &r.dataset, &r.network, &r.process, &r.at); e != nil {
			runRows.Close()
			return result, e
		}
		oldRuns = append(oldRuns, r)
	}
	e = runRows.Err()
	runRows.Close()
	if e != nil {
		return result, e
	}
	for _, run := range oldRuns {
		candidates, err := s.matchingLegacyPreflights(ctx, run.dataset, run.network, run.process, run.at)
		if err != nil {
			return result, err
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return result, err
		}
		outcome := "legacy_unbound"
		if len(candidates) == 1 {
			_, err = tx.ExecContext(ctx, `UPDATE v3_run_bindings SET preflight_id=$2,preflight_link_origin='reconstructed_match',preflight_link_reason=NULL WHERE job_id=$1 AND preflight_link_origin='legacy_unbound'`, run.id, candidates[0])
			outcome = "reconstructed_match"
		} else {
			reason := "no unique earlier matching ready preflight"
			if len(candidates) > 1 {
				reason = "multiple earlier matching ready preflights"
			}
			_, err = tx.ExecContext(ctx, `UPDATE v3_run_bindings SET preflight_link_reason=$2 WHERE job_id=$1 AND preflight_link_origin='legacy_unbound'`, run.id, reason)
		}
		if err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO v3_audit_events(dataset_id,job_id,action,outcome) VALUES($1,$2,'legacy_run_association',$3)`, run.dataset, run.id, outcome)
		}
		if err != nil {
			tx.Rollback()
			return result, err
		}
		if err = tx.Commit(); err != nil {
			return result, err
		}
		if len(candidates) == 1 {
			result.MatchedLegacyRuns++
		} else {
			result.UnboundLegacyRuns++
		}
	}
	return result, nil
}
func (s *Server) matchingLegacyPreflights(ctx context.Context, dataset, network, process string, before time.Time) ([]string, error) {
	rows, e := s.DB.QueryContext(ctx, `SELECT id,report,snapshot_json,snapshot_sha256 FROM v3_preflights WHERE dataset_id=$1 AND snapshot_status='reconstructed' AND created_at<=$2 ORDER BY created_at,id`, dataset, before)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	matches := []string{}
	for rows.Next() {
		var id, raw, sha string
		var reportRaw []byte
		if e = rows.Scan(&id, &reportRaw, &raw, &sha); e != nil {
			return nil, e
		}
		var report map[string]any
		if json.Unmarshal(reportRaw, &report) != nil || !readyPreflight(report) {
			continue
		}
		snap, err := parseSnapshot([]byte(raw), sha, "reconstructed")
		if err != nil {
			return nil, fmt.Errorf("historical preflight %s changed: %w", id, err)
		}
		if len(snap.Files) != 2 {
			continue
		}
		foundNetwork, foundProcess := false, false
		for _, f := range snap.Files {
			if f.Role == "network" && f.DatasetFileID == network {
				foundNetwork = true
			}
			if f.Role == "process" && f.DatasetFileID == process {
				foundProcess = true
			}
		}
		if foundNetwork && foundProcess {
			matches = append(matches, id)
		}
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	return matches, nil
}

var _ = errors.New
