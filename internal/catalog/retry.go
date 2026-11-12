package catalog

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/TonyP4N/cpagx-go/internal/jobapi"
)

// retryRun reopens the original immutable binding. Claim allocates the next
// attempt and token; neither the caller nor this endpoint manufactures one.
func (s *Server) retryRun(w http.ResponseWriter, r *http.Request, p *principal, dataset, id string, nativeBinding bool) {
	if !s.can(r.Context(), p, dataset, true) {
		fail(w, 403, "forbidden", "dataset write access required")
		return
	}
	if !nativeBinding {
		fail(w, 409, "retry_binding_unverified", "This historical run lacks an original admission binding. Submit a new run after preflight.")
		return
	}
	var q struct {
		Attempt *int `json:"expected_attempt"`
	}
	if body(w, r, &q, 1024) != nil || q.Attempt == nil || *q.Attempt < 0 {
		fail(w, 422, "invalid_attempt", "current attempt required")
		return
	}
	ctx := r.Context()
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		fail(w, 503, "database_error", "retry unavailable")
		return
	}
	defer tx.Rollback()
	var raw []byte
	err = tx.QueryRowContext(ctx, `SELECT payload FROM m4_jobs j WHERE id=$1 AND state IN ('failed','cancelled') AND attempt=$2 AND attempt<max_attempts
 AND (SELECT count(*) FROM m4_job_attempts a WHERE a.job_id=j.id AND a.attempt BETWEEN 1 AND j.attempt AND a.exited_at IS NOT NULL AND a.publication_state='fenced')=j.attempt
 AND NOT EXISTS (SELECT 1 FROM m4_compact_verifications v WHERE v.job_id=j.id AND v.state='running') FOR UPDATE`, id, *q.Attempt).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		fail(w, 409, "retry_conflict", "Refresh the run. Retry requires a terminal failed/cancelled run, remaining attempts and all previous executions confirmed exited.")
		return
	}
	if err != nil {
		fail(w, 503, "database_error", "retry unavailable")
		return
	}
	var payload jobapi.Payload
	if json.Unmarshal(raw, &payload) != nil || s.Internal.(*jobapi.Server).ValidatePayload(payload) != nil {
		fail(w, 409, "retry_input_invalid", "Original inputs, configuration or execution policy cannot be verified")
		return
	}
	_, err = tx.ExecContext(ctx, "UPDATE m4_jobs SET state='queued',available_at=clock_timestamp(),recovery_deadline=NULL,recovery_checked_at=NULL,recovery_reason=NULL WHERE id=$1", id)
	if err == nil {
		err = auditTx(ctx, tx, p, dataset, id, "run_retry", "queued")
	}
	if err != nil || tx.Commit() != nil {
		fail(w, 503, "database_error", "retry not confirmed")
		return
	}
	respond(w, 200, map[string]any{"run": map[string]any{"id": id, "state": "queued", "attempt": *q.Attempt}})
}
