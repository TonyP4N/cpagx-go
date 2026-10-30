package jobs

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// BeginCompactVerification reserves the same durable site slot after compute
// exit; a verifier remains outstanding until Docker removal is proven.
func (r Repository) BeginCompactVerification(ctx context.Context, id string, attempt int, name string, terminal bool) (time.Time, error) {
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, capacityLock); err != nil {
		return time.Time{}, err
	}
	var claimed time.Time
	var state string
	var current int
	var live sql.NullBool
	if err = tx.QueryRowContext(ctx, `SELECT j.state,j.attempt,j.lease_until>clock_timestamp(),a.claimed_at FROM m4_jobs j JOIN m4_job_attempts a ON a.job_id=j.id AND a.attempt=$2 WHERE j.id=$1 FOR UPDATE OF j`, id, attempt).Scan(&state, &current, &live, &claimed); err != nil {
		return claimed, err
	}
	if current != attempt || (!terminal && (state != "running" || !live.Valid || !live.Bool)) || (terminal && state != "succeeded") {
		return claimed, ErrStale
	}
	pending, err := unexitedAttempts(ctx, tx)
	if err != nil {
		return claimed, err
	}
	if pending {
		return claimed, errors.New("compact verification requires idle durable capacity slot")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO m4_compact_verifications(job_id,attempt,container_name,state) VALUES($1,$2,$3,'running') ON CONFLICT(job_id,attempt) DO UPDATE SET container_name=$3,state='running',started_at=clock_timestamp(),exited_at=NULL WHERE m4_compact_verifications.state='exited'`, id, attempt, name); err != nil {
		return claimed, err
	}
	var actual string
	if err = tx.QueryRowContext(ctx, `SELECT container_name FROM m4_compact_verifications WHERE job_id=$1 AND attempt=$2`, id, attempt).Scan(&actual); err != nil || actual != name {
		return claimed, errors.New("compact verifier already active")
	}
	return claimed, tx.Commit()
}
func (r Repository) FinishCompactVerification(ctx context.Context, id string, attempt int, name string) error {
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_compact_verifications SET state='exited',exited_at=clock_timestamp() WHERE job_id=$1 AND attempt=$2 AND container_name=$3 AND state='running'`, id, attempt, name))
}
