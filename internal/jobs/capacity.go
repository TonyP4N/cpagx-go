package jobs

import (
	"context"
	"database/sql"
	"errors"
	"github.com/TonyP4N/cpagx-go/internal/capacity"
)

const capacityLock int64 = 19002801

// EnableCapacityPolicy is explicit, durable and monotonic. No HTTP endpoint
// disables it. Existing unexplained executions must be recovered first.
func (r Repository) EnableCapacityPolicy(ctx context.Context, profile string) error {
	if profile != capacity.Engineering {
		return errors.New("unsupported site capacity policy")
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, capacityLock); err != nil {
		return err
	}
	var current string
	if err = tx.QueryRowContext(ctx, `SELECT profile FROM m4_capacity_policy WHERE singleton=true FOR UPDATE`).Scan(&current); err != nil {
		return err
	}
	if current == profile {
		return tx.Commit()
	}
	if current != "" {
		return errors.New("site capacity policy mismatch")
	}
	pending, err := unexitedAttempts(ctx, tx)
	if err != nil {
		return err
	}
	if pending {
		return errors.New("site capacity policy requires verified exit of all existing attempts")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE m4_capacity_policy SET profile=$1,enabled_at=clock_timestamp() WHERE singleton=true`, profile); err != nil {
		return err
	}
	return tx.Commit()
}

func unexitedAttempts(ctx context.Context, tx *sql.Tx) (bool, error) {
	var pending bool
	err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m4_job_attempts WHERE exited_at IS NULL) OR EXISTS(SELECT 1 FROM m4_jobs j WHERE j.attempt>0 AND NOT EXISTS(SELECT 1 FROM m4_job_attempts a WHERE a.job_id=j.id AND a.attempt=j.attempt AND a.exited_at IS NOT NULL))`).Scan(&pending)
	return pending, err
}

func claimCapacity(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, capacityLock); err != nil {
		return err
	}
	var profile string
	if err := tx.QueryRowContext(ctx, `SELECT profile FROM m4_capacity_policy WHERE singleton=true`).Scan(&profile); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("site capacity policy row missing")
		}
		return err
	}
	if profile == "" {
		return nil
	}
	if profile != capacity.Engineering {
		return errors.New("unsupported persisted site capacity policy")
	}
	pending, err := unexitedAttempts(ctx, tx)
	if err != nil {
		return err
	}
	if pending {
		return sql.ErrNoRows
	}
	return nil
}
