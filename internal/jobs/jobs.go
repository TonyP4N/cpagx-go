// Package jobs is an opt-in persistence prototype. No existing route or executor uses it.
package jobs

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path"
	"regexp"
	"time"
)

var ErrStale = errors.New("job attempt is stale, expired or cancelled")
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Repository struct{ DB *sql.DB }
type Claim struct {
	ID      string
	Attempt int
	Worker  string
}

func (r Repository) Enqueue(ctx context.Context, id string, maxAttempts int) error {
	if id == "" || maxAttempts < 1 || maxAttempts > 100 {
		return errors.New("invalid job")
	}
	_, err := r.DB.ExecContext(ctx, `INSERT INTO m4_jobs(id,max_attempts) VALUES($1,$2)`, id, maxAttempts)
	return err
}

// Claim atomically locks and fences one eligible task. Expired final attempts are terminal.
// Durations are bounded; all lease comparisons use database time.
func (r Repository) Claim(ctx context.Context, worker string, lease time.Duration) (Claim, error) {
	if worker == "" || lease < time.Second || lease > time.Hour {
		return Claim{}, errors.New("invalid worker or lease")
	}
	_, err := r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state='failed',lease_until=NULL,last_error='lease expired at attempt limit' WHERE state='running' AND lease_until<=clock_timestamp() AND attempt>=max_attempts`)
	if err != nil {
		return Claim{}, err
	}
	var c Claim
	err = r.DB.QueryRowContext(ctx, `WITH candidate AS (
 SELECT id FROM m4_jobs WHERE attempt<max_attempts AND
 ((state='queued' AND available_at<=clock_timestamp()) OR (state='running' AND lease_until<=clock_timestamp()))
 ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1)
 UPDATE m4_jobs j SET state='running',attempt=j.attempt+1,worker=$1,
 lease_until=clock_timestamp()+($2 * interval '1 millisecond') FROM candidate c WHERE j.id=c.id
 RETURNING j.id,j.attempt,j.worker`, worker, lease.Milliseconds()).Scan(&c.ID, &c.Attempt, &c.Worker)
	return c, err
}
func affected(result sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrStale
	}
	return nil
}
func (r Repository) Heartbeat(ctx context.Context, c Claim, lease time.Duration) error {
	if lease < time.Second || lease > time.Hour {
		return errors.New("invalid lease")
	}
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET lease_until=clock_timestamp()+($4 * interval '1 millisecond') WHERE id=$1 AND attempt=$2 AND worker=$3 AND state='running' AND lease_until>clock_timestamp()`, c.ID, c.Attempt, c.Worker, lease.Milliseconds()))
}

// Fail retries with bounded exponential backoff (1s..256s); final failure is terminal.
func (r Repository) Fail(ctx context.Context, c Claim, message string, retryable bool) error {
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state=CASE WHEN $5 AND attempt<max_attempts THEN 'queued' ELSE 'failed' END,
 available_at=clock_timestamp()+(power(2,least(attempt-1,8))*interval '1 second'),lease_until=NULL,last_error=$4
 WHERE id=$1 AND attempt=$2 AND worker=$3 AND state='running' AND lease_until>clock_timestamp()`, c.ID, c.Attempt, c.Worker, message, retryable))
}

// Cancel requests stopping a running worker; only AcknowledgeCancel can confirm exit.
// Repeated cancellation preserves terminal state and is idempotent.
func (r Repository) Cancel(ctx context.Context, id string) error {
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state=CASE WHEN state='queued' THEN 'cancelled' WHEN state='running' THEN 'cancelling' ELSE state END WHERE id=$1`, id))
}

// AcknowledgeCancel must be called only after the attempt's subprocess has exited.
// Recovery also must independently confirm no process remains before acknowledging.
func (r Repository) AcknowledgeCancel(ctx context.Context, c Claim) error {
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state='cancelled',lease_until=NULL WHERE id=$1 AND attempt=$2 AND worker=$3 AND state='cancelling'`, c.ID, c.Attempt, c.Worker))
}

// ArtifactKey gives each attempt a distinct relative immutable destination.
func ArtifactKey(c Claim, sha string) (string, error) {
	if c.ID == "" || c.ID == "." || c.ID == ".." || path.Base(c.ID) != c.ID || c.Attempt < 1 || !digest.MatchString(sha) {
		return "", errors.New("invalid artifact identity")
	}
	return fmt.Sprintf("jobs/%s/attempt-%d/%s.json", c.ID, c.Attempt, sha), nil
}

// Complete requires an attempt-scoped content-addressed path. The caller must write
// with exclusive creation and verify the bytes before calling; this records metadata
// atomically but does not implement a filesystem/database transaction.
func (r Repository) Complete(ctx context.Context, c Claim, key, sha string) error {
	expected, err := ArtifactKey(c, sha)
	if err != nil {
		return err
	}
	if key != expected {
		return errors.New("artifact key mismatch")
	}
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state='succeeded',lease_until=NULL,artifact_path=$4,artifact_sha256=$5 WHERE id=$1 AND attempt=$2 AND worker=$3 AND state='running' AND lease_until>clock_timestamp()`, c.ID, c.Attempt, c.Worker, key, sha))
}
