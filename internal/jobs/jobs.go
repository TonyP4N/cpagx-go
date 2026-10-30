// Package jobs is an opt-in persistence prototype. No existing route or executor uses it.
package jobs

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

var ErrStale = errors.New("job attempt is stale, expired or cancelled")
var digest = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Repository struct{ DB *sql.DB }
type Claim struct {
	ID      string
	Attempt int
	Worker  string
	Token   string
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
	return r.claim(ctx, worker, lease, "", "")
}
func (r Repository) ClaimExecution(ctx context.Context, worker string, lease time.Duration, executor, location string) (Claim, error) {
	if executor != "isolated-v2" || !strings.HasPrefix(location, "docker:") || len(location) > 512 {
		return Claim{}, errors.New("invalid gated executor or location")
	}
	return r.claim(ctx, worker, lease, executor, location)
}
func (r Repository) claim(ctx context.Context, worker string, lease time.Duration, executor, location string) (Claim, error) {
	if worker == "" || lease < time.Second || lease > time.Hour {
		return Claim{}, errors.New("invalid worker or lease")
	}
	_, err := r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state='failed',lease_until=NULL,last_error='lease expired at attempt limit' WHERE state='running' AND lease_until<=clock_timestamp() AND attempt>=max_attempts`)
	if err != nil {
		return Claim{}, err
	}
	var c Claim
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return c, err
	}
	token := hex.EncodeToString(tokenBytes)
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return c, err
	}
	defer tx.Rollback()
	if err = claimCapacity(ctx, tx); err != nil {
		return c, err
	}
	err = tx.QueryRowContext(ctx, `WITH candidate AS (
 SELECT id FROM m4_jobs WHERE attempt<max_attempts AND
 ((state='queued' AND available_at<=clock_timestamp()) OR (state='running' AND lease_until<=clock_timestamp()))
 ORDER BY available_at,id FOR UPDATE SKIP LOCKED LIMIT 1)
 UPDATE m4_jobs j SET state='running',attempt=j.attempt+1,worker=$1,attempt_token=$3,
 lease_until=clock_timestamp()+($2 * interval '1 millisecond') FROM candidate c WHERE j.id=c.id
 RETURNING j.id,j.attempt,j.worker,j.attempt_token`, worker, lease.Milliseconds(), token).Scan(&c.ID, &c.Attempt, &c.Worker, &c.Token)
	if err == nil && executor != "" {
		var result sql.Result
		result, err = tx.ExecContext(ctx, `UPDATE m4_job_attempts SET executor_kind=$5,location=$6 WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4`, c.ID, c.Attempt, c.Worker, c.Token, executor, location)
		err = affected(result, err)
	}
	if err == nil {
		err = tx.Commit()
	}
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
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET lease_until=clock_timestamp()+($4 * interval '1 millisecond') WHERE id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$5 AND state='running' AND lease_until>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM m4_job_attempts a WHERE a.job_id=m4_jobs.id AND a.attempt=m4_jobs.attempt AND a.start_revoked_at IS NOT NULL)`, c.ID, c.Attempt, c.Worker, lease.Milliseconds(), c.Token))
}

// Fail retries with bounded exponential backoff (1s..256s); final failure is terminal.
func (r Repository) Fail(ctx context.Context, c Claim, message string, retryable bool) error {
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state=CASE WHEN $5 AND attempt<max_attempts THEN 'queued' ELSE 'failed' END,
 available_at=clock_timestamp()+(power(2,least(attempt-1,8))*interval '1 second'),lease_until=NULL,last_error=$4
 WHERE id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$6 AND state='running' AND lease_until>clock_timestamp()`, c.ID, c.Attempt, c.Worker, message, retryable, c.Token))
}

// Cancel requests stopping any previously attempted computation, including a
// queued retry whose expired predecessor may still run. Only never-claimed queued
// jobs cancel immediately; attempted jobs require exit evidence before ACK.
// Repeated cancellation preserves terminal state and is idempotent.
func (r Repository) Cancel(ctx context.Context, id string) error {
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state=CASE WHEN state='queued' AND attempt=0 THEN 'cancelled' WHEN state='running' OR (state='queued' AND attempt>0) THEN 'cancelling' ELSE state END, lease_until=CASE WHEN state='queued' AND attempt>0 THEN clock_timestamp() ELSE lease_until END, recovery_deadline=CASE WHEN state='running' OR (state='queued' AND attempt>0) THEN clock_timestamp()+interval '5 seconds' ELSE recovery_deadline END WHERE id=$1`, id))
}

// AcknowledgeCancel must be called only after the attempt's subprocess has exited.
// Recovery also must independently confirm no process remains before acknowledging.
func (r Repository) AcknowledgeCancel(ctx context.Context, c Claim) error {
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state='cancelled',lease_until=NULL WHERE id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND state IN ('cancelling','cancelled') AND (SELECT count(*) FROM m4_job_attempts a WHERE a.job_id=m4_jobs.id AND a.exited_at IS NOT NULL)=m4_jobs.attempt AND NOT EXISTS(SELECT 1 FROM m4_compact_verifications v WHERE v.job_id=m4_jobs.id AND v.state='running')`, c.ID, c.Attempt, c.Worker, c.Token))
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
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM m4_jobs WHERE id=$1 FOR UPDATE`, c.ID).Scan(&locked); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE m4_jobs SET state='succeeded',lease_until=NULL,artifact_path=$4,artifact_sha256=$5 WHERE id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$6 AND state='running' AND lease_until>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM m4_job_attempts a WHERE a.job_id=m4_jobs.id AND a.attempt=m4_jobs.attempt AND (a.start_revoked_at IS NOT NULL OR (a.executor_kind='isolated-v2' AND a.container_id='') OR (a.container_id!='' AND a.exited_at IS NULL)))`, c.ID, c.Attempt, c.Worker, key, sha, c.Token)
	if err = affected(result, err); err != nil {
		return err
	}
	return tx.Commit()
}

// EnqueuePayload stores the validated immutable input description.
func (r Repository) EnqueuePayload(ctx context.Context, id string, max int, payload json.RawMessage) error {
	if id == "" || max < 1 || max > 100 {
		return errors.New("invalid job")
	}
	_, err := r.DB.ExecContext(ctx, `INSERT INTO m4_jobs(id,max_attempts,payload) VALUES($1,$2,$3)`, id, max, string(payload))
	return err
}

type Status struct {
	LeaseValid          bool            `json:"lease_valid"`
	ID                  string          `json:"id"`
	State               string          `json:"state"`
	Attempt             int             `json:"attempt"`
	Payload             json.RawMessage `json:"payload"`
	ArtifactPath        *string         `json:"artifact_path"`
	ArtifactSHA256      *string         `json:"artifact_sha256"`
	LastError           *string         `json:"last_error"`
	RecoveryDeadline    *time.Time      `json:"recovery_deadline"`
	RecoveryCheckedAt   *time.Time      `json:"recovery_checked_at"`
	RecoveryReason      *string         `json:"recovery_reason"`
	MissingExitAttempts []int           `json:"missing_exit_attempts"`
	AttemptHistory      []AttemptStatus `json:"attempt_history"`
}

func (r Repository) Status(ctx context.Context, id string) (Status, error) {
	var s Status
	err := r.DB.QueryRowContext(ctx, `SELECT id,state,attempt,payload,artifact_path,artifact_sha256,last_error,recovery_deadline,recovery_checked_at,recovery_reason,(state='running' AND lease_until>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM m4_job_attempts a WHERE a.job_id=m4_jobs.id AND a.attempt=m4_jobs.attempt AND a.start_revoked_at IS NOT NULL)) FROM m4_jobs WHERE id=$1`, id).Scan(&s.ID, &s.State, &s.Attempt, &s.Payload, &s.ArtifactPath, &s.ArtifactSHA256, &s.LastError, &s.RecoveryDeadline, &s.RecoveryCheckedAt, &s.RecoveryReason, &s.LeaseValid)
	if err == nil {
		s.AttemptHistory, err = r.History(ctx, id)
		for n := 1; n <= s.Attempt; n++ {
			found := false
			for _, a := range s.AttemptHistory {
				if a.Attempt == n && a.ExitedAt != nil {
					found = true
				}
			}
			if !found {
				s.MissingExitAttempts = append(s.MissingExitAttempts, n)
			}
		}
	}
	return s, err
}

func (r Repository) CheckClaim(ctx context.Context, c Claim) error {
	var ok bool
	err := r.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m4_jobs WHERE id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND state='running' AND lease_until>clock_timestamp() AND NOT EXISTS(SELECT 1 FROM m4_job_attempts a WHERE a.job_id=m4_jobs.id AND a.attempt=m4_jobs.attempt AND a.start_revoked_at IS NOT NULL))`, c.ID, c.Attempt, c.Worker, c.Token).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return ErrStale
	}
	return nil
}

// IsCompleted allows an identical authenticated completion to be retried after response loss.
func (r Repository) IsCompleted(ctx context.Context, c Claim, sha string) (bool, error) {
	var ok bool
	err := r.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m4_jobs WHERE id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND state='succeeded' AND artifact_sha256=$5)`, c.ID, c.Attempt, c.Worker, c.Token, sha).Scan(&ok)
	return ok, err
}

// CheckPublication prevents any container attempt publication before its external
// coordinator has durably recorded irreversible container removal.
func (r Repository) CheckPublication(ctx context.Context, c Claim) error {
	if err := r.CheckClaim(ctx, c); err != nil {
		return err
	}
	var pending bool
	err := r.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m4_job_attempts WHERE job_id=$1 AND attempt=$2 AND (start_revoked_at IS NOT NULL OR (executor_kind='isolated-v2' AND container_id='') OR (container_id!='' AND exited_at IS NULL)))`, c.ID, c.Attempt).Scan(&pending)
	if err != nil {
		return err
	}
	if pending {
		return ErrStale
	}
	return nil
}
