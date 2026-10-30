package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var ErrInvalidProof = errors.New("invalid exit proof")

type AttemptStatus struct {
	Executor         string          `json:"executor"`
	StartRevokedAt   *time.Time      `json:"start_revoked_at"`
	ExitCheckedAt    *time.Time      `json:"exit_checked_at"`
	ExitError        *string         `json:"exit_error"`
	ClaimedAt        time.Time       `json:"claimed_at"`
	ArtifactSHA256   *string         `json:"artifact_sha256"`
	ExitEvidence     json.RawMessage `json:"exit_evidence"`
	Attempt          int             `json:"attempt"`
	Worker           string          `json:"worker"`
	Location         string          `json:"location"`
	ContainerID      string          `json:"container_id"`
	ExitedAt         *time.Time      `json:"exited_at"`
	PublicationState string          `json:"publication_state"`
	ArtifactPath     *string         `json:"artifact_path"`
}

func (r Repository) History(ctx context.Context, id string) ([]AttemptStatus, error) {
	rows, err := r.DB.QueryContext(ctx, `SELECT attempt,worker,location,container_id,exited_at,publication_state,artifact_path,claimed_at,artifact_sha256,exit_receipt,exit_checked_at,exit_error,executor_kind,start_revoked_at FROM m4_job_attempts WHERE job_id=$1 ORDER BY attempt`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AttemptStatus{}
	for rows.Next() {
		var a AttemptStatus
		var receipt []byte
		if err = rows.Scan(&a.Attempt, &a.Worker, &a.Location, &a.ContainerID, &a.ExitedAt, &a.PublicationState, &a.ArtifactPath, &a.ClaimedAt, &a.ArtifactSHA256, &receipt, &a.ExitCheckedAt, &a.ExitError, &a.Executor, &a.StartRevokedAt); err != nil {
			return nil, err
		}
		if len(receipt) > 0 {
			var evidence map[string]any
			if json.Unmarshal(receipt, &evidence) == nil {
				delete(evidence, "token")
				a.ExitEvidence, _ = json.Marshal(evidence)
			}
		}
		result = append(result, a)
	}
	return result, rows.Err()
}

// RegisterExecution is serialized with cancellation/claim and precedes container
// start. A lost registration response can be retried with exactly the same ID.
func (r Repository) RegisterExecution(ctx context.Context, c Claim, location, containerID string) error {
	if !strings.HasPrefix(location, "docker:") || !digest.MatchString(containerID) || len(location) > 512 {
		return fmt.Errorf("execution location and container identity required")
	}
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ok bool
	err = tx.QueryRowContext(ctx, `SELECT state='running' AND lease_until>clock_timestamp() AND attempt=$2 AND worker=$3 AND attempt_token=$4 FROM m4_jobs WHERE id=$1 FOR UPDATE`, c.ID, c.Attempt, c.Worker, c.Token).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return ErrStale
	}
	result, err := tx.ExecContext(ctx, `UPDATE m4_job_attempts SET location=$5,container_id=$6 WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND exited_at IS NULL AND start_revoked_at IS NULL AND (container_id='' OR (location=$5 AND container_id=$6))`, c.ID, c.Attempt, c.Worker, c.Token, location, containerID)
	if err = affected(result, err); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordExit accepts historical identities, but only matching registered external
// container execution. It never grants publication rights to stale attempts.
func (r Repository) RecordExit(ctx context.Context, c Claim, proof ExitProof) error {
	if proof.ID != c.ID || proof.Attempt != c.Attempt || proof.Worker != c.Worker || proof.Token != c.Token || proof.Scope != "container" || !proof.Exited || !strings.HasPrefix(proof.Location, "docker:") || !digest.MatchString(proof.ContainerID) {
		return fmt.Errorf("%w: external container receipt identity", ErrInvalidProof)
	}
	if !proof.Removed || proof.InspectedID != proof.ContainerID || proof.Running == nil || *proof.Running || proof.PID == nil || *proof.PID != 0 || proof.Labels["cpag.job"] != c.ID || proof.Labels["cpag.attempt"] != fmt.Sprint(c.Attempt) || proof.Labels["cpag.worker"] != c.Worker {
		return fmt.Errorf("%w: container inspect exit evidence mismatch", ErrInvalidProof)
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
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
	result, err := tx.ExecContext(ctx, `UPDATE m4_job_attempts SET start_revoked_at=CASE WHEN container_id='' THEN coalesce(start_revoked_at,clock_timestamp()) ELSE start_revoked_at END,exit_checked_at=clock_timestamp(),exit_error=NULL,location=$5,container_id=$6,exited_at=coalesce(exited_at,clock_timestamp()),exit_receipt=CASE WHEN exit_receipt->>'scope'='not-started' THEN $7::jsonb ELSE coalesce(exit_receipt,$7::jsonb) END WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND ((location=$5 AND container_id=$6) OR (container_id='' AND publication_state!='published' AND ((location='legacy-process-group' AND exited_at IS NULL) OR (executor_kind='isolated-v2' AND location=$5 AND (exited_at IS NULL OR start_revoked_at IS NOT NULL))))) AND (exit_receipt IS NULL OR exit_receipt=$7::jsonb OR (exit_receipt->>'scope'='not-started' AND start_revoked_at IS NOT NULL))`, c.ID, c.Attempt, c.Worker, c.Token, proof.Location, proof.ContainerID, string(raw))
	if err = affected(result, err); err != nil {
		return err
	}
	return tx.Commit()
}

func (r Repository) allExited(ctx context.Context, id string, attempt int) (string, error) {
	var verifierPending bool
	if err := r.DB.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM m4_compact_verifications WHERE job_id=$1 AND state='running')`, id).Scan(&verifierPending); err != nil {
		return "", err
	}
	if verifierPending {
		return "pending controlled compact verifier exit evidence", nil
	}
	history, err := r.History(ctx, id)
	if err != nil {
		return "", err
	}
	missing := []int{}
	diagnostics := []string{}
	for n := 1; n <= attempt; n++ {
		found := false
		for _, a := range history {
			if a.Attempt == n && a.ExitedAt != nil {
				found = true
			}
		}
		if !found {
			missing = append(missing, n)
			for _, a := range history {
				if a.Attempt == n && a.ExitError != nil {
					diagnostics = append(diagnostics, fmt.Sprintf("attempt %d: %s", n, *a.ExitError))
				}
			}
		}
	}
	if len(missing) > 0 {
		return fmt.Sprintf("pending exit evidence for attempts %v", missing) + strings.Join(append([]string{""}, diagnostics...), "; "), nil
	}
	return "", nil
}

// DiscoverExecutions is coordinator-only: private tokens never enter public status.
// Location is an exact daemon identity; lease inspection never renews a lease.
func (r Repository) DiscoverExecutions(ctx context.Context, location string) ([]map[string]any, error) {
	if !strings.HasPrefix(location, "docker:") || len(location) > 512 {
		return nil, fmt.Errorf("docker location required")
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT a.job_id,a.attempt,a.worker,a.attempt_token,a.location,a.container_id,a.exited_at,j.state,j.attempt,a.executor_kind,a.start_revoked_at,(j.state='running' AND j.lease_until>clock_timestamp()) FROM m4_job_attempts a JOIN m4_jobs j ON j.id=a.job_id WHERE a.location=$1 AND (a.container_id!='' OR a.executor_kind='isolated-v2') AND (a.exited_at IS NULL OR (a.attempt=j.attempt AND j.state='running' AND a.publication_state!='published')) ORDER BY a.job_id,a.attempt`, location)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []map[string]any{}
	for rows.Next() {
		var id, worker, token, where, container, state string
		var attempt, current int
		var exited *time.Time
		var lease bool
		var executor string
		var revoked *time.Time
		if err = rows.Scan(&id, &attempt, &worker, &token, &where, &container, &exited, &state, &current, &executor, &revoked, &lease); err != nil {
			return nil, err
		}
		result = append(result, map[string]any{"executor": executor, "start_revoked_at": revoked, "id": id, "attempt": attempt, "worker": worker, "token": token, "location": where, "container_id": container, "exited_at": exited, "state": state, "current_attempt": current, "lease_valid": lease && attempt == current && revoked == nil})
	}
	return result, rows.Err()
}

func (r Repository) noteExitCheck(ctx context.Context, c Claim, problem error) error {
	var message any
	if problem != nil {
		message = problem.Error()
	}
	_, err := r.DB.ExecContext(ctx, `UPDATE m4_job_attempts SET exit_checked_at=clock_timestamp(),exit_error=$5 WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND exited_at IS NULL`, c.ID, c.Attempt, c.Worker, c.Token, message)
	return err
}

// RevokeUnstarted closes the registration/start gate before attesting no execution.
// It never infers legacy non-execution and cannot win after container registration.
func (r Repository) RevokeUnstarted(ctx context.Context, c Claim, location string) error {
	receipt, _ := json.Marshal(map[string]any{"id": c.ID, "attempt": c.Attempt, "worker": c.Worker, "token": c.Token, "location": location, "scope": "not-started", "start_revoked": true})
	tx, err := r.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var locked string
	if err = tx.QueryRowContext(ctx, `SELECT id FROM m4_jobs WHERE id=$1 FOR UPDATE`, c.ID).Scan(&locked); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE m4_job_attempts SET start_revoked_at=coalesce(start_revoked_at,clock_timestamp()),exited_at=coalesce(exited_at,clock_timestamp()),exit_receipt=coalesce(exit_receipt,$6::jsonb),exit_checked_at=clock_timestamp(),exit_error=NULL,publication_state='fenced' WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND publication_state!='published' AND executor_kind='isolated-v2' AND location=$5 AND container_id='' AND (exit_receipt IS NULL OR exit_receipt=$6::jsonb)`, c.ID, c.Attempt, c.Worker, c.Token, location, string(receipt))
	if err = affected(result, err); err != nil {
		return err
	}
	return tx.Commit()
}
