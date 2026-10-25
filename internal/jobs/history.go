package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type AttemptStatus struct {
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
	rows, err := r.DB.QueryContext(ctx, `SELECT attempt,worker,location,container_id,exited_at,publication_state,artifact_path,claimed_at,artifact_sha256,exit_receipt FROM m4_job_attempts WHERE job_id=$1 ORDER BY attempt`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AttemptStatus{}
	for rows.Next() {
		var a AttemptStatus
		var receipt []byte
		if err = rows.Scan(&a.Attempt, &a.Worker, &a.Location, &a.ContainerID, &a.ExitedAt, &a.PublicationState, &a.ArtifactPath, &a.ClaimedAt, &a.ArtifactSHA256, &receipt); err != nil {
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
	result, err := tx.ExecContext(ctx, `UPDATE m4_job_attempts SET location=$5,container_id=$6 WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND exited_at IS NULL AND (container_id='' OR (location=$5 AND container_id=$6))`, c.ID, c.Attempt, c.Worker, c.Token, location, containerID)
	if err = affected(result, err); err != nil {
		return err
	}
	return tx.Commit()
}

// RecordExit accepts historical identities, but only matching registered external
// container execution. It never grants publication rights to stale attempts.
func (r Repository) RecordExit(ctx context.Context, c Claim, proof ExitProof) error {
	if proof.ID != c.ID || proof.Attempt != c.Attempt || proof.Worker != c.Worker || proof.Token != c.Token || proof.Scope != "container" || !proof.Exited || proof.Location == "" || proof.ContainerID == "" {
		return fmt.Errorf("invalid external container exit receipt")
	}
	if !proof.Removed || proof.InspectedID != proof.ContainerID || proof.Running == nil || *proof.Running || proof.PID == nil || *proof.PID != 0 || proof.Labels["cpag.job"] != c.ID || proof.Labels["cpag.attempt"] != fmt.Sprint(c.Attempt) || proof.Labels["cpag.worker"] != c.Worker {
		return fmt.Errorf("container inspect exit evidence mismatch")
	}
	raw, err := json.Marshal(proof)
	if err != nil {
		return err
	}
	return affected(r.DB.ExecContext(ctx, `UPDATE m4_job_attempts SET exited_at=coalesce(exited_at,clock_timestamp()),exit_receipt=coalesce(exit_receipt,$7::jsonb) WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND location=$5 AND container_id=$6 AND (exit_receipt IS NULL OR exit_receipt=$7::jsonb)`, c.ID, c.Attempt, c.Worker, c.Token, proof.Location, proof.ContainerID, string(raw)))
}

func (r Repository) allExited(ctx context.Context, id string, attempt int) (string, error) {
	history, err := r.History(ctx, id)
	if err != nil {
		return "", err
	}
	missing := []int{}
	for n := 1; n <= attempt; n++ {
		found := false
		for _, a := range history {
			if a.Attempt == n && a.ExitedAt != nil {
				found = true
			}
		}
		if !found {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		return fmt.Sprintf("pending exit evidence for attempts %v", missing), nil
	}
	return "", nil
}
