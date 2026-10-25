package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExitProof is written by the trusted guardian only after the entire computation
// process group has exited. No remote PID is interpreted on the recovery host.
type ExitProof struct {
	Removed     bool              `json:"removed,omitempty"`
	InspectedID string            `json:"inspected_id,omitempty"`
	Running     *bool             `json:"running,omitempty"`
	PID         *int              `json:"pid,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Scope       string            `json:"scope,omitempty"`
	Location    string            `json:"location,omitempty"`
	ContainerID string            `json:"container_id,omitempty"`
	Exited      bool              `json:"exited,omitempty"`
	ID          string            `json:"id"`
	Attempt     int               `json:"attempt"`
	Worker      string            `json:"worker"`
	Token       string            `json:"token"`
	GroupExited bool              `json:"group_exited"`
	ChildPID    int               `json:"child_pid"`
	GuardianPID int               `json:"guardian_pid"`
}

func readExit(root string, c Claim) (ExitProof, error) {

	if c.ID == "" || filepath.Base(c.ID) != c.ID || c.ID == "." || c.ID == ".." {
		return ExitProof{}, fmt.Errorf("invalid job identity")
	}
	p := filepath.Join(root, "jobs", c.ID, fmt.Sprintf("attempt-%d.worker", c.Attempt), "exit.json")
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return ExitProof{}, fmt.Errorf("shared root unavailable: %w", err)
	}
	canonicalPath, err := filepath.EvalSymlinks(p)
	if err != nil {
		return ExitProof{}, fmt.Errorf("exit proof unavailable: %w", err)
	}
	relative, err := filepath.Rel(canonicalRoot, canonicalPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return ExitProof{}, fmt.Errorf("exit proof escapes shared root")
	}
	info, err := os.Lstat(p)
	if err != nil {
		return ExitProof{}, fmt.Errorf("exit proof unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return ExitProof{}, fmt.Errorf("invalid exit proof file")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return ExitProof{}, err
	}
	var proof ExitProof
	if err = json.Unmarshal(b, &proof); err != nil {
		return ExitProof{}, fmt.Errorf("invalid exit proof: %w", err)
	}
	if proof.ID != c.ID || proof.Attempt != c.Attempt || proof.Worker != c.Worker || proof.Token != c.Token || c.Token == "" {
		return ExitProof{}, fmt.Errorf("exit proof identity mismatch")
	}
	return proof, nil
}
func VerifyExit(root string, c Claim) error {
	proof, err := readExit(root, c)
	if err != nil {
		return err
	}
	if !proof.GroupExited || proof.ChildPID <= 0 || proof.GuardianPID <= 0 {
		return fmt.Errorf("exit proof process evidence mismatch")
	}
	return nil
}

// RefreshExitEvidence imports only receipts bound to the persisted execution.
func (r Repository) RefreshExitEvidence(ctx context.Context, root, id string) error {
	rows, err := r.DB.QueryContext(ctx, `SELECT attempt,worker,attempt_token,location FROM m4_job_attempts WHERE job_id=$1 AND exited_at IS NULL ORDER BY attempt`, id)
	if err != nil {
		return err
	}
	type pending struct {
		c        Claim
		location string
	}
	items := []pending{}
	for rows.Next() {
		a := pending{}
		a.c.ID = id
		if err = rows.Scan(&a.c.Attempt, &a.c.Worker, &a.c.Token, &a.location); err != nil {
			rows.Close()
			return err
		}
		items = append(items, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}

	// Probe the shared dependency once. Per-attempt paths can then fail locally
	// without preventing unrelated good receipts from being processed.
	realRoot, rootErr := filepath.EvalSymlinks(root)
	if rootErr != nil {
		return fmt.Errorf("receipt root unavailable: %w", rootErr)
	}
	rootInfo, rootErr := os.Stat(realRoot)
	if rootErr != nil {
		return fmt.Errorf("receipt root unavailable: %w", rootErr)
	}
	if !rootInfo.IsDir() {
		return fmt.Errorf("receipt root is not a directory")
	}

	for _, a := range items {
		proof, e := readExit(root, a.c)
		if e != nil {
			if err = r.noteExitCheck(ctx, a.c, e); err != nil {
				return err
			}
			continue
		}
		if a.location != "legacy-process-group" || proof.Scope == "container" {
			if e = r.RecordExit(ctx, a.c, proof); e != nil {
				if errors.Is(e, ErrStale) || errors.Is(e, ErrInvalidProof) {
					if err = r.noteExitCheck(ctx, a.c, e); err != nil {
						return err
					}
					continue
				}
				return fmt.Errorf("record exit %s attempt %d: %w", id, a.c.Attempt, e)
			}
		} else {
			if e = VerifyExit(root, a.c); e != nil {
				if err = r.noteExitCheck(ctx, a.c, e); err != nil {
					return err
				}
				continue
			}
			raw, _ := json.Marshal(proof)
			if _, e = r.DB.ExecContext(ctx, `UPDATE m4_job_attempts SET exit_checked_at=clock_timestamp(),exit_error=NULL,exited_at=clock_timestamp(),exit_receipt=$5 WHERE job_id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND location='legacy-process-group' AND exited_at IS NULL`, id, a.c.Attempt, a.c.Worker, a.c.Token, string(raw)); e != nil {
				return e
			}
		}
	}
	return nil
}

// Recover is independent of Claim and of the HTTP service. Missing proof never
// turns a cancellation into cancelled. Expired running attempts are fenced by
// state even when no replacement worker ever claims work.
func (r Repository) Recover(ctx context.Context, root string) error {
	_, err := r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state=CASE WHEN attempt<max_attempts THEN 'queued' ELSE 'failed' END, lease_until=NULL, available_at=clock_timestamp(), recovery_checked_at=clock_timestamp(), recovery_reason='expired running lease fenced by independent recovery', last_error='lease expired' WHERE state='running' AND lease_until<=clock_timestamp()`)
	if err != nil {
		return err
	}
	pendingRows, e := r.DB.QueryContext(ctx, `SELECT DISTINCT job_id FROM m4_job_attempts WHERE exited_at IS NULL ORDER BY job_id`)
	if e != nil {
		return e
	}
	ids := []string{}
	for pendingRows.Next() {
		var id string
		if e = pendingRows.Scan(&id); e != nil {
			pendingRows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = pendingRows.Err()
	pendingRows.Close()
	if e != nil {
		return e
	}
	for _, id := range ids {
		if e = r.RefreshExitEvidence(ctx, root, id); e != nil {
			return e
		}
	}
	rows, err := r.DB.QueryContext(ctx, `SELECT id,attempt,coalesce(worker,''),coalesce(attempt_token,'') FROM m4_jobs WHERE state='cancelling' AND recovery_deadline<=clock_timestamp()`)
	if err != nil {
		return err
	}
	var claims []Claim
	for rows.Next() {
		var c Claim
		if err = rows.Scan(&c.ID, &c.Attempt, &c.Worker, &c.Token); err != nil {
			rows.Close()
			return err
		}
		claims = append(claims, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, c := range claims {
		reason := "all attempt exit evidence recorded"
		state := "cancelled"
		if err = r.RefreshExitEvidence(ctx, root, c.ID); err != nil {
			return err
		}
		pending, e := r.allExited(ctx, c.ID, c.Attempt)
		if e != nil {
			return e
		}
		if pending != "" {
			state = "cancelling"
			reason = pending
		}
		_, err = r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state=$5,lease_until=CASE WHEN $5='cancelled' THEN NULL ELSE lease_until END,recovery_checked_at=clock_timestamp(),recovery_reason=$6 WHERE id=$1 AND attempt=$2 AND coalesce(worker,'')=$3 AND coalesce(attempt_token,'')=$4 AND state='cancelling' AND ($5!='cancelled' OR (SELECT count(*) FROM m4_job_attempts a WHERE a.job_id=m4_jobs.id AND a.exited_at IS NOT NULL)=m4_jobs.attempt)`, c.ID, c.Attempt, c.Worker, c.Token, state, reason)
		if err != nil {
			return err
		}
	}
	return nil
}

// RunRecovery runs immediately, then periodically. The per-pass timeout prevents
// an unavailable database from indefinitely delaying shutdown or later passes.
func (r Repository) RunRecovery(ctx context.Context, root string, interval time.Duration, report func(error)) {
	if interval <= 0 {
		if report != nil {
			report(fmt.Errorf("recovery interval must be positive"))
		}
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		pass, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := r.Recover(pass, root)
		cancel()
		if err != nil && report != nil {
			report(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
