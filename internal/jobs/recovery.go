package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ExitProof is written by the trusted guardian only after the entire computation
// process group has exited. No remote PID is interpreted on the recovery host.
type ExitProof struct {
	ID          string `json:"id"`
	Attempt     int    `json:"attempt"`
	Worker      string `json:"worker"`
	Token       string `json:"token"`
	GroupExited bool   `json:"group_exited"`
	ChildPID    int    `json:"child_pid"`
	GuardianPID int    `json:"guardian_pid"`
}

func VerifyExit(root string, c Claim) error {
	if c.Attempt > 1 {
		return fmt.Errorf("all-attempt exit proof not implemented: latest receipt cannot attest predecessor computations")
	}

	if c.ID == "" || filepath.Base(c.ID) != c.ID || c.ID == "." || c.ID == ".." {
		return fmt.Errorf("invalid job identity")
	}
	p := filepath.Join(root, "jobs", c.ID, fmt.Sprintf("attempt-%d.worker", c.Attempt), "exit.json")
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("shared root unavailable: %w", err)
	}
	canonicalPath, err := filepath.EvalSymlinks(p)
	if err != nil {
		return fmt.Errorf("exit proof unavailable: %w", err)
	}
	relative, err := filepath.Rel(canonicalRoot, canonicalPath)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("exit proof escapes shared root")
	}
	info, err := os.Lstat(p)
	if err != nil {
		return fmt.Errorf("exit proof unavailable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return fmt.Errorf("invalid exit proof file")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var proof ExitProof
	if err = json.Unmarshal(b, &proof); err != nil {
		return fmt.Errorf("invalid exit proof: %w", err)
	}
	if proof.ID != c.ID || proof.Attempt != c.Attempt || proof.Worker != c.Worker || proof.Token != c.Token || c.Token == "" || !proof.GroupExited || proof.ChildPID <= 0 || proof.GuardianPID <= 0 {
		return fmt.Errorf("exit proof identity or process evidence mismatch")
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
		reason := "guardian proved computation group exit"
		state := "cancelled"
		if proofErr := VerifyExit(root, c); proofErr != nil {
			state = "cancelling"
			reason = "pending: " + proofErr.Error()
		}
		_, err = r.DB.ExecContext(ctx, `UPDATE m4_jobs SET state=$5,lease_until=CASE WHEN $5='cancelled' THEN NULL ELSE lease_until END,recovery_checked_at=clock_timestamp(),recovery_reason=$6 WHERE id=$1 AND attempt=$2 AND coalesce(worker,'')=$3 AND coalesce(attempt_token,'')=$4 AND state='cancelling'`, c.ID, c.Attempt, c.Worker, c.Token, state, reason)
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
