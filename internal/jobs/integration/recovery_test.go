package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIndependentRecovery(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	var name string
	if err = db.QueryRow("SELECT current_database()").Scan(&name); err != nil || name != "m4_validation" {
		t.Fatal("disposable database required", err)
	}
	files, err := os.ReadDir("../migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sql") {
			b, e := os.ReadFile("../migrations/" + f.Name())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.Exec(string(b)); e != nil {
				t.Fatal(e)
			}
		}
	}
	if _, err = db.Exec("TRUNCATE m4_jobs"); err != nil {
		t.Fatal(err)
	}
	repo := jobs.Repository{DB: db}
	root := t.TempDir()
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(repo.Enqueue(ctx, "lost", 1))
	lost, err := repo.Claim(ctx, "gone", time.Second)
	must(err)
	must(repo.Cancel(ctx, lost.ID))
	_, err = db.Exec("UPDATE m4_jobs SET recovery_deadline=clock_timestamp()-interval '1 second'")
	must(err)
	// No HTTP API or Claim is called while this independent ticker runs.
	recoveryCtx, stop := context.WithCancel(ctx)
	defer stop()
	go repo.RunRecovery(recoveryCtx, root, 20*time.Millisecond, nil)
	wait := func(state string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			s, e := repo.Status(ctx, lost.ID)
			must(e)
			if s.State == state && s.RecoveryCheckedAt != nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatal("recovery did not reach", state)
	}
	wait("cancelling")
	status, err := repo.Status(ctx, lost.ID)
	must(err)
	if status.RecoveryReason == nil || !strings.Contains(*status.RecoveryReason, "pending") {
		t.Fatal(status)
	}
	proof := jobs.ExitProof{ID: lost.ID, Attempt: lost.Attempt, Worker: lost.Worker, Token: "wrong", GroupExited: true, ChildPID: 123, GuardianPID: 456}
	path := filepath.Join(root, "jobs", lost.ID, "attempt-1.worker", "exit.json")
	must(os.MkdirAll(filepath.Dir(path), 0700))
	b, _ := json.Marshal(proof)
	must(os.WriteFile(path, b, 0600))
	time.Sleep(80 * time.Millisecond)
	status, err = repo.Status(ctx, lost.ID)
	must(err)
	if status.State != "cancelling" {
		t.Fatal("accepted stale proof")
	}
	// Run the real guardian and simulate Worker SIGKILL with pipe EOF.
	must(os.Remove(path))
	_, source, _, _ := runtime.Caller(0)
	guardian := filepath.Join(filepath.Dir(source), "../../../services/worker/cpag_worker/guardian.py")
	config := map[string]any{"identity": map[string]any{"id": lost.ID, "attempt": lost.Attempt, "worker": lost.Worker, "token": lost.Token}, "command": []string{"python3", "-c", "import time; time.sleep(60)"}, "env": map[string]string{"PATH": os.Getenv("PATH")}, "timeout": 60, "kill_grace": 0.1, "log_bytes": 1024, "memory_bytes": 0, "file_bytes": 0, "cpu_seconds": 0, "pid_file": filepath.Join(filepath.Dir(path), "child.pid"), "exit_file": path, "stdout": filepath.Join(filepath.Dir(path), "stdout"), "stderr": filepath.Join(filepath.Dir(path), "stderr")}
	configBytes, _ := json.Marshal(config)
	configPath := filepath.Join(filepath.Dir(path), "config.json")
	must(os.WriteFile(configPath, configBytes, 0600))
	command := exec.Command("python3", guardian, configPath)
	pipe, err := command.StdinPipe()
	must(err)
	must(command.Start())
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		if _, e := os.Stat(fmt.Sprint(config["pid_file"])); e == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	must(pipe.Close())
	must(command.Wait())
	must(jobs.VerifyExit(root, lost))
	wait("cancelled")
	if err = repo.CheckClaim(ctx, lost); err != jobs.ErrStale {
		t.Fatal("recovered attempt not fenced", err)
	}
	// A queued retry is not evidence that its expired computation exited.
	must(repo.Enqueue(ctx, "expired-queued-cancel", 3))
	queuedClaim, err := repo.Claim(ctx, "queued-old", time.Minute)
	must(err)
	_, err = db.Exec("UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", queuedClaim.ID)
	must(err)
	must(repo.Recover(ctx, root))
	queuedStatus, err := repo.Status(ctx, queuedClaim.ID)
	must(err)
	if queuedStatus.State != "queued" {
		t.Fatal("expected independently recovered queue", queuedStatus.State)
	}
	must(repo.Cancel(ctx, queuedClaim.ID))
	_, err = db.Exec("UPDATE m4_jobs SET recovery_deadline=clock_timestamp()-interval '1 second' WHERE id=$1", queuedClaim.ID)
	must(err)
	must(repo.Recover(ctx, root))
	queuedStatus, err = repo.Status(ctx, queuedClaim.ID)
	must(err)
	if queuedStatus.State != "cancelling" || queuedStatus.RecoveryReason == nil || !strings.Contains(*queuedStatus.RecoveryReason, "pending") {
		t.Fatal("queued cancellation lacked exit proof", queuedStatus)
	}
	queuedProof := jobs.ExitProof{ID: queuedClaim.ID, Attempt: queuedClaim.Attempt, Worker: queuedClaim.Worker, Token: queuedClaim.Token, GroupExited: true, ChildPID: proof.ChildPID, GuardianPID: proof.GuardianPID}
	queuedPath := filepath.Join(root, "jobs", queuedClaim.ID, "attempt-1.worker", "exit.json")
	must(os.MkdirAll(filepath.Dir(queuedPath), 0700))
	queuedBytes, _ := json.Marshal(queuedProof)
	must(os.WriteFile(queuedPath, queuedBytes, 0600))
	must(repo.Recover(ctx, root))
	queuedStatus, err = repo.Status(ctx, queuedClaim.ID)
	must(err)
	if queuedStatus.State != "cancelled" {
		t.Fatal("valid bound proof did not cancel queued predecessor", queuedStatus.State)
	}
	queuedSHA := strings.Repeat("a", 64)
	queuedKey, err := jobs.ArtifactKey(queuedClaim, queuedSHA)
	must(err)
	if err = repo.Complete(ctx, queuedClaim, queuedKey, queuedSHA); err != jobs.ErrStale {
		t.Fatal("queued predecessor completion was accepted", err)
	}
	// Fail's retry path must retain the identity needed by cancellation recovery.
	must(repo.Enqueue(ctx, "failed-retry-cancel", 3))
	retryClaim, err := repo.Claim(ctx, "retry-old", time.Minute)
	must(err)
	must(repo.Fail(ctx, retryClaim, "retry fixture", true))
	must(repo.Cancel(ctx, retryClaim.ID))
	var retainedWorker, retainedToken, state string
	must(db.QueryRow("SELECT worker,attempt_token,state FROM m4_jobs WHERE id=$1", retryClaim.ID).Scan(&retainedWorker, &retainedToken, &state))
	if retainedWorker != retryClaim.Worker || retainedToken != retryClaim.Token || state != "cancelling" {
		t.Fatal("retry cancellation discarded exit proof identity")
	}
	// No marker exists: independent recovery must also leave this retry pending.
	_, err = db.Exec("UPDATE m4_jobs SET recovery_deadline=clock_timestamp()-interval '1 second' WHERE id=$1", retryClaim.ID)
	must(err)
	must(repo.Recover(ctx, root))
	retryStatus, err := repo.Status(ctx, retryClaim.ID)
	must(err)
	if retryStatus.State != "cancelling" {
		t.Fatal("retry cancellation bypassed exit proof")
	}
	// Legacy claim recovery and the independent sweep may race on the same row.
	must(repo.Enqueue(ctx, "claim-race", 3))
	old, err := repo.Claim(ctx, "old-race", time.Second)
	must(err)
	_, err = db.Exec("UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", old.ID)
	must(err)
	var raced jobs.Claim
	var claimErr, recoveryErr error
	var group sync.WaitGroup
	group.Add(2)
	go func() { defer group.Done(); raced, claimErr = repo.Claim(ctx, "new-race", time.Minute) }()
	go func() { defer group.Done(); recoveryErr = repo.Recover(ctx, root) }()
	group.Wait()
	must(recoveryErr)
	if claimErr == sql.ErrNoRows {
		raced, claimErr = repo.Claim(ctx, "new-race", time.Minute)
	}
	must(claimErr)
	if raced.Attempt != 2 || raced.ID != old.ID {
		t.Fatal("claim/recovery changed attempt", raced)
	}
	must(repo.CheckClaim(ctx, raced))
	if err = repo.CheckClaim(ctx, old); err != jobs.ErrStale {
		t.Fatal("old attempt survived claim/recovery race", err)
	}
	// A repeated sweep must not fence the new unexpired lease.
	must(repo.Recover(ctx, root))
	must(repo.CheckClaim(ctx, raced))
	// Even a valid latest receipt cannot attest older overwritten attempts.
	latestProof := jobs.ExitProof{ID: raced.ID, Attempt: raced.Attempt, Worker: raced.Worker, Token: raced.Token, GroupExited: true, ChildPID: proof.ChildPID, GuardianPID: proof.GuardianPID}
	latestPath := filepath.Join(root, "jobs", raced.ID, "attempt-2.worker", "exit.json")
	must(os.MkdirAll(filepath.Dir(latestPath), 0700))
	latestBytes, _ := json.Marshal(latestProof)
	must(os.WriteFile(latestPath, latestBytes, 0600))
	if e := jobs.VerifyExit(root, raced); e == nil || !strings.Contains(e.Error(), "all-attempt") {
		t.Fatal("latest receipt accepted as all-attempt proof", e)
	}
	must(repo.Cancel(ctx, raced.ID))
	_, err = db.Exec("UPDATE m4_jobs SET recovery_deadline=clock_timestamp()-interval '1 second' WHERE id=$1", raced.ID)
	must(err)
	must(repo.Recover(ctx, root))
	multiStatus, err := repo.Status(ctx, raced.ID)
	must(err)
	if multiStatus.State != "cancelling" || multiStatus.RecoveryReason == nil || !strings.Contains(*multiStatus.RecoveryReason, "all-attempt") {
		t.Fatal("multiple attempts automatically cancelled", multiStatus)
	}
	must(repo.Enqueue(ctx, "expired", 1))
	expired, err := repo.Claim(ctx, "gone", time.Second)
	must(err)
	_, err = db.Exec("UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", expired.ID)
	must(err)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		s, e := repo.Status(ctx, expired.ID)
		must(e)
		if s.State == "failed" && s.RecoveryCheckedAt != nil {
			sha := strings.Repeat("a", 64)
			key, e := jobs.ArtifactKey(expired, sha)
			must(e)
			if e = repo.Complete(ctx, expired, key, sha); e != jobs.ErrStale {
				t.Fatal("late publication accepted after independent recovery", e)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("expired job undiscovered without new claims")
}
