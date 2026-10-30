package integration

import (
	"context"
	"database/sql"
	"errors"
	"github.com/TonyP4N/cpagx-go/internal/capacity"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSiteCapacityPolicySerializesAllUnexitedAttempts(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated M4_TEST_DATABASE_URL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	var name string
	if err = db.QueryRowContext(ctx, "SELECT current_database()").Scan(&name); err != nil || name != "m4_validation" {
		t.Fatalf("refusing test database %q: %v", name, err)
	}
	files, err := os.ReadDir("../migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".sql") {
			raw, e := os.ReadFile(filepath.Join("../migrations", file.Name()))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.ExecContext(ctx, string(raw)); e != nil {
				t.Fatalf("migration %s: %v", file.Name(), e)
			}
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.ExecContext(ctx, "TRUNCATE m4_jobs CASCADE; UPDATE m4_capacity_policy SET profile='',enabled_at=NULL")
	must(err)
	defer db.ExecContext(ctx, "TRUNCATE m4_jobs CASCADE; UPDATE m4_capacity_policy SET profile='',enabled_at=NULL")
	r := jobs.Repository{DB: db}
	// Default disabled keeps old independent claims available.
	must(r.Enqueue(ctx, "legacy-a", 1))
	must(r.Enqueue(ctx, "legacy-b", 1))
	_, err = r.Claim(ctx, "old-a", time.Minute)
	must(err)
	_, err = r.Claim(ctx, "old-b", time.Minute)
	must(err)
	if err = r.EnableCapacityPolicy(ctx, capacity.Engineering); err == nil {
		t.Fatal("enabled over unexplained existing attempts")
	}
	_, err = db.ExecContext(ctx, "UPDATE m4_job_attempts SET exited_at=clock_timestamp(); UPDATE m4_jobs SET state='failed',lease_until=NULL")
	must(err)
	must(r.EnableCapacityPolicy(ctx, capacity.Engineering))
	// Reapplying migrations must not reset the enabled policy.
	raw, err := os.ReadFile("../migrations/011_capacity_policy.sql")
	must(err)
	_, err = db.ExecContext(ctx, string(raw))
	must(err)
	for _, id := range []string{"new-a", "new-b", "new-c"} {
		must(r.Enqueue(ctx, id, 3))
	}
	var wg sync.WaitGroup
	claims := make(chan jobs.Claim, 12)
	failures := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, e := r.ClaimExecution(ctx, "worker", time.Minute, "isolated-v2", "docker:test:scope")
			if e == nil {
				claims <- c
			} else if !errors.Is(e, sql.ErrNoRows) {
				failures <- e
			}
		}()
	}
	wg.Wait()
	close(claims)
	close(failures)
	for err := range failures {
		t.Fatal(err)
	}
	if len(claims) != 1 {
		t.Fatalf("concurrent claims=%d", len(claims))
	}
	active := <-claims
	// Expiry, terminal failure, and cancellation never supply exit proof.
	_, err = db.ExecContext(ctx, "UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1", active.ID)
	must(err)
	if _, err = r.Claim(ctx, "legacy-mixed", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expiry released slot: %v", err)
	}
	must(r.Cancel(ctx, active.ID))
	if _, err = r.ClaimExecution(ctx, "mixed", time.Minute, "isolated-v2", "docker:test:scope"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cancel request released slot: %v", err)
	}
	// Even an older binary using its original SQL cannot bypass the DB trigger.
	_, err = db.ExecContext(ctx, "UPDATE m4_jobs SET state='running',attempt=attempt+1,lease_until=clock_timestamp()+interval '1 minute' WHERE id='new-c'")
	if err == nil || !strings.Contains(err.Error(), "site capacity") {
		t.Fatal("old/raw claim bypassed site gate")
	}
	// Gated pre-start revocation is the existing verified non-execution path.
	must(r.RevokeUnstarted(ctx, active, "docker:test:scope"))
	must(r.AcknowledgeCancel(ctx, active))
	next, err := r.Claim(ctx, "legacy-mixed", time.Minute)
	must(err)
	if next.ID == active.ID {
		t.Fatal("cancelled job reclaimed")
	}
	if _, err = r.Claim(ctx, "another", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("second active attempt allowed: %v", err)
	}
}

func TestCompactVerifierKeepsDurableSlotUntilControlledExit(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated M4_TEST_DATABASE_URL required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	var database string
	if err = db.QueryRowContext(ctx, "SELECT current_database()").Scan(&database); err != nil || database != "m4_validation" {
		t.Fatalf("refusing test database %q: %v", database, err)
	}
	files, err := os.ReadDir("../migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".sql") {
			raw, e := os.ReadFile(filepath.Join("../migrations", file.Name()))
			if e != nil {
				t.Fatal(e)
			}
			if _, e = db.ExecContext(ctx, string(raw)); e != nil {
				t.Fatalf("migration %s: %v", file.Name(), e)
			}
		}
	}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	_, err = db.ExecContext(ctx, "TRUNCATE m4_jobs CASCADE; UPDATE m4_capacity_policy SET profile='',enabled_at=NULL")
	must(err)
	defer db.ExecContext(ctx, "TRUNCATE m4_jobs CASCADE; UPDATE m4_capacity_policy SET profile='',enabled_at=NULL")
	repo := jobs.Repository{DB: db}
	must(repo.EnableCapacityPolicy(ctx, capacity.EngineeringCore))
	must(repo.Enqueue(ctx, "verify-first", 1))
	must(repo.Enqueue(ctx, "verify-next", 1))
	claim, err := repo.Claim(ctx, "worker", time.Minute)
	must(err)
	_, err = db.ExecContext(ctx, "UPDATE m4_job_attempts SET exited_at=clock_timestamp() WHERE job_id=$1 AND attempt=$2", claim.ID, claim.Attempt)
	must(err)
	started, err := repo.BeginCompactVerification(ctx, claim.ID, claim.Attempt, strings.Repeat("a", 64), false)
	must(err)
	if started.IsZero() || started.After(time.Now()) {
		t.Fatal("untrusted attempt budget clock")
	}
	if _, err = repo.Claim(ctx, "other", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("source verifier released slot: %v", err)
	}
	must(repo.Cancel(ctx, claim.ID))
	if err = repo.AcknowledgeCancel(ctx, claim); !errors.Is(err, jobs.ErrStale) {
		t.Fatalf("cancel acknowledged before verifier exit: %v", err)
	}
	if _, err = repo.Claim(ctx, "other", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("cancelled verifier released slot before exit: %v", err)
	}
	_, err = db.ExecContext(ctx, "UPDATE m4_jobs SET state='running',attempt=attempt+1,lease_until=clock_timestamp()+interval '1 minute' WHERE id='verify-next'")
	if err == nil || !strings.Contains(err.Error(), "site capacity") {
		t.Fatal("old/raw claim bypassed outstanding verifier")
	}
	if _, err = repo.BeginCompactVerification(ctx, claim.ID, claim.Attempt, strings.Repeat("b", 64), false); !errors.Is(err, jobs.ErrStale) {
		t.Fatalf("late cancelled verification allowed: %v", err)
	}
	must(repo.FinishCompactVerification(ctx, claim.ID, claim.Attempt, strings.Repeat("a", 64)))
	must(repo.AcknowledgeCancel(ctx, claim))
	next, err := repo.Claim(ctx, "other", time.Minute)
	must(err)
	if next.ID == claim.ID {
		t.Fatal("cancelled verifier task reclaimed")
	}
}
