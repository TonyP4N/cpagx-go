package integration

import (
	"context"
	"database/sql"
	"errors"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	_ "github.com/jackc/pgx/v5/stdlib"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestPostgresFaults(t *testing.T) {
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
	var databaseName string
	if err = db.QueryRowContext(ctx, "SELECT current_database()").Scan(&databaseName); err != nil {
		t.Fatal(err)
	}
	if databaseName != "m4_validation" {
		t.Fatalf("refusing destructive tests on database %q", databaseName)
	}
	files, err := os.ReadDir("../migrations")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".sql") {
			continue
		}
		migration, e := os.ReadFile("../migrations/" + file.Name())
		if e != nil {
			t.Fatal(e)
		}
		if _, e = db.ExecContext(ctx, string(migration)); e != nil {
			t.Fatal(e)
		}
	}
	// Runner supplies a disposable dedicated database; never use a production DSN.
	if _, err = db.ExecContext(ctx, "TRUNCATE m4_jobs CASCADE"); err != nil {
		t.Fatal(err)
	}
	r := jobs.Repository{DB: db}
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	stale := func(err error) {
		t.Helper()
		if !errors.Is(err, jobs.ErrStale) {
			t.Fatalf("expected stale, got %v", err)
		}
	}
	must(r.Enqueue(ctx, "fenced", 3))
	c, err := r.Claim(ctx, "worker-a", time.Second)
	must(err)
	_, err = db.ExecContext(ctx, "UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id='fenced'")
	must(err)
	stale(r.Heartbeat(ctx, c, time.Second))
	n, err := r.Claim(ctx, "worker-b", time.Minute)
	must(err)
	if n.Attempt != 2 {
		t.Fatalf("attempt=%d", n.Attempt)
	}
	sha := strings.Repeat("a", 64)
	key, err := jobs.ArtifactKey(c, sha)
	must(err)
	stale(r.Complete(ctx, c, key, sha))
	stale(r.Fail(ctx, c, "late failure", true))
	must(r.Heartbeat(ctx, n, time.Minute))
	must(r.Cancel(ctx, n.ID))
	must(r.Cancel(ctx, n.ID))
	var cancelling string
	must(db.QueryRowContext(ctx, "SELECT state FROM m4_jobs WHERE id=$1", n.ID).Scan(&cancelling))
	if cancelling != "cancelling" {
		t.Fatal(cancelling)
	}
	stale(r.AcknowledgeCancel(ctx, c))
	_, err = db.ExecContext(ctx, "UPDATE m4_job_attempts SET exited_at=clock_timestamp() WHERE job_id=$1", n.ID)
	must(err)
	must(r.AcknowledgeCancel(ctx, n))
	key, err = jobs.ArtifactKey(n, sha)
	must(err)
	stale(r.Complete(ctx, n, key, sha))
	must(r.Enqueue(ctx, "retry", 2))
	c, err = r.Claim(ctx, "retry-worker", time.Minute)
	must(err)
	must(r.Fail(ctx, c, "transient", true))
	if _, err = r.Claim(ctx, "early", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("backoff bypassed: %v", err)
	}
	_, err = db.ExecContext(ctx, "UPDATE m4_jobs SET available_at=clock_timestamp()-interval '1 second' WHERE id='retry'")
	must(err)
	c, err = r.Claim(ctx, "retry-worker", time.Minute)
	must(err)
	must(r.Fail(ctx, c, "permanent", false))
	var state string
	must(db.QueryRowContext(ctx, "SELECT state FROM m4_jobs WHERE id='retry'").Scan(&state))
	if state != "failed" {
		t.Fatal(state)
	}
	must(r.Enqueue(ctx, "nonretryable", 3))
	c, err = r.Claim(ctx, "worker", time.Minute)
	must(err)
	must(r.Fail(ctx, c, "invalid input", false))
	must(db.QueryRowContext(ctx, "SELECT state FROM m4_jobs WHERE id='nonretryable'").Scan(&state))
	if state != "failed" {
		t.Fatal(state)
	}
	must(r.Enqueue(ctx, "crash-final", 1))
	c, err = r.Claim(ctx, "killed-worker", time.Second)
	must(err)
	_, err = db.ExecContext(ctx, "UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id='crash-final'")
	must(err)
	_, err = r.Claim(ctx, "rescuer", time.Second)
	if !errors.Is(err, sql.ErrNoRows) {
		t.Fatal(err)
	}
	must(db.QueryRowContext(ctx, "SELECT state FROM m4_jobs WHERE id='crash-final'").Scan(&state))
	if state != "failed" {
		t.Fatal(state)
	}
	must(r.Enqueue(ctx, "publish", 1))
	c, err = r.Claim(ctx, "publisher", time.Minute)
	must(err)
	if err = r.Complete(ctx, c, "arbitrary/output.json", sha); err == nil {
		t.Fatal("accepted mutable key")
	}
	key, err = jobs.ArtifactKey(c, sha)
	must(err)
	must(r.Complete(ctx, c, key, sha))
	stale(r.Complete(ctx, c, key, sha))
	must(r.Cancel(ctx, c.ID))
	must(db.QueryRowContext(ctx, "SELECT state FROM m4_jobs WHERE id=$1", c.ID).Scan(&state))
	if state != "succeeded" {
		t.Fatalf("terminal cancellation changed succeeded to %s", state)
	}
	must(r.Enqueue(ctx, "concurrent", 1))
	var wg sync.WaitGroup
	results := make(chan jobs.Claim, 12)
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := r.Claim(ctx, "contender", time.Minute)
			if err == nil {
				results <- c
			} else if !errors.Is(err, sql.ErrNoRows) {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if len(results) != 1 {
		t.Fatalf("concurrent claims=%d", len(results))
	}
}
