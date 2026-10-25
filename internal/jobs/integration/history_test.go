package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHistoricalContainerCancellation(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated postgres required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var name string
	if err = db.QueryRow("SELECT current_database()").Scan(&name); err != nil || name != "m4_validation" {
		t.Fatal("disposable database required", err)
	}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	files, err := os.ReadDir("../migrations")
	must(err)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sql") {
			b, e := os.ReadFile("../migrations/" + f.Name())
			must(e)
			_, e = db.Exec(string(b))
			must(e)
		}
	}
	_, err = db.Exec("TRUNCATE m4_jobs CASCADE")
	must(err)
	repo := jobs.Repository{DB: db}
	ctx := context.Background()
	root := t.TempDir()
	control := t.TempDir()
	workerSecret := strings.Repeat("w", 32)
	coordinator := strings.Repeat("c", 32)
	handler, err := jobapi.NewWithCoordinator(repo, root, workerSecret, coordinator, control)
	must(err)
	server := httptest.NewServer(handler)
	defer func() { server.Close() }()
	post := func(op, secret string, c jobs.Claim, extra map[string]any) int {
		t.Helper()
		body := map[string]any{"attempt": c.Attempt, "worker": c.Worker, "token": c.Token}
		for k, v := range extra {
			body[k] = v
		}
		b, _ := json.Marshal(body)
		req, e := http.NewRequest("POST", server.URL+"/v1/jobs/"+c.ID+"/"+op, bytes.NewReader(b))
		must(e)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, e := http.DefaultClient.Do(req)
		must(e)
		defer resp.Body.Close()
		return resp.StatusCode
	}
	must(repo.Enqueue(ctx, "history", 3))
	first, err := repo.Claim(ctx, "one", time.Minute)
	must(err)
	id1 := strings.Repeat("1", 64)
	id2 := strings.Repeat("2", 64)
	if code := post("execution", workerSecret, first, map[string]any{"location": "docker:test", "container_id": id1}); code != 401 {
		t.Fatal("worker registered external proof", code)
	}
	if code := post("execution", coordinator, first, map[string]any{"location": "docker:test", "container_id": id1}); code != 200 {
		t.Fatal(code)
	}
	_, err = db.Exec("UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id='history'")
	must(err)
	must(repo.Recover(ctx, control))
	second, err := repo.Claim(ctx, "two", time.Minute)
	must(err)
	if code := post("execution", coordinator, first, map[string]any{"location": "docker:test", "container_id": id1}); code != 409 {
		t.Fatal("stale execution registration", code)
	}
	if code := post("execution", coordinator, second, map[string]any{"location": "docker:test", "container_id": id2}); code != 200 {
		t.Fatal(code)
	}
	makeExit := func(c jobs.Claim, id string) map[string]any {
		return map[string]any{"location": "docker:test", "container_id": id, "scope": "container", "exited": true, "removed": true, "inspected_id": id, "running": false, "pid": 0, "labels": map[string]string{"cpag.job": c.ID, "cpag.attempt": string(rune('0' + c.Attempt)), "cpag.worker": c.Worker}}
	}
	noRemoval := makeExit(first, id1)
	noRemoval["removed"] = false
	if code := post("exit", coordinator, first, noRemoval); code != 400 {
		t.Fatal("restartable stopped container proved exit", code)
	}
	must(repo.Cancel(ctx, "history"))
	_, err = db.Exec("UPDATE m4_jobs SET recovery_deadline=clock_timestamp()-interval '1 second' WHERE id='history'")
	must(err)
	if code := post("exit", coordinator, second, makeExit(second, id2)); code != 200 {
		t.Fatal(code)
	}
	must(repo.Recover(ctx, control))
	status, err := repo.Status(ctx, "history")
	must(err)
	if status.State != "cancelling" || len(status.MissingExitAttempts) != 1 || status.MissingExitAttempts[0] != 1 {
		t.Fatal("lost predecessor hidden", status)
	}
	// Rebuild API handler over persisted state; historical receipt is still accepted.
	server.Close()
	handler, err = jobapi.NewWithCoordinator(jobs.Repository{DB: db}, root, workerSecret, coordinator, control)
	must(err)
	server = httptest.NewServer(handler)
	if code := post("exit", coordinator, first, makeExit(first, id1)); code != 200 {
		t.Fatal("old exit rejected after restart", code)
	}
	if code := post("exit", coordinator, first, makeExit(first, id1)); code != 200 {
		t.Fatal("exit retry not idempotent", code)
	}
	must((jobs.Repository{DB: db}).Recover(ctx, control))
	status, err = repo.Status(ctx, "history")
	must(err)
	if status.State != "cancelled" || len(status.AttemptHistory) != 2 || len(status.MissingExitAttempts) != 0 {
		t.Fatal(status)
	}
	sha := strings.Repeat("a", 64)
	key, err := jobs.ArtifactKey(first, sha)
	must(err)
	if e := repo.Complete(ctx, first, key, sha); e != jobs.ErrStale {
		t.Fatal("old exit granted publication", e)
	}
	// Missing imported earlier history is visible and never inferred as exited.
	must(repo.Enqueue(ctx, "legacy-gap", 3))
	_, err = db.Exec(`UPDATE m4_jobs SET state='running',attempt=3,worker='legacy',attempt_token='old-token',lease_until=clock_timestamp()+interval '1 minute' WHERE id='legacy-gap'`)
	must(err)
	must(repo.Cancel(ctx, "legacy-gap"))
	gap, err := repo.Status(ctx, "legacy-gap")
	must(err)
	if len(gap.AttemptHistory) != 1 || len(gap.MissingExitAttempts) != 3 {
		t.Fatal("missing imported attempt history hidden", gap)
	}
	// Container publication requires irreversible exit/removal even with live lease.
	must(repo.Enqueue(ctx, "publishgate", 1))
	published, err := repo.Claim(ctx, "publisher", time.Minute)
	must(err)
	must(repo.RegisterExecution(ctx, published, "docker:test", strings.Repeat("3", 64)))
	if e := repo.CheckPublication(ctx, published); e != jobs.ErrStale {
		t.Fatal("container published before removal", e)
	}
	publishKey, e := jobs.ArtifactKey(published, sha)
	must(e)
	if e = repo.Complete(ctx, published, publishKey, sha); e != jobs.ErrStale {
		t.Fatal("repository skipped container removal", e)
	}
	exitBody := makeExit(published, strings.Repeat("3", 64))
	if code := post("exit", coordinator, published, exitBody); code != 200 {
		t.Fatal(code)
	}
	must(repo.CheckPublication(ctx, published))
	must(repo.Complete(ctx, published, publishKey, sha))
	publishedStatus, e := repo.Status(ctx, published.ID)
	must(e)
	if publishedStatus.AttemptHistory[0].PublicationState != "published" || publishedStatus.AttemptHistory[0].ArtifactSHA256 == nil || *publishedStatus.AttemptHistory[0].ArtifactSHA256 != sha {
		t.Fatal("publication history lost", publishedStatus)
	}
	// A retry Claim and cancellation serialize on the job row; cancellation can
	// never bypass the prior attempted execution's proof.
	must(repo.Enqueue(ctx, "retry-cancel-race", 3))
	prior, e := repo.Claim(ctx, "prior", time.Minute)
	must(e)
	must(repo.Fail(ctx, prior, "retry", true))
	_, e = db.Exec(`UPDATE m4_jobs SET available_at=clock_timestamp() WHERE id=$1`, prior.ID)
	must(e)
	var group sync.WaitGroup
	var cancelErr, claimErr error
	group.Add(2)
	go func() { defer group.Done(); cancelErr = repo.Cancel(ctx, prior.ID) }()
	go func() { defer group.Done(); _, claimErr = repo.Claim(ctx, "racer", time.Minute) }()
	group.Wait()
	must(cancelErr)
	if claimErr != nil && claimErr != sql.ErrNoRows {
		t.Fatal(claimErr)
	}
	race, e := repo.Status(ctx, prior.ID)
	must(e)
	if race.State != "cancelling" || len(race.MissingExitAttempts) == 0 || len(race.AttemptHistory) != race.Attempt {
		t.Fatal("cancel/retry race bypassed historical exit", race)
	}

}

func TestMigrationPreservesPublishedHistory(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated postgres required")
	}
	db, e := sql.Open("pgx", dsn)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	var name string
	if e = db.QueryRow("SELECT current_database()").Scan(&name); e != nil || name != "m4_validation" {
		t.Fatal("disposable database required", e)
	}
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, file := range []string{"001_jobs.sql", "002_worker_api.sql", "003_recovery.sql", "004_attempt_history.sql"} {
		b, e := os.ReadFile("../migrations/" + file)
		must(e)
		_, e = db.Exec(string(b))
		must(e)
	}
	tx, e := db.Begin()
	must(e)
	defer tx.Rollback()
	_, e = tx.Exec("DROP TRIGGER m4_attempt_history ON m4_jobs; DROP TABLE m4_job_attempts")
	must(e)
	sha := strings.Repeat("a", 64)
	path := "jobs/legacy/attempt-2/" + sha + ".json"
	_, e = tx.Exec(`INSERT INTO m4_jobs(id,state,attempt,max_attempts,worker,attempt_token,artifact_path,artifact_sha256) VALUES('migration-legacy','succeeded',2,3,'legacy','legacy-token',$1,$2)`, path, sha)
	must(e)
	migration, e := os.ReadFile("../migrations/004_attempt_history.sql")
	must(e)
	_, e = tx.Exec(string(migration))
	must(e)
	var state, artifact, pub, historyArtifact, historySHA string
	var exited *time.Time
	var count int
	must(tx.QueryRow(`SELECT j.state,j.artifact_path,a.publication_state,a.artifact_path,a.artifact_sha256,a.exited_at FROM m4_jobs j JOIN m4_job_attempts a ON a.job_id=j.id WHERE j.id='migration-legacy'`).Scan(&state, &artifact, &pub, &historyArtifact, &historySHA, &exited))
	must(tx.QueryRow(`SELECT count(*) FROM m4_job_attempts WHERE job_id='migration-legacy'`).Scan(&count))
	if state != "succeeded" || artifact != path || pub != "published" || historyArtifact != path || historySHA != sha || exited != nil || count != 1 {
		t.Fatal("migration rewrote results or invented historical exit", state, artifact, pub, count)
	}
}
