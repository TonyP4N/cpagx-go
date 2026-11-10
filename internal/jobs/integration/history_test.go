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
	"path/filepath"
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
	leaseBefore := time.Time{}
	must(db.QueryRow("SELECT lease_until FROM m4_jobs WHERE id=$1", second.ID).Scan(&leaseBefore))
	discover := func(secret, location string) (int, []map[string]any) {
		req, e := http.NewRequest("GET", server.URL+"/v1/executions?location="+location, nil)
		must(e)
		req.Header.Set("Authorization", "Bearer "+secret)
		resp, e := http.DefaultClient.Do(req)
		must(e)
		defer resp.Body.Close()
		var items []map[string]any
		if resp.StatusCode == 200 {
			must(json.NewDecoder(resp.Body).Decode(&items))
		}
		return resp.StatusCode, items
	}
	if code, _ := discover(workerSecret, "docker:test"); code != 401 {
		t.Fatal("worker discovered private execution tokens", code)
	}
	if code, items := discover(coordinator, "docker:test"); code != 200 || len(items) != 2 {
		t.Fatal("daemon history discovery missing", code, items)
	}
	if code, items := discover(coordinator, "docker:other"); code != 200 || len(items) != 0 {
		t.Fatal("cross-daemon discovery leak", code, items)
	}
	leaseAfter := time.Time{}
	must(db.QueryRow("SELECT lease_until FROM m4_jobs WHERE id=$1", second.ID).Scan(&leaseAfter))
	if !leaseBefore.Equal(leaseAfter) {
		t.Fatal("discovery renewed orphan lease")
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
	// Reproduce the baseline's terminal retry: its cancelling-only guard maps
	// zero affected rows to ErrStale/HTTP409 after recovery already cancelled.
	baseline := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, e := db.Exec(`UPDATE m4_jobs SET state='cancelled',lease_until=NULL WHERE id=$1 AND attempt=$2 AND worker=$3 AND attempt_token=$4 AND state='cancelling' AND (SELECT count(*) FROM m4_job_attempts a WHERE a.job_id=m4_jobs.id AND a.exited_at IS NOT NULL)=m4_jobs.attempt`, second.ID, second.Attempt, second.Worker, second.Token)
		if e != nil {
			http.Error(w, e.Error(), 500)
			return
		}
		n, _ := result.RowsAffected()
		if n != 1 {
			w.WriteHeader(409)
			return
		}
		w.WriteHeader(200)
	}))
	baselineResponse, e := http.Post(baseline.URL, "application/json", strings.NewReader("{}"))
	must(e)
	baselineResponse.Body.Close()
	baseline.Close()
	if baselineResponse.StatusCode != 409 {
		t.Fatal("baseline ACK guard did not reproduce", baselineResponse.StatusCode)
	}
	t.Log("REPRO baseline cancelling-only ACK after cancellation: HTTP409")
	if code := post("ack-cancel", workerSecret, second, map[string]any{}); code != 200 {
		t.Fatal("terminal ACK retry not idempotent", code)
	}
	if code := post("ack-cancel", workerSecret, second, map[string]any{}); code != 200 {
		t.Fatal(code)
	}
	wrongIdentity := second
	wrongIdentity.Token = "wrong-token"
	if code := post("ack-cancel", workerSecret, wrongIdentity, map[string]any{}); code != 409 {
		t.Fatal("terminal ACK accepted wrong token", code)
	}
	// Create/register cancellation window: only removed coordinator proof can bind
	// a previously empty execution, and that retired binding cannot later start.
	must(repo.Enqueue(ctx, "registration-window", 3))
	window, e := repo.Claim(ctx, "window", time.Minute)
	must(e)
	must(repo.Cancel(ctx, window.ID))
	windowID := strings.Repeat("4", 64)
	if code := post("exit", workerSecret, window, makeExit(window, windowID)); code != 401 {
		t.Fatal("worker bound missing execution", code)
	}
	if code := post("exit", coordinator, window, makeExit(window, windowID)); code != 200 {
		t.Fatal("removed unregistered execution did not converge", code)
	}
	if e = repo.RegisterExecution(ctx, window, "docker:test", windowID); e != jobs.ErrStale {
		t.Fatal("retired registration acquired start rights", e)
	}
	if code := post("exit", coordinator, window, makeExit(window, strings.Repeat("5", 64))); code != 409 {
		t.Fatal("retired container ID was replaced", code)
	}
	wrongWindow := window
	wrongWindow.Token = "wrong-window-token"
	if code := post("exit", coordinator, wrongWindow, makeExit(window, windowID)); code != 400 && code != 409 {
		t.Fatal("wrong historical token accepted", code)
	}
	must(repo.AcknowledgeCancel(ctx, window))
	must(repo.AcknowledgeCancel(ctx, window))
	sha := strings.Repeat("a", 64)
	key, err := jobs.ArtifactKey(first, sha)
	must(err)
	if e := repo.Complete(ctx, first, key, sha); e != jobs.ErrStale {
		t.Fatal("old exit granted publication", e)
	}
	// A PostgreSQL dependency failure while recording a valid receipt must escape
	// the pass; semantic invalid proof remains a diagnosed per-attempt condition.
	must(repo.Enqueue(ctx, "dependency-fixture", 1))
	dependency, e := repo.Claim(ctx, "dependency", time.Minute)
	must(e)
	dependencyID := strings.Repeat("6", 64)
	must(repo.RegisterExecution(ctx, dependency, "docker:test", dependencyID))
	receipt := makeExit(dependency, dependencyID)
	receipt["id"] = dependency.ID
	receipt["attempt"] = dependency.Attempt
	receipt["worker"] = dependency.Worker
	receipt["token"] = dependency.Token
	receiptPath := filepath.Join(control, "jobs", dependency.ID, "attempt-1.worker", "exit.json")
	must(os.MkdirAll(filepath.Dir(receiptPath), 0700))
	receiptBytes, _ := json.Marshal(receipt)
	must(os.WriteFile(receiptPath, receiptBytes, 0600))
	_, e = db.Exec(`CREATE FUNCTION m4_test_record_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'dependency failure fixture'; END $$; CREATE TRIGGER m4_test_record_failure BEFORE UPDATE ON m4_job_attempts FOR EACH ROW WHEN (OLD.job_id='dependency-fixture') EXECUTE FUNCTION m4_test_record_failure()`)
	must(e)
	e = repo.RefreshExitEvidence(ctx, control, dependency.ID)
	if e == nil || !strings.Contains(e.Error(), "dependency failure fixture") {
		t.Fatal("receipt DB failure was swallowed", e)
	}
	t.Log("PASS valid receipt database failure propagates instead of per-item continue")
	_, e = db.Exec(`DROP TRIGGER m4_test_record_failure ON m4_job_attempts; DROP FUNCTION m4_test_record_failure()`)
	must(e)
	must(repo.RefreshExitEvidence(ctx, control, dependency.ID))
	// Invalid evidence cannot poison other attempts and remains visible in status.
	must(repo.Enqueue(ctx, "invalid-proof-fixture", 1))
	invalid, e := repo.Claim(ctx, "invalid", time.Minute)
	must(e)
	invalidID := strings.Repeat("7", 64)
	must(repo.RegisterExecution(ctx, invalid, "docker:test", invalidID))
	badReceipt := makeExit(invalid, invalidID)
	badReceipt["id"] = invalid.ID
	badReceipt["attempt"] = invalid.Attempt
	badReceipt["worker"] = invalid.Worker
	badReceipt["token"] = invalid.Token
	badReceipt["removed"] = false
	badPath := filepath.Join(control, "jobs", invalid.ID, "attempt-1.worker", "exit.json")
	must(os.MkdirAll(filepath.Dir(badPath), 0700))
	badBytes, _ := json.Marshal(badReceipt)
	must(os.WriteFile(badPath, badBytes, 0600))
	must(repo.RefreshExitEvidence(ctx, control, invalid.ID))
	invalidStatus, e := repo.Status(ctx, invalid.ID)
	must(e)
	if invalidStatus.AttemptHistory[0].ExitError == nil || !strings.Contains(*invalidStatus.AttemptHistory[0].ExitError, "inspect") || invalidStatus.AttemptHistory[0].ExitedAt != nil {
		t.Fatal("invalid proof diagnostic missing", invalidStatus)
	}
	// Remove these live fixture claims from the queue without manufacturing exits.
	must(repo.Fail(ctx, dependency, "fixture finished", false))
	must(repo.Fail(ctx, invalid, "fixture finished", false))
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
	// A local ELOOP receipt must not prevent a later good receipt from recording.
	must(repo.Enqueue(ctx, "file-local-fixture", 2))
	fileOne, e := repo.Claim(ctx, "file-one", time.Minute)
	must(e)
	fileID1 := strings.Repeat("a", 64)
	fileID2 := strings.Repeat("b", 64)
	must(repo.RegisterExecution(ctx, fileOne, "docker:test", fileID1))
	must(repo.Fail(ctx, fileOne, "retry", true))
	_, e = db.Exec(`UPDATE m4_jobs SET available_at=clock_timestamp() WHERE id=$1`, fileOne.ID)
	must(e)
	fileTwo, e := repo.Claim(ctx, "file-two", time.Minute)
	must(e)
	must(repo.RegisterExecution(ctx, fileTwo, "docker:test", fileID2))
	badLoop := filepath.Join(control, "jobs", fileOne.ID, "attempt-1.worker", "exit.json")
	goodFile := filepath.Join(control, "jobs", fileTwo.ID, "attempt-2.worker", "exit.json")
	must(os.MkdirAll(filepath.Dir(badLoop), 0700))
	must(os.MkdirAll(filepath.Dir(goodFile), 0700))
	must(os.Symlink("exit.json", badLoop))
	goodReceipt := makeExit(fileTwo, fileID2)
	for k, v := range map[string]any{"id": fileTwo.ID, "attempt": fileTwo.Attempt, "worker": fileTwo.Worker, "token": fileTwo.Token} {
		goodReceipt[k] = v
	}
	goodBytes, _ := json.Marshal(goodReceipt)
	must(os.WriteFile(goodFile, goodBytes, 0600))
	must(repo.RefreshExitEvidence(ctx, control, fileOne.ID))
	local, e := repo.Status(ctx, fileOne.ID)
	must(e)
	if local.AttemptHistory[0].ExitError == nil || local.AttemptHistory[0].ExitedAt != nil || local.AttemptHistory[1].ExitedAt == nil {
		t.Fatal("local path failure poisoned later receipt", local)
	}
	t.Log("PASS actual ELOOP receipt diagnosed locally; later good attempt exit recorded")
	if e = repo.RefreshExitEvidence(ctx, filepath.Join(control, "missing-root"), fileOne.ID); e == nil {
		t.Fatal("shared root outage was hidden")
	}
	must(os.Remove(badLoop))
	oldReceipt := makeExit(fileOne, fileID1)
	for k, v := range map[string]any{"id": fileOne.ID, "attempt": fileOne.Attempt, "worker": fileOne.Worker, "token": fileOne.Token} {
		oldReceipt[k] = v
	}
	oldBytes, _ := json.Marshal(oldReceipt)
	must(os.WriteFile(badLoop, oldBytes, 0600))
	must(repo.RefreshExitEvidence(ctx, control, fileOne.ID))
	must(repo.Cancel(ctx, fileOne.ID))
	must(repo.AcknowledgeCancel(ctx, fileTwo))
	// Claim response discarded before any create-intent: isolated mode/location
	// are already durable and discovery can revoke the unregistered start gate.
	must(repo.Enqueue(ctx, "gated-lost-response", 2))
	claimBody, _ := json.Marshal(map[string]any{"worker": "gated-lost", "lease_seconds": 30, "executor": "isolated-v2", "location": "docker:test"})
	request, e := http.NewRequest("POST", server.URL+"/v1/claim", bytes.NewReader(claimBody))
	must(e)
	request.Header.Set("Authorization", "Bearer "+workerSecret)
	response, e := http.DefaultClient.Do(request)
	must(e)
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	var lost jobs.Claim
	lost.ID = "gated-lost-response"
	must(db.QueryRow(`SELECT attempt,worker,attempt_token FROM m4_jobs WHERE id=$1`, lost.ID).Scan(&lost.Attempt, &lost.Worker, &lost.Token))
	foundLost := false
	items, e := repo.DiscoverExecutions(ctx, "docker:test")
	must(e)
	for _, item := range items {
		if item["id"] == lost.ID && item["executor"] == "isolated-v2" && item["container_id"] == "" {
			foundLost = true
		}
	}
	if !foundLost {
		t.Fatal("lost claim absent from durable discovery")
	}
	must(repo.Cancel(ctx, lost.ID))
	if code := post("not-started", workerSecret, lost, map[string]any{"location": "docker:test"}); code != 401 {
		t.Fatal("worker revoked coordinator gate", code)
	}
	if code := post("not-started", coordinator, lost, map[string]any{"location": "docker:test"}); code != 200 {
		t.Fatal("lost claim did not converge", code)
	}
	if e = repo.RegisterExecution(ctx, lost, "docker:test", strings.Repeat("8", 64)); e != jobs.ErrStale {
		t.Fatal("revoked lost claim registered", e)
	}
	if e = repo.Heartbeat(ctx, lost, time.Minute); e != jobs.ErrStale {
		t.Fatal("revoked claim renewed lease", e)
	}
	if e = repo.CheckClaim(ctx, lost); e != jobs.ErrStale {
		t.Fatal("revoked attempt still owned claim", e)
	}
	if e = repo.CheckPublication(ctx, lost); e != jobs.ErrStale {
		t.Fatal("not-started acquired publication", e)
	}
	must(repo.AcknowledgeCancel(ctx, lost))
	must(repo.AcknowledgeCancel(ctx, lost))
	lostStatus, e := repo.Status(ctx, lost.ID)
	must(e)
	if lostStatus.State != "cancelled" || lostStatus.LeaseValid || lostStatus.AttemptHistory[0].StartRevokedAt == nil {
		t.Fatal(lostStatus)
	}
	if e = repo.RevokeUnstarted(ctx, first, "docker:test"); e != jobs.ErrStale {
		t.Fatal("legacy inferred not-started", e)
	}
	// Actual concurrent register/revoke has exactly one winner. A later removed
	// receipt can enrich a not-started record but can never reopen its gate.
	must(repo.Enqueue(ctx, "gated-register-race", 2))
	gated, e := repo.ClaimExecution(ctx, "gated-race", time.Minute, "isolated-v2", "docker:test")
	must(e)
	if e = repo.CheckPublication(ctx, gated); e != jobs.ErrStale {
		t.Fatal("unregistered isolated attempt acquired publication", e)
	}
	unregisteredKey, e := jobs.ArtifactKey(gated, sha)
	must(e)
	if e = repo.Complete(ctx, gated, unregisteredKey, sha); e != jobs.ErrStale {
		t.Fatal("unregistered isolated completion accepted", e)
	}
	gatedID := strings.Repeat("9", 64)
	var registerErr, revokeErr error
	var gateGroup sync.WaitGroup
	gateGroup.Add(2)
	go func() {
		defer gateGroup.Done()
		registerErr = repo.RegisterExecution(ctx, gated, "docker:test", gatedID)
	}()
	go func() { defer gateGroup.Done(); revokeErr = repo.RevokeUnstarted(ctx, gated, "docker:test") }()
	gateGroup.Wait()
	if (registerErr == nil) == (revokeErr == nil) {
		t.Fatal("register/revoke did not have one winner", registerErr, revokeErr)
	}
	if registerErr != nil && registerErr != jobs.ErrStale {
		t.Fatal(registerErr)
	}
	if revokeErr != nil && revokeErr != jobs.ErrStale {
		t.Fatal(revokeErr)
	}
	if code := post("exit", coordinator, gated, makeExit(gated, gatedID)); code != 200 {
		t.Fatal("removed receipt did not retire gated execution", code)
	}
	if revokeErr == nil {
		if e = repo.CheckPublication(ctx, gated); e != jobs.ErrStale {
			t.Fatal("cleanup reopened revoked publication", e)
		}
	}
	must(repo.Cancel(ctx, gated.ID))
	must(repo.AcknowledgeCancel(ctx, gated))
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

	// Suppress one trigger insert to verify a zero-row history mode update rolls
	// back the claim instead of returning an untracked executable identity.
	must(repo.Enqueue(ctx, "missing-ledger-fixture", 1))
	_, e = db.Exec(`CREATE FUNCTION m4_test_skip_history() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$; CREATE TRIGGER m4_test_skip_history BEFORE INSERT ON m4_job_attempts FOR EACH ROW WHEN (NEW.job_id='missing-ledger-fixture') EXECUTE FUNCTION m4_test_skip_history()`)
	must(e)
	_, claimError := repo.ClaimExecution(ctx, "missing-ledger", time.Minute, "isolated-v2", "docker:test")
	if claimError != jobs.ErrStale {
		t.Fatal("untracked claim returned executable identity", claimError)
	}
	_, e = db.Exec(`DROP TRIGGER m4_test_skip_history ON m4_job_attempts; DROP FUNCTION m4_test_skip_history()`)
	must(e)
	unclaimed, e := repo.Status(ctx, "missing-ledger-fixture")
	must(e)
	if unclaimed.Attempt != 0 || unclaimed.State != "queued" || len(unclaimed.AttemptHistory) != 0 {
		t.Fatal("failed history update leaked committed claim", unclaimed)
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
