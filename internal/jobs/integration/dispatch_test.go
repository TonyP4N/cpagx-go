package integration

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobapi"
	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

func TestRabbitOutboxAtomicPartitionLeaseRecoveryAndRollback(t *testing.T) {
	dsn := os.Getenv("M4_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated postgres required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var name string
	must(db.QueryRow("SELECT current_database()").Scan(&name))
	if name != "m4_validation" {
		t.Fatal("isolated database required")
	}
	files, err := os.ReadDir("../migrations")
	must(err)
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".sql") {
			raw, e := os.ReadFile("../migrations/" + f.Name())
			must(e)
			_, e = db.Exec(string(raw))
			must(e)
		}
	}
	_, err = db.Exec("TRUNCATE m4_jobs CASCADE; UPDATE m4_capacity_policy SET profile=''")
	must(err)
	ctx := context.Background()
	repo := jobs.Repository{DB: db}
	poll := strings.Repeat("1", 32)
	rabbit := strings.Repeat("2", 32)
	other := strings.Repeat("3", 32)
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		must(db.QueryRow(query, args...).Scan(&n))
		return n
	}
	enqueue := func(id, partition string) {
		t.Helper()
		_, e := db.Exec(`INSERT INTO m4_jobs(id,max_attempts,dispatch_partition) VALUES($1,3,$2)`, id, partition)
		must(e)
	}
	dispatch := func(id string) string {
		t.Helper()
		var value string
		must(db.QueryRow(`SELECT dispatch_id FROM m4_jobs WHERE id=$1`, id).Scan(&value))
		return value
	}
	tx, err := db.Begin()
	must(err)
	_, err = tx.Exec(`INSERT INTO m4_jobs(id,max_attempts,dispatch_partition) VALUES($1,3,'rabbit-v3')`, rabbit)
	must(err)
	must(tx.Rollback())
	if count(`SELECT count(*) FROM m4_dispatch_outbox`) != 0 {
		t.Fatal("rolled back admission left dispatch")
	}
	enqueue(poll, "poll")
	enqueue(rabbit, "rabbit-v3")
	first := dispatch(rabbit)
	if count(`SELECT count(*) FROM m4_dispatch_outbox WHERE job_id=$1 AND dispatch_id=$2`, rabbit, first) != 1 {
		t.Fatal("admission missing atomic outbox")
	}
	c, err := repo.Claim(ctx, "poll-worker", time.Minute)
	must(err)
	if c.ID != poll {
		t.Fatal("scan stole rabbit task")
	}
	must(repo.Fail(ctx, c, "done", false))
	if _, err = repo.Claim(ctx, "poll-worker", time.Minute); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("poll scan stole rabbit", err)
	}
	leased, err := repo.LeaseDispatches(ctx, "publisher-one", time.Second, 1)
	must(err)
	if len(leased) != 1 || leased[0].DispatchID != first {
		t.Fatal("dispatch missing", leased)
	}
	again, err := repo.LeaseDispatches(ctx, "publisher-two", time.Second, 1)
	must(err)
	if len(again) != 0 {
		t.Fatal("publisher lease duplicated")
	}
	if err = repo.ConfirmDispatch(ctx, first, "publisher-one", strings.Repeat("f", 64)); !errors.Is(err, jobs.ErrStale) {
		t.Fatal("wrong lease confirmed", err)
	}
	_, err = db.Exec(`UPDATE m4_dispatch_outbox SET leased_until=clock_timestamp()-interval '1 second' WHERE dispatch_id=$1`, first)
	must(err)
	if err = repo.ConfirmDispatch(ctx, first, "publisher-one", leased[0].LeaseToken); !errors.Is(err, jobs.ErrStale) {
		t.Fatal("expired lease confirmed", err)
	}
	again, err = repo.LeaseDispatches(ctx, "publisher-two", time.Minute, 1)
	must(err)
	if len(again) != 1 || again[0].DispatchID != first || again[0].LeaseToken == leased[0].LeaseToken {
		t.Fatal("outage catchup lost dispatch identity")
	}
	if err = repo.ConfirmDispatch(ctx, first, "publisher-one", leased[0].LeaseToken); !errors.Is(err, jobs.ErrStale) {
		t.Fatal("old publisher confirmed new lease", err)
	}
	must(repo.ConfirmDispatch(ctx, first, "publisher-two", again[0].LeaseToken))
	must(repo.ConfirmDispatch(ctx, first, "publisher-two", again[0].LeaseToken))
	location := "resident:0c3a6291-1ec0-4550-9220-62c135c8cedc"
	if _, err = repo.ClaimDispatched(ctx, "queue-worker", time.Minute, "resident-v1", location, poll, first, "rabbit-v3"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("exact crossed poll partition", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	claims := []jobs.Claim{}
	claimErrors := []error{}
	for n := 0; n < 6; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			claim, e := repo.ClaimDispatched(ctx, "queue-worker", time.Minute, "resident-v1", location, rabbit, first, "rabbit-v3")
			mu.Lock()
			defer mu.Unlock()
			if e == nil {
				claims = append(claims, claim)
			} else {
				claimErrors = append(claimErrors, e)
			}
		}()
	}
	wg.Wait()
	if len(claims) != 1 {
		t.Fatal("duplicate delivery allocated multiple attempts", len(claims), claimErrors)
	}
	c = claims[0]
	history, e := repo.History(ctx, rabbit)
	must(e)
	if history[0].DispatchID == nil || *history[0].DispatchID != first {
		t.Fatal("dispatch attempt audit lost")
	}
	if c.Attempt != 1 {
		t.Fatal("wrong attempt")
	}
	rollback, err := repo.RollbackDispatch(ctx, []string{rabbit})
	must(err)
	if len(rollback) != 0 {
		t.Fatal("running task changed by rollback")
	}
	must(repo.CheckClaim(ctx, c))
	if dispatch(rabbit) != first {
		t.Fatal("running rollback changed dispatch")
	}
	must(repo.Fail(ctx, c, "retry", true))
	second := dispatch(rabbit)
	if first == second {
		t.Fatal("retry reused dispatch")
	}
	if count(`SELECT count(*) FROM m4_dispatch_outbox WHERE dispatch_id=$1 AND invalidated_at IS NOT NULL`, first) != 1 {
		t.Fatal("old dispatch remained live")
	}
	if _, e := repo.ClaimDispatched(ctx, "queue-worker", time.Minute, "resident-v1", location, rabbit, second, "rabbit-v3"); !errors.Is(e, jobs.ErrDispatchBusy) {
		t.Fatal("future dispatch was dropped as stale", e)
	}
	_, err = db.Exec(`UPDATE m4_jobs SET available_at=clock_timestamp() WHERE id=$1`, rabbit)
	must(err)
	c, err = repo.ClaimDispatched(ctx, "queue-worker", time.Minute, "resident-v1", location, rabbit, second, "rabbit-v3")
	must(err)
	_, err = db.Exec(`UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1`, rabbit)
	must(err)
	must(repo.Recover(ctx, t.TempDir()))
	third := dispatch(rabbit)
	if third == second {
		t.Fatal("expired attempt reused dispatch")
	}
	enqueue(other, "rabbit-v3")
	rollback, err = repo.RollbackDispatch(ctx, []string{rabbit, other})
	must(err)
	if len(rollback) != 2 {
		t.Fatal("queued rollback incomplete", rollback)
	}
	if count(`SELECT count(*) FROM m4_dispatch_outbox WHERE invalidated_at IS NULL`) != 0 {
		t.Fatal("rollback left publishable dispatch")
	}
	if _, err = repo.ClaimDispatched(ctx, "queue-worker", time.Minute, "resident-v1", location, rabbit, third, "rabbit-v3"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("rollback accepted stale delivery", err)
	}
	c, err = repo.Claim(ctx, "poll-worker", time.Minute)
	must(err)
	if c.ID != rabbit && c.ID != other {
		t.Fatal("rollback did not restore poll claim")
	}
}

func TestDispatchHTTPAuthoritySeparation(t *testing.T) {
	root := t.TempDir()
	handler, err := jobapi.NewWithCoordinator(jobs.Repository{}, root, strings.Repeat("w", 32), strings.Repeat("c", 32), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server := handler.(*jobapi.Server)
	server.DispatcherSecret = strings.Repeat("d", 32)
	post := func(path, secret string) int {
		raw, _ := json.Marshal(map[string]any{})
		r := httptest.NewRequest("POST", path, bytes.NewReader(raw))
		r.Header.Set("Authorization", "Bearer "+secret)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w.Code
	}
	for _, path := range []string{"/v1/dispatch/lease", "/v1/dispatch/confirm"} {
		for _, secret := range []string{strings.Repeat("w", 32), strings.Repeat("c", 32)} {
			if code := post(path, secret); code != 401 {
				t.Fatal("publisher endpoint accepted other authority", path, code)
			}
		}
	}
	for _, path := range []string{"/v1/dispatch/rollback", "/v1/jobs/test/cancel", "/v1/jobs/test/execution", "/v1/claim"} {
		if code := post(path, strings.Repeat("d", 32)); code != 401 {
			t.Fatal("publisher gained execution authority", path, code)
		}
	}
}
