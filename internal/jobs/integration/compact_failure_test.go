package integration

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TonyP4N/cpagx-go/internal/jobs"
)

func TestFailVerifiedRequiresCurrentCompactClaimAndAllExitEvidence(t *testing.T) {
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
	must := func(e error) {
		t.Helper()
		if e != nil {
			t.Fatal(e)
		}
	}
	var name string
	must(db.QueryRow("SELECT current_database()").Scan(&name))
	if name != "m4_validation" {
		t.Fatal("disposable database required")
	}
	files, err := os.ReadDir("../migrations")
	must(err)
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".sql") {
			raw, e := os.ReadFile(filepath.Join("../migrations", file.Name()))
			must(e)
			_, e = db.Exec(string(raw))
			must(e)
		}
	}
	for _, condition := range []string{"verified_exit", "missing_compute_exit", "running_verifier", "missing_verifier", "wrong_claim", "expired", "cancelled", "revoked", "old_format", "database_error"} {
		t.Run(condition, func(t *testing.T) {
			must := func(e error) {
				t.Helper()
				if e != nil {
					t.Fatal(e)
				}
			}
			_, e := db.Exec("TRUNCATE m4_jobs CASCADE;UPDATE m4_capacity_policy SET profile='',enabled_at=NULL")
			must(e)
			defer db.Exec("TRUNCATE m4_jobs CASCADE")
			payload := map[string]string{"capacity_profile": "engineering-core-capacity-3", "storage_format": "shared-observation-dag-6", "resource_profile": "storage-budget-2", "storage_budget_version": "shared-storage-budget-2"}
			if condition == "old_format" {
				payload = map[string]string{}
			}
			raw, _ := json.Marshal(payload)
			repo := jobs.Repository{DB: db}
			must(repo.EnqueuePayload(ctx, "reject", 3, raw))
			claim, e := repo.Claim(ctx, "worker", time.Minute)
			must(e)
			if condition != "missing_compute_exit" {
				_, e = db.Exec("UPDATE m4_job_attempts SET exited_at=clock_timestamp() WHERE job_id='reject'")
				must(e)
			}
			if condition != "missing_verifier" {
				state := "exited"
				if condition == "running_verifier" {
					state = "running"
				}
				_, e = db.Exec("INSERT INTO m4_compact_verifications(job_id,attempt,container_name,state,exited_at)VALUES('reject',1,$1,$2,CASE WHEN $2='exited' THEN clock_timestamp() ELSE NULL END)", strings.Repeat("a", 64), state)
				must(e)
			}
			switch condition {
			case "wrong_claim":
				claim.Token = "wrong"
			case "expired":
				_, e = db.Exec("UPDATE m4_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id='reject'")
				must(e)
			case "cancelled":
				must(repo.Cancel(ctx, "reject"))
			case "revoked":
				_, e = db.Exec("UPDATE m4_job_attempts SET start_revoked_at=clock_timestamp() WHERE job_id='reject'")
				must(e)
			}
			if condition == "database_error" {
				unavailable, e := sql.Open("pgx", dsn)
				must(e)
				must(unavailable.Close())
				e = (jobs.Repository{DB: unavailable}).FailVerified(ctx, claim, "source rejected")
				if e == nil {
					t.Fatal("closed database accepted failure")
				}
			} else {
				e = repo.FailVerified(ctx, claim, "source rejected after controlled exit")
				if condition == "verified_exit" {
					must(e)
				} else if !errors.Is(e, jobs.ErrStale) {
					t.Fatalf("unsafe failure condition %s: %v", condition, e)
				}
			}
			status, e := repo.Status(ctx, "reject")
			must(e)
			if condition == "verified_exit" {
				if status.State != "failed" || status.LastError == nil || *status.LastError != "source rejected after controlled exit" || status.Attempt != 1 {
					t.Fatal("failure metadata lost", status.State)
				}
				if e = repo.FailVerified(ctx, claim, "overwrite reason"); !errors.Is(e, jobs.ErrStale) {
					t.Fatalf("terminal failure changed: %v", e)
				}
				if _, e = repo.Claim(ctx, "retry", time.Minute); !errors.Is(e, sql.ErrNoRows) {
					t.Fatalf("permanent verification failure retried: %v", e)
				}
			} else {
				want := "running"
				if condition == "cancelled" {
					want = "cancelling"
				}
				if status.State != want || status.LastError != nil {
					t.Fatalf("unsafe terminal mutation: %s %v", status.State, status.LastError)
				}
			}
		})
	}
}
